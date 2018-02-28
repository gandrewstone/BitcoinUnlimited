// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockdb_sequential.h"

#include "pruning.h"
#include "main.h"

extern bool AbortNode(CValidationState &state, const std::string &strMessage, const std::string &userMessage = "");
extern bool fCheckForPruning;
extern CCriticalSection cs_LastBlockFile;
extern std::set<int> setDirtyFileInfo;
extern std::multimap<CBlockIndex *, CBlockIndex *> mapBlocksUnlinked;

fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}


FILE *OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    fs::path path = GetBlockPosFilename(pos, prefix);
    fs::create_directories(path.parent_path());
    FILE *file = fsbridge::fopen(path, "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file)
    {
        LOGA("Unable to open file %s\n", path.string());
        return NULL;
    }
    if (pos.nPos)
    {
        if (fseek(file, pos.nPos, SEEK_SET))
        {
            LOGA("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE *OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly)
{
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE *OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly)
{
    return OpenDiskFile(pos, "rev", fReadOnly);
}


void FlushBlockFile(bool fFinalize)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld)
    {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld)
    {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}



/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool FlushStateToDisk(CValidationState &state, FlushStateMode mode)
{
    const CChainParams &chainparams = Params();
    LOCK2(cs_main, cs_LastBlockFile);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    try
    {
        if (fPruneMode && fCheckForPruning && !fReindex)
        {
            FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
            fCheckForPruning = false;
            if (!setFilesToPrune.empty())
            {
                fFlushForPrune = true;
                if (!fHavePruned)
                {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        int64_t nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0)
        {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0)
        {
            nLastFlush = nNow;
        }
        if (nLastSetChain == 0)
        {
            nLastSetChain = nNow;
        }

        // If possible adjust the max size of the coin cache (nCoinCacheUsage) based on current available memory. Do
        // this before determinining whether to flush the cache or not in the steps that follow.
        AdjustCoinCacheSize();

        size_t cacheSize = pcoinsTip->DynamicMemoryUsage();
        static int64_t nSizeAfterLastFlush = 0;
        // The cache is close to the limit. Try to flush and trim.
        bool fCacheCritical = ((mode == FLUSH_STATE_IF_NEEDED) && (cacheSize > nCoinCacheUsage * 0.995)) ||
                              (cacheSize - nSizeAfterLastFlush > nMaxCacheIncreaseSinceLastFlush);
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload
        // after a crash.
        bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite)
        {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(0))
            {
                return state.Error("out of disk space");
            }
            // First make sure all block and undo data is flushed to disk.
            FlushBlockFile();
            // Then update all block file information (which may refer to block and undo files).
            {
                std::vector<std::pair<int, const CBlockFileInfo *> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end();)
                {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex *> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex *>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end();)
                {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks))
                {
                    return AbortNode(state, "Files to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune)
            {
                UnlinkPrunedFiles(setFilesToPrune);
            }
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush)
        {
            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
            {
                return state.Error("out of disk space");
            }
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
            {
                return AbortNode(state, "Failed to write to coin database");
            }
            nLastFlush = nNow;
            // Trim any excess entries from the cache if needed.  If chain is not syncd then
            // trim extra so that we don't flush as often during IBD.
            if (IsChainNearlySyncd() && !fReindex && !fImporting)
            {
                pcoinsTip->Trim(nCoinCacheUsage);
            }
            else
            {
                // Trim, but never trim more than nMaxCacheIncreaseSinceLastFlush
                size_t nTrimSize = nCoinCacheUsage * .90;
                if (nCoinCacheUsage - nMaxCacheIncreaseSinceLastFlush > nTrimSize)
                {
                    nTrimSize = nCoinCacheUsage - nMaxCacheIncreaseSinceLastFlush;
                }
                pcoinsTip->Trim(nTrimSize);
            }
            nSizeAfterLastFlush = pcoinsTip->DynamicMemoryUsage();
        }
        if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) &&
                                nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000))
        {
            // Update best block in wallet (so we can detect restored wallets).
            GetMainSignals().SetBestChain(chainActive.GetLocator());
            nLastSetChain = nNow;
        }

        // As a safeguard, periodically check and correct any drift in the value of cachedCoinsUsage.  While a
        // correction should never be needed, resetting the value allows the node to continue operating, and only
        // an error is reported if the new and old values do not match.
        if (fPeriodicFlush)
        {
            pcoinsTip->ResetCachedCoinUsage();
        }
    }
    catch (const std::runtime_error &e)
    {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk()
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush()
{
    CValidationState state;
    fCheckForPruning = true;
    FlushStateToDisk(state, FLUSH_STATE_NONE);
}
