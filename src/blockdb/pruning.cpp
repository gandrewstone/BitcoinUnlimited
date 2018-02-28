// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pruning.h"

#include "blockdb_leveldb.h"
#include "blockdb_sequential.h"
#include "main.h"

extern CCriticalSection cs_LastBlockFile;
extern std::set<int> setDirtyFileInfo;
extern std::multimap<CBlockIndex *, CBlockIndex *> mapBlocksUnlinked;

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    uint64_t retval = 0;
    BOOST_FOREACH (const CBlockFileInfo &file, vinfoBlockFile)
    {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}



/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it)
    {
        CBlockIndex *pindex = it->second;
        if (pindex->nFile == fileNumber)
        {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
                range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second)
            {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator it = range.first;
                range.first++;
                if (it->second == pindex)
                {
                    mapBlocksUnlinked.erase(it);
                }
            }
        }
    }
    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}

/* Calculate the block/rev files that should be deleted to remain under target*/
void FindFilesToPrune(std::set<int> &setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);

    if (chainActive.Tip() == NULL || nPruneTarget == 0)
    {
        return;
    }
    if ((uint64_t)chainActive.Tip()->nHeight <= nPruneAfterHeight)
    {
        return;
    }
    uint64_t nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;

    if(BLOCK_DB_MODE == SEQUENTIAL_BLOCK_FILES || BLOCK_DB_MODE == LEVELDB_AND_SEQUENTIAL)
    {
        uint64_t nCurrentUsage = CalculateCurrentUsage();
        // We don't check to prune until after we've allocated new space for files
        // So we should leave a buffer under our target to account for another allocation
        // before the next pruning.
        uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
        uint64_t nBytesToPrune;
        int count = 0;

        if (nCurrentUsage + nBuffer >= nPruneTarget)
        {
            for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++)
            {
                nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

                if (vinfoBlockFile[fileNumber].nSize == 0)
                    continue;

                if (nCurrentUsage + nBuffer < nPruneTarget) // are we below our target?
                    break;

                // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep
                // scanning
                if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                    continue;

                PruneOneBlockFile(fileNumber);
                // Queue up the files for removal
                setFilesToPrune.insert(fileNumber);
                nCurrentUsage -= nBytesToPrune;
                count++;
            }
        }

        LOG(PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
            nPruneTarget / 1024 / 1024, nCurrentUsage / 1024 / 1024,
            ((int64_t)nPruneTarget - (int64_t)nCurrentUsage) / 1024 / 1024, nLastBlockWeCanPrune, count);
    }
    else if(BLOCK_DB_MODE == LEVELDB_BLOCK_STORAGE || BLOCK_DB_MODE == LEVELDB_AND_SEQUENTIAL)
    {
        std::vector<uint256> hashesToPrune;
        /// just remove the to be pruned blocks here in the case of leveldb storage
        boost::scoped_ptr<CDBIterator> pcursor(pblockfull->NewIterator());
        pcursor->Seek(uint256());
        // Load mapBlockIndex
        while (pcursor->Valid())
        {
            boost::this_thread::interruption_point();
            std::pair<char, uint256> key;
            if (pcursor->GetKey(key))
            {
                BlockDBValue diskblock;
                if (pcursor->GetValue(diskblock))
                {
                    if(diskblock.blockHeight <= nLastBlockWeCanPrune)
                    {
                        /// unsafe to alter a set of data as we iterate through it so store hashes to be deleted in a
                        hashesToPrune.push_back(diskblock.block.GetHash());
                    }
                    pcursor->Next();
                }
                else
                {
                    return; // error("FindFilesToPrune() : failed to read value");
                }
            }
            else
            {
                break;
            }
        }
        /// this should prune all blocks from the DB that are old enough to prune
        for(std::vector<uint256>::iterator iter = hashesToPrune.begin(); iter != hashesToPrune.end(); ++iter)
        {
            pblockfull->EraseBlock(*iter);
        }
    }
}

void UnlinkPrunedFiles(std::set<int> &setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it)
    {
        CDiskBlockPos pos(*it, 0);
        fs::remove(GetBlockPosFilename(pos, "blk"));
        fs::remove(GetBlockPosFilename(pos, "rev"));
        LOGA("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}
