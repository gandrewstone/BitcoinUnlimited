// Copyright (c) 2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKDB_H
#define BLOCKDB_H

#include "uint256.h"
#include "dbwrapper.h"
#include "chain.h"
#include "primitives/block.h"
#include "undo.h"

struct BlockDBValue
{
    int32_t blockVersion;
    uint64_t blockHeight;
    CBlock block;

    BlockDBValue()
    {
        SetNull();
    }

    BlockDBValue(const CBlock &_block)
    {
        assert(_block.IsNull() == false);
        this->block = _block;
        this->blockVersion = this->block.nVersion;
        this->blockHeight = this->block.GetHeight();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockVersion);
        READWRITE(blockHeight);
        READWRITE(block);
    }

    void SetNull()
    {
        blockVersion = 0;
        blockHeight = 0;
        block.SetNull();
    }
};

struct UndoDBValue
{
    uint256 hashChecksum;
    uint256 hashBlock;
    CBlockUndo blockundo;

    UndoDBValue()
    {
        SetNull();
    }

    UndoDBValue(const uint256 &_hashChecksum, const uint256 &_hashBlock, const CBlockUndo &_blockundo)
    {
        this->hashChecksum = _hashChecksum;
        this->hashBlock = _hashBlock;
        this->blockundo = _blockundo;
    }

    template <typename Stream>
    void Serialize(Stream &s) const
    {
        s << FLATDATA(hashChecksum);
        s << FLATDATA(hashBlock);
        s << blockundo;
    }

    template <typename Stream>
    void Unserialize(Stream &s)
    {
        s >> FLATDATA(hashChecksum);
        s >> FLATDATA(hashBlock);
        s >> blockundo;
    }

    void SetNull()
    {
        hashChecksum.SetNull();
        hashBlock.SetNull();
        blockundo.vtxundo.clear();
    }
};

/** Access to the block database (blocks/ * /) */
class CBlockDB : public CDBWrapper
{
public:
    CBlockDB(std::string folder, size_t nCacheSize, bool fMemory = false, bool fWipe = false, bool obfuscate = false, COverrideOptions *override = nullptr);

private:
    CBlockDB(const CBlockDB &);
    void operator=(const CBlockDB &);

public:
    bool WriteBatchSync(const std::vector<CBlock> &blocks);

    // we need a custom read functions to account for the way we want to deserialize blockdbvalue and undodbvalue
    template <typename K>
    bool ReadBlock(const K &key, BlockDBValue &value, CBlock& block) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok())
        {
            if (status.IsNotFound())
                return false;
            LOGA("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        try
        {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue.Xor(obfuscate_key);
            ssValue.readtovoid(&value.nVersion, sizeof(int32_t));
            ssValue.readtovoid(&value.blockHeight, sizeof(uint64_t));
            ssValue.readtovoid(&block, ssValue.size());
        }
        catch (const std::exception &)
        {
            return false;
        }
        return true;
    }

    template <typename K>
    bool ReadUndo(const K &key, UndoDBValue &value, CBlockUndo& blockundo) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok())
        {
            if (status.IsNotFound())
                return false;
            LOGA("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        try
        {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue.Xor(obfuscate_key);
            ssValue.readtovoid(&value.hashChecksum, 32); // 32 is number of bytes in uint256
            ssValue.readtovoid(&value.hashBlock, 32); // 32 is number of bytes in uint256
            ssValue.readtovoid(&blockundo, ssValue.size());
        }
        catch (const std::exception &)
        {
            return false;
        }
        return true;
    }
};

extern CBlockDB *pblockdb;
extern CBlockDB *pblockundodb;

bool WriteBlockToDB(const CBlock &block);
bool ReadBlockFromDB(const CBlockIndex *pindex, BlockDBValue &value);

bool UndoWriteToDB(const CBlockUndo &blockundo, const uint256 &hashBlock, const int64_t nBlockTime);
bool UndoReadFromDB(CBlockUndo &blockundo, const uint256 &hashBlock, const int64_t nBlockTime);

uint64_t FindFilesToPruneLevelDB(uint64_t nLastBlockWeCanPrune);

#endif // BLOCKDB_H
