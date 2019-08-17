// Copyright (c) 2019 G. Andrew Stone

// Counterparty and protocol discovery
#include <limits>
#include <queue>

#include "serialize.h"
#include "uint256.h"
#include "utiltime.h"

extern bool StartCapd();
extern void StopCapd();

//! Contains a node and information about what it wants notifications for
class CNotify
{
protected:
public:
};


class CMsgLookup
{
public:
    enum
    {
        MSG_LOOKUP_LEN = 10
    };

    uint8_t data[MSG_LOOKUP_LEN];
};


//! A message to be stored in the pool
class CMsg
{
protected:
    enum Fields : uint8_t
    {
        NONE = 0,
        EXPIRATION = 1,
        RESCINDHASH = 2,
    };

public:
    static const uint8_t CURRENT_VERSION = 0;
    static const uint8_t HASHSIZE = 20;

    // TODO version in CDataStream could replace this
    uint8_t version; //! (not network serialized) The expected serialization version

    uint64_t createTime = 0; //! When this message was created (seconds since epoch)
    //! When this message expires (seconds since epoch) max_int means never
    uint64_t expiration = std::numeric_limits<short>::max();
    uint160 rescindHash; //! When the preimage is published, this message expires, 0 means no preimage
    std::vector<uint8_t> data; //! The message contents
    uint32_t difficultyBits = 0; //! the message's proof of work target
    uint64_t nonce = 0; //! needed to prove this message's POW

    CMsg(uint8_t ver = CURRENT_VERSION) : version(ver) {}
    CMsg(const std::string &indata, uint8_t ver = CURRENT_VERSION)
        : version(ver), createTime(GetTime()), data(indata.begin(), indata.end())
    {
    }

    CMsg(const std::vector<uint8_t> &indata, uint8_t ver = CURRENT_VERSION)
        : version(ver), createTime(GetTime()), data(indata.begin(), indata.end())
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        if (s.GetType() & SER_GETHASH)
        {
            READWRITE(data);
            READWRITE(createTime);
            READWRITE(rescindHash);
            READWRITE(expiration);
            READWRITE(difficultyBits);
        }
        else
        {
            uint8_t fields = 0;
            if (!ser_action.ForRead())
            {
                fields |= (expiration == std::numeric_limits<short>::max()) ? Fields::EXPIRATION : Fields::NONE;
                fields |= (rescindHash == uint160()) ? Fields::RESCINDHASH : Fields::NONE;
            }

            READWRITE(fields);
            READWRITE(createTime);
            READWRITE(difficultyBits);
            READWRITE(nonce);
            if (fields & Fields::EXPIRATION)
                READWRITE(expiration);
            if (fields & Fields::RESCINDHASH)
                READWRITE(rescindHash);
            READWRITE(data);
        }
    }

    //! Return the approximate RAM used by this object
    size_t RamSize() { return sizeof(CMsg) + data.size(); }
    /** Calculate this message's hash.  Used for POW and identity */
    uint256 CalcHash();

    /** Verify that the proof of work matches the difficulty claimed in the message */
    bool DoesPowMatchDifficulty();

    /** Find a Nonce that solves this message and difficulty */
    uint64_t Mine();
};


typedef std::shared_ptr<const CMsg> CMsgRef;
static inline CMsgRef MakeMsgRef() { return std::make_shared<const CMsg>(); }
template <typename Tx>
static inline CMsgRef MakeMsgRef(CMsg &&in)
{
    return std::make_shared<const CMsg>(std::forward<CMsg>(in));
}


//! The pool of all current messages
class CMsgPool
{
protected:
    std::priority_queue<CMsgRef> heap;
    std::map<CMsgLookup, CMsgRef> cam;

public:
};
