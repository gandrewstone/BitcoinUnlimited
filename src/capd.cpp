// Copyright (c) 2019 G. Andrew Stone

// Counterparty and protocol discovery
#include <limits>
#include <queue>

#include "arith_uint256.h"
#include "capd.h"
#include "clientversion.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"

// #include "BLAKE2/sse/blake2.h"

#include "hashwrapper.h"
#include "httpserver.h"
#include "rpc/server.h"
#include "utilstrencodings.h"

#include <univalue.h>

const CMsgRef nullmsgref = CMsgRef();

const long int YEAR_OF_SECONDS = 31536000;

CMsgPool msgpool;

uint64_t MSG_LIFETIME_SEC = 60 * 60 * 10; // expected message lifetime in seconds
uint64_t NOMINAL_MSG_SIZE = 100; // A message of this size or less has no penalty

// Local message difficulty must be less than forwarded message difficulty
arith_uint256 MIN_FORWARD_MSG_DIFFICULTY("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
arith_uint256 MIN_LOCAL_MSG_DIFFICULTY("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");


PriorityType MIN_RELAY_PRIORITY = Priority(MIN_FORWARD_MSG_DIFFICULTY, NOMINAL_MSG_SIZE, 0);
PriorityType MIN_LOCAL_PRIORITY = Priority(MIN_LOCAL_MSG_DIFFICULTY, NOMINAL_MSG_SIZE, 0);

arith_uint256 MAX_UINT256 = ~arith_uint256();

/* When converting a double to a uint256, precision will be lost.  This is how much to keep.
   Basically, doubles are multiplied by this amount before being converted to a uint256.
   This means that this precision is often lost in related uint256 values because the algorithm
   looks something like this to avoid overflow:

   uintVal/CONVERSION_FRAC * (uint256) ((uint64_t) (doubleVal * CONVERSION_FRAC))
 */
const unsigned long int PRIORITY_CONVERSION_FRAC = 0x100000;

PriorityType Priority(uint32_t difficultyBits, size_t msgContentSize, uint64_t age)
{
    arith_uint256 difficulty;
    difficulty.SetCompact(difficultyBits);
    // printf("difficulty bits = %x -> %s\n",difficultyBits, difficulty.GetHex().c_str() );
    return Priority(difficulty, msgContentSize, age);
}

PriorityType Priority(arith_uint256 hashTarget, size_t msgContentSize, uint64_t age)
{
    double ret = MIN_LOCAL_MSG_DIFFICULTY.getdouble() / hashTarget.getdouble();

    // Calculate the size based penalty
    if (msgContentSize > NOMINAL_MSG_SIZE)
    {
        ret = (ret / msgContentSize) * NOMINAL_MSG_SIZE;
    }

    // Next subtract the creation time based penalty
    double penaltyPerSec = ret / MSG_LIFETIME_SEC;
    double totalPenalty = penaltyPerSec * age;

    ret -= totalPenalty;
    return ret;

    /*
    // hash must be less than hashTarget, so smaller numbers are harder
    // subtract from maxint to reverse the direction of priority -- now bigger numbers are harder

    // A message that's solved a harder (now bigger) POW has a higher base priority.
    //auto ret = MAX_UINT256 - hashTarget;
    auto ret = hashTarget;
    //double tgt = hashTarget.getdouble();

    // Now subtract off the size based penalty
    if (msgContentSize > NOMINAL_MSG_SIZE)
    {

    ret = (ret/msgContentSize)*NOMINAL_MSG_SIZE;
    }

    // Next subtract the creation time based penalty
    arith_uint256 penaltyPerSec = ret/MSG_LIFETIME_SEC;
    arith_uint256 totalPenalty = penaltyPerSec * age;
    // check totalPenalty overflow -- if it overflowed, priority is 0.
    if ((age != 0) && (totalPenalty/age != penaltyPerSec)) return uint256();

    // Priority is zero if we overflow
    if (MAX_UINT256 - ret <= totalPenalty) return uint256();

    ret += totalPenalty;
    ret = MAX_UINT256 - ret;
    return ArithToUint256(ret);
    */
}

arith_uint256 aPriorityToDifficultyTarget(PriorityType priority, size_t msgContentSize, uint64_t age)
{
    DbgAssert(age == 0, );

    if (msgContentSize > NOMINAL_MSG_SIZE)
    {
        priority = (priority * msgContentSize) / NOMINAL_MSG_SIZE;
    }


    arith_uint256 ret;
    if (priority < 1.0)
    {
        PriorityType priInv = (((PriorityType)1) / priority) * PRIORITY_CONVERSION_FRAC;
        ret = MIN_LOCAL_MSG_DIFFICULTY / PRIORITY_CONVERSION_FRAC * arith_uint256((uint64_t)priInv);
    }
    else
    {
        arith_uint256 v;
        v.setdouble(priority * PRIORITY_CONVERSION_FRAC);
        ret = (MIN_LOCAL_MSG_DIFFICULTY / v) * PRIORITY_CONVERSION_FRAC;
    }


    /*
    // TODO age
    DbgAssert(age == 0,);

    arith_uint256 ret = MAX_UINT256 - UintToArith256(priority);
    //ret += arith_uint256(msgContentSize);
    if (msgContentSize > NOMINAL_MSG_SIZE)
    {
        ret = (ret/NOMINAL_MSG_SIZE)*msgContentSize;
    }

    // ret = MAX_UINT256 - ret;
    */
    return ret;
}

uint256 CMsg::CalcHash() const
{
    CDataStream serialized(SER_GETHASH, CLIENT_VERSION);
    serialized << *this;
    /*
      blake2b_state bs;
      blake2b_init(&bs, HASHSIZE);

      uint160 ret;
      blake2b_update(&bs, serialized.data(), serialized.size());
      if (blake2b_final(&bs, (void *) ret.begin(), 20) == -1)
      {
      // ERROR
      }

      // TODO ^ does not follow the spec
      */
    // uint160 ret = Hash160(serialized.begin(), serialized.end());

    CSHA256 sha;
    sha.Write((unsigned char *)serialized.data(), serialized.size());
    unsigned char stage1[CSHA256::OUTPUT_SIZE + sizeof(uint64_t)];
    sha.Finalize(stage1);
    uint256 hash;
    memcpy(&stage1[CSHA256::OUTPUT_SIZE], (void *)&nonce, sizeof(uint64_t));
    CHash256 sha2;
    sha2.Write(stage1, sizeof(stage1));
    sha2.Finalize(hash.begin());

    return hash;
}

PriorityType CMsg::Priority() const { return ::Priority(difficultyBits, data.size(), GetTime() - createTime); }
bool CMsg::DoesPowMatchDifficulty() const { return GetDifficulty() > GetHash(); }
uint64_t CMsg::Solve(long int time)
{
    if (time < YEAR_OF_SECONDS)
        createTime = GetTime() - time;
    else
        createTime = time;

    CDataStream serialized(SER_GETHASH, CLIENT_VERSION);
    serialized << *this;

    CSHA256 sha;
    sha.Write((unsigned char *)serialized.data(), serialized.size());
    unsigned char stage1[CSHA256::OUTPUT_SIZE + sizeof(uint64_t)];
    sha.Finalize(stage1);

    arith_uint256 hashTarget = arith_uint256().SetCompact(difficultyBits);

    uint256 hash;
    do
    {
        memcpy(&stage1[CSHA256::OUTPUT_SIZE], (void *)&nonce, sizeof(uint64_t));
        CHash256 sha2;
        sha2.Write(stage1, sizeof(stage1));
        sha2.Finalize(hash.begin());

        if (UintToArith256(hash) <= hashTarget)
        {
            break;
        }
        nonce += 1;
    } while (1);

    return nonce;
}


void CMsgPool::add(const CMsgRef &msg)
{
    WRITELOCK(csMsgPool);

    // TODO clean up a message if pool is filled

    if (!msg->DoesPowMatchDifficulty())
    {
        throw CMsgPoolException("Message POW inconsistent");
    }
    if (msg->Priority() < _GetLocalPriority())
    {
        // printf("Priority: msg: %s >=  local: %s\n", msg->Priority().GetHex().c_str(),
        // _GetLocalPriority().GetHex().c_str());
        // printf("Difficulty: msg: %s  local: %s\n", msg->GetDifficulty().GetHex().c_str(),
        // _GetLocalDifficulty().GetHex().c_str());
        throw CMsgPoolException("Message POW too low");
    }

    // Free up some room
    _pare(msg->RamSize());

    msgs.insert(msg);
    size += msg->RamSize();
}

void CMsgPool::clear()
{
    WRITELOCK(csMsgPool);
    /*
    cam.clear();
    while (!heap.empty())
    {
        heap.pop();
    }
    */
    msgs.clear();
    size = 0;
}

void CMsg::SetDifficultyHarderThan(uint256 target)
{
    // Subtract 1 from the difficulty as a compact number.  By doing it this way we are certain
    // that the change isn't rounded away.
    uint32_t cInt = UintToArith256(target).GetCompact();
    uint32_t mantissa = (cInt & ((1 << 23) - 1));
    uint32_t randomReduction = std::rand() % 0xff;

    if (mantissa > randomReduction) // subtract a bit from the mantissa if we won't underflow
    {
        cInt -= randomReduction;
    }
    else // subtract one from the exponent and set the enough bits that its like 0x100 -> 0xff
    {
        cInt = (cInt - (1 << 25)) | 0xff;
    }

    arith_uint256 num;
    // printf("harder than: %s -> 0x%x\n", target.GetHex().c_str(), cInt);
    SetDifficulty(num.SetCompact(cInt));
}

void CMsg::SetDifficultyHarderThanPriority(PriorityType priority)
{
    SetDifficultyHarderThan(PriorityToDifficultyTarget(priority, data.size(), 0));
}

uint256 CMsgPool::_GetRelayDifficulty()
{
    static const uint256 minFwdDiffTgt = ArithToUint256(MIN_FORWARD_MSG_DIFFICULTY);

    if (size < maxSize * 8 / 10)
        return minFwdDiffTgt; // If the pool isn't filled up, return the minimum.

    auto &priorityIndexer = msgs.get<MsgPriorityTag>();

    unsigned int half = priorityIndexer.size() / 2;

    MsgIterByPriority i = priorityIndexer.begin();
    for (unsigned int j = 0; j < half; j++, i++)
    {
    } // essentially i += half;

    if (i == priorityIndexer.end())
        return minFwdDiffTgt;

    uint256 ret = (*i)->GetDifficulty();
    if (ret > minFwdDiffTgt)
        return minFwdDiffTgt;
    return ret;
}

uint256 CMsgPool::_GetLocalDifficulty()
{
    static const uint256 minLclDiffTgt = ArithToUint256(MIN_LOCAL_MSG_DIFFICULTY);

    if (size < maxSize * 8 / 10)
        return minLclDiffTgt; // If the pool isn't filled up, return the minimum.

    auto &priorityIndexer = msgs.get<MsgPriorityTag>();

    // MsgReverseIterByPriority i = priorityIndexer.rbegin();
    // if (i==priorityIndexer.rend()) return  MIN_LOCAL_MSG_DIFFICULTY;

    MsgIterByPriority i = priorityIndexer.begin();
    if (i == priorityIndexer.end())
        return minLclDiffTgt;

    uint256 ret = (*i)->GetDifficulty();
    if (ret > minLclDiffTgt)
        return minLclDiffTgt;
    return ret;
}

PriorityType CMsgPool::_GetRelayPriority()
{
    if (size < maxSize * 8 / 10)
        return MIN_RELAY_PRIORITY;

    auto &priorityIndexer = msgs.get<MsgPriorityTag>();

    unsigned int half = priorityIndexer.size() / 2;

    MsgIterByPriority i = priorityIndexer.begin();
    for (unsigned int j = 0; j < half; j++, i++)
    {
    } // essentially i += half;

    if (i == priorityIndexer.end())
        return MIN_RELAY_PRIORITY;

    PriorityType ret = (*i)->Priority();
    if (ret < MIN_RELAY_PRIORITY)
        return MIN_RELAY_PRIORITY;
    return ret;
}

PriorityType CMsgPool::_GetLocalPriority()
{
    if (size < maxSize * 8 / 10)
        return MIN_LOCAL_PRIORITY;

    auto &priorityIndexer = msgs.get<MsgPriorityTag>();

    MsgIterByPriority i = priorityIndexer.begin();
    auto last = priorityIndexer.end();
    last--;
    if ((*last)->Priority() < (*i)->Priority())
    {
        return (*last)->Priority();
    }

    if (i == priorityIndexer.end())
        return MIN_LOCAL_PRIORITY;

    PriorityType ret = (*i)->Priority();
    if (ret < MIN_LOCAL_PRIORITY)
        return MIN_LOCAL_PRIORITY;
    return ret;
}


void CMsgPool::_pare(int len)
{
    len -= maxSize - size; // We already have this amount available
    auto &priorityIndexer = msgs.get<MsgPriorityTag>();
    MsgIterByPriority i = priorityIndexer.begin();
    auto end = priorityIndexer.end();

    // MsgIterByPriority st = priorityIndexer.begin();
    // if (st != priorityIndexer.end() && i != end)
    //    printf("%x %x\n", (*st)->difficultyBits, (*i)->difficultyBits);

    while ((len > 0) && (i != end))
    {
        auto txSize = (*i)->RamSize();
        len -= txSize;
        size -= txSize;

        auto j = i; // Advance before erase
        i++;
        priorityIndexer.erase(j);
    }
}


CMsgRef CMsgPool::find(const uint256 &hash) const
{
    MsgIter i = msgs.find(hash);
    if (i == msgs.end())
        return nullmsgref;
    return *i;
}

std::vector<CMsgRef> CMsgPool::find(const std::vector<unsigned char> v) const
{
    READLOCK(csMsgPool);
    if (v.size() == 2)
    {
        auto &indexer = msgs.get<MsgLookup2>();
        std::array<unsigned char, 2> srch = {v[0], v[1]};
        MessageContainer::index<MsgLookup2>::type::iterator it = indexer.find(srch);

        std::vector<CMsgRef> ret;
        for (; it != indexer.end(); it++)
        {
            if (!(*it)->matches(srch))
                break;
            ret.push_back(*it);
        }
        return ret;
    }

    if (v.size() == 4)
    {
        auto &indexer = msgs.get<MsgLookup4>();
        std::array<unsigned char, 4> srch = {v[0], v[1], v[2], v[3]};
        MessageContainer::index<MsgLookup4>::type::iterator it = indexer.find(srch);

        std::vector<CMsgRef> ret;
        for (; it != indexer.end(); it++)
        {
            if (!(*it)->matches(srch))
                break;
            ret.push_back(*it);
        }
        return ret;
    }

    if (v.size() == 8)
    {
        auto &indexer = msgs.get<MsgLookup8>();
        std::array<unsigned char, 8> srch;
        for (auto i = 0; i < 8; i++)
            srch[i] = v[i];
        MessageContainer::index<MsgLookup8>::type::iterator it = indexer.find(srch);

        std::vector<CMsgRef> ret;
        for (; it != indexer.end(); it++)
        {
            if (!(*it)->matches(srch))
                break;
            ret.push_back(*it);
        }
        return ret;
    }

    if (v.size() == 16)
    {
        auto &indexer = msgs.get<MsgLookup16>();
        std::array<unsigned char, 16> srch;
        for (auto i = 0; i < 16; i++)
            srch[i] = v[i];
        MessageContainer::index<MsgLookup16>::type::iterator it = indexer.find(srch);

        std::vector<CMsgRef> ret;
        for (; it != indexer.end(); it++)
        {
            if (!(*it)->matches(srch))
                break;
            ret.push_back(*it);
        }
        return ret;
    }

    return std::vector<CMsgRef>();
}


void CMsgPool::_DbgDump()
{
    auto &priorityIndexer = msgs.get<MsgPriorityTag>();

    MsgIterByPriority i = priorityIndexer.begin();
    for (unsigned int j = 0; i != priorityIndexer.end(); j++, i++)
    {
        printf("%4d: priority:%f - difficulty:%s -- %s %.8s\n", j, (*i)->Priority(),
            (*i)->GetDifficulty().GetHex().c_str(), (*i)->GetHash().GetHex().c_str(), &(*i)->data[0]);
    }

    printf("relay: %s, local: %s\n", _GetRelayDifficulty().GetHex().c_str(), _GetLocalDifficulty().GetHex().c_str());
}


//  Connect via JSON HTTP

enum RetFormat
{
    RF_UNDEF,
    RF_BINARY,
    RF_HEX,
    RF_JSON,
};

static const struct
{
    enum RetFormat rf;
    const char *name;
} rf_names[] = {
    {RF_UNDEF, ""}, {RF_BINARY, "bin"}, {RF_HEX, "hex"}, {RF_JSON, "json"},
};

static bool RETERR(HTTPRequest *req, enum HTTPStatusCode status, const std::string &message)
{
    req->WriteHeader("Content-Type", "text/plain");
    req->WriteReply(status, message + "\r\n");
    return false;
}

static enum RetFormat ParseDataFormat(std::string &param, const std::string &strReq)
{
    const std::string::size_type pos = strReq.rfind('.');
    if (pos == std::string::npos)
    {
        param = strReq;
        return rf_names[0].rf;
    }

    param = strReq.substr(0, pos);
    const std::string suff(strReq, pos + 1);

    for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
        if (suff == rf_names[i].name)
            return rf_names[i].rf;

    /* If no suffix is found, return original string.  */
    param = strReq;
    return rf_names[0].rf;
}

static std::string AvailableDataFormatsString()
{
    std::string formats = "";
    for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
        if (strlen(rf_names[i].name) > 0)
        {
            formats.append(".");
            formats.append(rf_names[i].name);
            formats.append(", ");
        }

    if (formats.length() > 0)
        return formats.substr(0, formats.length() - 2);

    return formats;
}

static bool CheckWarmup(HTTPRequest *req)
{
    std::string statusmessage;
    if (RPCIsInWarmup(&statusmessage))
        return RETERR(req, HTTP_SERVICE_UNAVAILABLE, "Service temporarily unavailable: " + statusmessage);
    return true;
}

// http://192.168.1.155:20332/capd/get/<data>
static bool capdHttpGet(HTTPRequest *req, const std::string &strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    std::vector<unsigned char> prefix;
    if (!IsHex(hashStr))
        return RETERR(req, HTTP_BAD_REQUEST, "Invalid hex string: " + hashStr);
    prefix = ParseHex(hashStr);

    std::vector<unsigned char> data = prefix;


    switch (rf)
    {
    case RF_BINARY:
    {
        std::string binaryTx(data.begin(), data.end());
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, binaryTx);
        return true;
    }

    case RF_HEX:
    {
        std::string strHex = HexStr(data.begin(), data.end()) + "\n";
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }

    case RF_JSON:
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("search", HexStr(data.begin(), data.end()));
        std::string strJSON = obj.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }

    default:
    {
        return RETERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }

    // not reached
    return true; // continue to process further HTTP reqs on this cxn
}

static bool capdHttpSend(HTTPRequest *req, const std::string &strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string result = "OK";

    if (!IsHex(strURIPart))
        return RETERR(req, HTTP_BAD_REQUEST, "Invalid hex string: " + strURIPart);
    std::vector<unsigned char> msgData = ParseHex(strURIPart);
    CMsgRef msg = MakeMsgRef(CMsg(msgData));
    if (!msg->DoesPowMatchDifficulty())
    {
        result = "inconsistent message, incorrect proof-of-work";
    }
    else
    {
        try
        {
            msgpool.add(msg);
        }
        catch (CMsgPoolException &e)
        {
            result = e.what();
        }
    }

    req->WriteHeader("Content-Type", "text/plain");
    req->WriteReply(HTTP_OK, result);
    return true;
}


static const struct
{
    const char *prefix;
    bool (*handler)(HTTPRequest *req, const std::string &strReq);
} uri_prefixes[] = {
    {"/capd/get/", capdHttpGet}, {"/capd/send/", capdHttpSend},
};

bool StartCapd()
{
    for (unsigned int i = 0; i < ARRAYLEN(uri_prefixes); i++)
        RegisterHTTPHandler(uri_prefixes[i].prefix, false, uri_prefixes[i].handler);
    return true;
}

void InterruptCapd() {}
void StopCapd()
{
    for (unsigned int i = 0; i < ARRAYLEN(uri_prefixes); i++)
        UnregisterHTTPHandler(uri_prefixes[i].prefix, false);
}
