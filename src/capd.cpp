// Copyright (c) 2019 G. Andrew Stone

// Counterparty and protocol discovery
#include <limits>
#include <queue>

#include "arith_uint256.h"
#include "capd.h"
#include "clientversion.h"
#include "dosman.h"
#include "net.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"

#include "hashwrapper.h"
#include "httpserver.h"
#include "rpc/server.h"
#include "utilstrencodings.h"

#include <univalue.h>

const CapdMsgRef nullmsgref = CapdMsgRef();

const long int YEAR_OF_SECONDS = 31536000;
const uint CAPD_MAX_INV_TO_SEND = 20000;
const uint CAPD_MAX_MSG_TO_REQUEST = 10000;
const uint CAPD_MAX_MSG_TO_SEND = 5000;

CapdMsgPool msgpool;
CapdProtocol capdProtocol(msgpool);

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

uint256 CapdMsg::CalcHash() const
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
    unsigned char stage1[CSHA256::OUTPUT_SIZE];
    sha.Finalize(stage1);
    uint256 hash;
    // memcpy(&stage1[CSHA256::OUTPUT_SIZE], (void *)&nonce, sizeof(uint64_t));
    CHash256 sha2;
    sha2.Write(stage1, sizeof(stage1));
    sha2.Write(&nonce[0], nonce.size());
    sha2.Finalize(hash.begin());

    return hash;
}

PriorityType CapdMsg::Priority() const { return ::Priority(difficultyBits, data.size(), GetTime() - createTime); }
bool CapdMsg::DoesPowMatchDifficulty() const { return GetDifficulty() > GetHash(); }
std::string CapdMsg::EncodeHex()
{
    CDataStream strmdata(SER_NETWORK, PROTOCOL_VERSION);
    strmdata << *this;
    return HexStr(strmdata.begin(), strmdata.end());
}


bool CapdMsg::checkNonce(unsigned char *stage1, const arith_uint256 &hashTarget)
{
    uint256 hash;
    CHash256 sha2;
    sha2.Write(stage1, CSHA256::OUTPUT_SIZE);
    sha2.Write(&nonce[0], nonce.size());
    sha2.Finalize(hash.begin());

    if (UintToArith256(hash) <= hashTarget)
        return true;
    return false;
}

bool CapdMsg::Solve(long int time)
{
    if (time < YEAR_OF_SECONDS)
        createTime = GetTime() - time;
    else
        createTime = time;

    CDataStream serialized(SER_GETHASH, CLIENT_VERSION);
    serialized << *this;

    CSHA256 sha;
    sha.Write((unsigned char *)serialized.data(), serialized.size());
    unsigned char stage1[CSHA256::OUTPUT_SIZE];
    sha.Finalize(stage1);

    arith_uint256 hashTarget = arith_uint256().SetCompact(difficultyBits);

    bool solved = false;

    do
    {
        // Looking for the shortest solution means searching all possibilities of different nonce lengths.
        nonce.resize(1);
        uint64_t count = 0;
        while (count < 256)
        {
            nonce[0] = count & 255;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }
        if (solved)
            break;

        count = 0;
        nonce.resize(2);
        while (count < 256 * 256)
        {
            nonce[0] = count & 255;
            nonce[1] = count >> 8;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }
        if (solved)
            break;

        count = 0;
        nonce.resize(3);
        while (count < 256 * 256 * 256)
        {
            nonce[0] = count & 255;
            nonce[1] = count >> 8;
            nonce[2] = count >> 16;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }

        count = 0;
        nonce.resize(4);
        while (count < 256UL * 256UL * 256UL * 256UL)
        {
            nonce[0] = count & 255;
            nonce[1] = count >> 8;
            nonce[2] = count >> 16;
            nonce[3] = count >> 24;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }
    } while (0);

    return solved;
}


void CapdMsgPool::add(const CapdMsgRef &msg)
{
    {
        WRITELOCK(csMsgPool);

        // TODO clean up a message if pool is filled

        if (!msg->DoesPowMatchDifficulty())
        {
            throw CapdMsgPoolException("Message POW inconsistent");
        }
        if (msg->Priority() < _GetLocalPriority())
        {
            // printf("Priority: msg: %s >=  local: %s\n", msg->Priority().GetHex().c_str(),
            // _GetLocalPriority().GetHex().c_str());
            // printf("Difficulty: msg: %s  local: %s\n", msg->GetDifficulty().GetHex().c_str(),
            // _GetLocalDifficulty().GetHex().c_str());
            throw CapdMsgPoolException("Message POW too low");
        }

        // Free up some room
        _pare(msg->RamSize());

        msgs.insert(msg);
        size += msg->RamSize();
    }

    auto *p = p2p; // Throw in a temp to avoid locking
    if (p)
        p->GossipMessage(*msg);
}

void CapdMsgPool::clear()
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

void CapdMsg::SetDifficultyHarderThan(uint256 target)
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

void CapdMsg::SetDifficultyHarderThanPriority(PriorityType priority)
{
    SetDifficultyHarderThan(PriorityToDifficultyTarget(priority, data.size(), 0));
}

uint256 CapdMsgPool::_GetRelayDifficulty()
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

uint256 CapdMsgPool::_GetLocalDifficulty()
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

PriorityType CapdMsgPool::_GetRelayPriority()
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

PriorityType CapdMsgPool::_GetLocalPriority()
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


void CapdMsgPool::_pare(int len)
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


CapdMsgRef CapdMsgPool::find(const uint256 &hash) const
{
    MsgIter i = msgs.find(hash);
    if (i == msgs.end())
        return nullmsgref;
    return *i;
}

std::vector<CapdMsgRef> CapdMsgPool::find(const std::vector<unsigned char> v) const
{
    READLOCK(csMsgPool);
    if (v.size() == 2)
    {
        auto &indexer = msgs.get<MsgLookup2>();
        std::array<unsigned char, 2> srch = {v[0], v[1]};
        MessageContainer::index<MsgLookup2>::type::iterator it = indexer.find(srch);

        std::vector<CapdMsgRef> ret;
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

        std::vector<CapdMsgRef> ret;
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

        std::vector<CapdMsgRef> ret;
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

        std::vector<CapdMsgRef> ret;
        for (; it != indexer.end(); it++)
        {
            if (!(*it)->matches(srch))
                break;
            ret.push_back(*it);
        }
        return ret;
    }

    return std::vector<CapdMsgRef>();
}


void CapdMsgPool::_DbgDump()
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


bool CapdProtocol::HandleCapdMessage(CNode *pfrom,
    std::string &command,
    CDataStream &vRecv,
    int64_t stopwatchTimeReceived)
{
    DbgAssert(pool != nullptr, return false);
    CapdNode *cn = pfrom->capd;
    if (!pfrom->IsCapdEnabled())
        return false;
    if (!cn)
        return false;

    if (command == NetMsgType::CAPDINV)
    {
        std::vector<uint256> vInv;
        int objtype = ReadCompactSize(vRecv);
        if (objtype != CAPD_MSG_TYPE) // unknown object type
        {
            return error(CAPD, "Received INV with unknown type %d\n", objtype);
        }
        vRecv >> vInv;
        if (vInv.size() > CAPD_MAX_INV_TO_SEND)
        {
            dosMan.Misbehaving(pfrom, 20);
            return error(CAPD, "Received message with too many (%d) INVs\n", vInv.size());
        }
        for (auto inv : vInv)
        {
            if (pool->find(inv) == nullptr)
                cn->getData(CInv(objtype, inv));
        }
    }
    else if (command == NetMsgType::CAPDGETMSG)
    {
        std::vector<uint256> msgIds;
        vRecv >> cn->youDontSendPriority;
        vRecv >> msgIds;
        if (msgIds.size() > CAPD_MAX_MSG_TO_REQUEST)
        {
            dosMan.Misbehaving(pfrom, 20);
            return error(CAPD, "Received message with too many (%d) capd message requests\n", msgIds.size());
        }

        for (auto id : msgIds)
        {
            auto msg = pool->find(id);
            if ((msg != nullptr) && (msg->Priority() >= cn->youDontSendPriority))
            {
                cn->sendMsg(msg);
            }
        }
    }
    else if (command == NetMsgType::CAPDMSG)
    {
        std::vector<std::pair<uint256, PriorityType> > relayInv;
        std::vector<CapdMsg> msgs; // TODO deserialize as CapdMsgRefs
        vRecv >> msgs;
        for (const auto msg : msgs)
        {
            auto msgRef = MakeMsgRef(CapdMsg(msg));
            PriorityType priority = msgRef->Priority();
            if (priority < cn->dontSendMePriority)
            {
                dosMan.Misbehaving(pfrom, 1);
                LOG(CAPD, "Capd message priority below minimum for node %s: %f %f\n", pfrom->GetLogName(), priority,
                    cn->dontSendMePriority);
                continue;
            }

            try
            {
                pool->add(msgRef);
                relayInv.push_back(std::pair<uint256, PriorityType>(msgRef->GetHash(), priority));
            }
            catch (CapdMsgPoolException &e)
            {
                // messsage was too low priority, drop it
            }
        }
    }
    else
    {
        // TODO: Something more than ignore if I don't understand the capd message
    }
    return true;
}

void CapdProtocol::GossipMessage(const CapdMsg &msg)
{
    auto hash = msg.GetHash();
    auto inv = CInv(CAPD_MSG_TYPE, hash);

    std::vector<CNode *> vNodesCopy;

    {
        LOCK(cs_vNodes);
        vNodesCopy = vNodes;
        for (CNode *pnode : vNodesCopy)
            pnode->AddRef();
    }

    for (CNode *pnode : vNodesCopy)
    {
        CapdNode *cn = pnode->capd;
        if (pnode->IsCapdEnabled() && cn)
            cn->inv(inv);
    }
    // A cs_vNodes lock is not required here when releasing refs for two reasons: one, this only decrements
    // an atomic counter, and two, the counter will always be > 0 at this point, so we don't have to worry
    // that a pnode could be disconnected and no longer exist before the decrement takes place.
    for (CNode *pnode : vNodesCopy)
    {
        pnode->Release();
    }
}

bool CapdNode::FlushMessages()
{
    LOCK(csCapdNode);
    DbgAssert(node, return false);

    if (!invMsgs.empty())
    {
        unsigned int offset = 0;
        do
        {
            node->PushMessage(NetMsgType::CAPDINV, VectorSpan<uint256>(invMsgs, offset, CAPD_MAX_INV_TO_SEND));
            offset += CAPD_MAX_INV_TO_SEND;
        } while (offset < invMsgs.size());

        invMsgs.clear();
    }

    if (!requestMsgs.empty())
    {
        unsigned int offset = 0;
        do
        {
            node->PushMessage(NetMsgType::CAPDGETMSG, msgpool.GetRelayPriority(),
                VectorSpan<uint256>(requestMsgs, offset, CAPD_MAX_MSG_TO_REQUEST));
            offset += CAPD_MAX_MSG_TO_REQUEST;
        } while (offset < requestMsgs.size());

        requestMsgs.clear();
    }

    if (!sendMsgs.empty())
    {
        unsigned int offset = 0;
        std::vector<CapdMsg> sm; // TODO figure out shared_ptr serialization
        for (auto m : sendMsgs)
            sm.push_back(*m);
        do
        {
            node->PushMessage(NetMsgType::CAPDMSG, VectorSpan<CapdMsg>(sm, offset, CAPD_MAX_MSG_TO_SEND));
            offset += CAPD_MAX_MSG_TO_SEND;
        } while (offset < sm.size());

        sendMsgs.clear();
    }

    return true;
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
    CapdMsgRef msg = MakeMsgRef(CapdMsg(msgData));
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
        catch (CapdMsgPoolException &e)
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
