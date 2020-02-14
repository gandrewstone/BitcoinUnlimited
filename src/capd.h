// Copyright (c) 2019 G. Andrew Stone

// Counterparty and protocol discovery
#include <limits>
#include <queue>

#include "arith_uint256.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"
#include "utiltime.h"

#undef foreach
#include "boost/multi_index/hashed_index.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"

extern bool StartCapd();
extern void StopCapd();

typedef double PriorityType;

extern uint64_t NOMINAL_MSG_SIZE; // A message of this size or less has no priority penalty

extern arith_uint256 MIN_FORWARD_MSG_DIFFICULTY;
extern arith_uint256 MIN_LOCAL_MSG_DIFFICULTY;

extern uint64_t MSG_LIFETIME_SEC; //!< expected message lifetime in seconds

/** The minimum message priority accepted and forwarded by the network
    Having a minimum reduces spam even if the msg pool is under utilized */
extern PriorityType MIN_RELAY_PRIORITY;
/** The minimum priority accepted by network nodes, but this message won't be forwarded.
    Having a minimum reduces spam even if the msg pool is under utilized */
extern PriorityType MIN_LOCAL_PRIORITY;

/** The maximum uint256 number (a useful constant) */
extern arith_uint256 MAX_UINT256;

/* When converting a double to a uint256, precision will be lost.  This is how much to keep.
   Basically, doubles are multiplied by this amount before being converted to a uint256.
   This means that this precision is often lost in related uint256 values because the algorithm
   looks something like this to avoid overflow:

   uintVal/CONVERSION_FRAC * (uint256) ((uint64_t) (doubleVal * CONVERSION_FRAC))
 */
extern const unsigned long int PRIORITY_CONVERSION_FRAC;

/** return the message priority given these parameters
  @param difficultyBits  The difficulty of this message's POW, expressed in bitcoin's degenerate floating point format
  @param msgContentSize  The length of the message body
  @param age             The difference between now and the message's creation time, in seconds
  @return priority -- higher priority messages are higher numbers
*/
PriorityType Priority(uint32_t difficultyBits, size_t msgContentSize, uint64_t age);

/** return the message priority given these parameters
  @param hashTarget  The difficulty of this message's POW, expressed in the 256 bit number that the hash must be < then
  @param msgContentSize  The length of the message body
  @param age             The difference between now and the message's creation time, in seconds
  @return priority -- higher priority messages are higher numbers
*/
PriorityType Priority(arith_uint256 hashTarget, size_t msgContentSize, uint64_t age);


/** return the difficulty given these parameters.  Inverse of the Priority function.
 */
arith_uint256 aPriorityToDifficultyTarget(PriorityType priority, size_t msgContentSize, uint64_t age);
inline uint256 PriorityToDifficultyTarget(PriorityType priority, size_t msgContentSize, uint64_t age)
{
    return ArithToUint256(aPriorityToDifficultyTarget(priority, msgContentSize, age));
}


//! Contains a node and information about what it wants notifications for
class CNotify
{
protected:
public:
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
    uint8_t version; //!< (not network serialized) The expected serialization version

    uint64_t createTime = 0; //!< When this message was created (seconds since epoch)
    //! When this message expires (seconds since epoch) max_int means never
    uint64_t expiration = std::numeric_limits<short>::max();
    uint160 rescindHash; //!< When the preimage is published, this message expires, 0 means no preimage
    std::vector<uint8_t> data; //!< The message contents
    uint32_t difficultyBits = 0; //!< the message's proof of work target
    uint64_t nonce = 0; //!< needed to prove this message's POW

    CMsg(uint8_t ver = CURRENT_VERSION) : version(ver) {}
    CMsg(const std::string &indata, uint8_t ver = CURRENT_VERSION)
        : version(ver), createTime(GetTime()), data(indata.begin(), indata.end())
    {
    }

    CMsg(const std::vector<uint8_t> &indata, uint8_t ver = CURRENT_VERSION)
        : version(ver), createTime(GetTime()), data(indata.begin(), indata.end())
    {
    }

    bool matches(std::array<unsigned char, 2> &arr)
    {
        if (data.size() < 2)
            return false;
        return ((arr[0] == data[0]) && (arr[1] == data[1]));
    }

    bool matches(std::array<unsigned char, 4> &arr)
    {
        if (data.size() < 4)
            return false;
        return ((arr[0] == data[0]) && (arr[1] == data[1]) && (arr[2] == data[2]) && (arr[3] == data[3]));
    }

    bool matches(std::array<unsigned char, 8> &arr)
    {
        if (data.size() < 8)
            return false;
        for (auto i = 0; i < 8; i++)
            if (arr[i] != data[i])
                return false;
        return true;
    }
    bool matches(std::array<unsigned char, 16> &arr)
    {
        if (data.size() < 16)
            return false;
        for (auto i = 0; i < 16; i++)
            if (arr[i] != data[i])
                return false;
        return true;
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

    /** Return the approximate RAM used by this object */
    size_t RamSize() const { return sizeof(CMsg) + data.size(); }
    /** Calculate this message's hash.  Used for POW and identity */
    uint256 CalcHash() const;

    /** Calculate or return the cached hash of this message */
    uint256 GetHash() const { return CalcHash(); }
    /** Verify that the proof of work matches the difficulty claimed in the message */
    bool DoesPowMatchDifficulty() const;

    /** Returns this message's advertised difficulty.
        Lower values is greater difficulty.
     */
    uint256 GetDifficulty() const
    {
        arith_uint256 hashTarget = arith_uint256().SetCompact(difficultyBits);
        return ArithToUint256(hashTarget);
    }

    /** Find a Nonce that solves this message and difficulty.
    Solve() also updates the message creation time to the passed parameter (defaults to now), so that the solved message
    has the maximum priority.  You can pass a future creationTime to solve a message for the future, but note that
    nodes drop future-dated messages.

    @param creationTime The desired creation time of this message in seconds.  Any number less than 1 year of seconds
           (31536000) is considered to be an offset from the current time.  For example, 0 means "now", 10 would solve
           a message that only becomes valid 10 seconds from now, and -5 solves a message that became valid 5 seconds
           ago.
    @return the solved nonce (the message is updated with this nonce so there's nothing the caller needs to do with it)
    */
    uint64_t Solve(long int creationTime = 0);

    /** Set difficulty bits based on difficulty value */
    void SetDifficulty(arith_uint256 target) { difficultyBits = target.GetCompact(); }
    void SetDifficulty(uint256 target) { SetDifficulty(UintToArith256(target)); }
    /** Sets the difficulty to be harder than the the provided priority.
    This function adjusts based on message size, and assumes no creation time penalty.
    Call Solve() after calling this function, or the message will not meet its own difficulty.
    */
    void SetDifficultyHarderThanPriority(PriorityType priority);

    /** Sets the difficulty to be harder than the provided target.
    You almost certainly want to use SetDifficultyHarderThan(double priority), rather than this function.
    Call Solve() after calling this function, or the message will not meet its own difficulty.
    */
    void SetDifficultyHarderThan(uint256 target);

    /** Returns the message's current priority */
    PriorityType Priority() const;
};


typedef std::shared_ptr<CMsg> CMsgRef;
/** the null pointer equivalent for message references */
extern const CMsgRef nullmsgref;

static inline CMsgRef MakeMsgRef() { return std::make_shared<CMsg>(); }
static inline CMsgRef MakeMsgRef(CMsg &&in) { return std::make_shared<CMsg>(std::forward<CMsg>(in)); }
static inline CMsgRef MsgRefCopy(const CMsg &in) { return std::make_shared<CMsg>(in); }
/** Allow CMsg to be sorted by priority
    begin() will have the lowest priority
    end()-1 will have the highest
*/
class CompareCMsgRefByPriority
{
public:
    bool operator()(const CMsgRef &a, const CMsgRef &b) const { return (a->Priority() < b->Priority()); }
};

// extracts a TxMemPoolEntry's transaction hash
struct MsgHashExtractor
{
    typedef uint256 result_type;
    result_type operator()(const CMsgRef &msg) const { return msg->GetHash(); }
};

class CMsgPoolException : public std::exception
{
public:
    std::string reason;
    CMsgPoolException(const std::string &what) : reason(what) {}
    const char *what() const throw() { return reason.c_str(); }
};

/*
//  Extracts the first 2 bytes of the data
typedef struct MsgLookup1Extractor
{
  typedef uint64_t result_type;

  result_type operator()(const CMsgRef& r) const
  {
      uint64_t ret = 0;
      if (r->data.size() > 0)
          ret = r->data[0];
      return ret;
  }
};
*/

#if 0
template<size_t N>
class InplaceChunk
{
public:
    unsigned char* data;
    uint8_t size;
};


//  Extracts the first 2 bytes of the data
template<size_t N>
class MsgLookupNExtractor
{
public:
    typedef InplaceChunk<N> result_type;
    //typedef std::vector<unsigned char> result_type;

  result_type operator()(const CMsgRef& r) const
  {
      result_type ret;
      ret.data = &r->data[0];
      ret.size = std::min(r->data.size(), N);
      return ret;
  }
};

struct hash2 {
    std::size_t operator()(InplaceChunk<2> const& m) const
  {
      
      uint16_t s = (m.data[0] << 8) + m.data[1];
      return s;
  }
};
#endif

//  Extracts the first 2 bytes of the data
template <size_t N>
class MsgLookupNExtractor
{
public:
    typedef std::array<unsigned char, N> result_type;
    // typedef std::vector<unsigned char> result_type;

    result_type operator()(const CMsgRef &r) const
    {
        result_type ret;
        // ret.resize(N);
        size_t end = std::min(N, (size_t)r->data.size());
        size_t i;
        for (i = 0; i < end; i++)
        {
            ret[i] = r->data[i];
        }
        for (; i < N; i++)
            ret[i] = 0; // Zero any extra if the message is too short
        return ret;
    }
};

struct ArrayHash2
{
    std::size_t operator()(std::array<unsigned char, 2> const &m) const
    {
        uint16_t s = (m[0] << 8) + m[1];
        return s;
    }
};

struct ArrayHash4
{
    std::size_t operator()(std::array<unsigned char, 4> const &m) const
    {
        uint32_t s = 0;
        memcpy(&s, &m[0], 4);
        return s;
    }
};

template <size_t N>
class ArrayHash
{
public:
    std::size_t operator()(std::array<unsigned char, N> const &m) const
    {
        std::string s(m.begin(), m.end());
        boost::hash<std::string> sh;
        return sh(s);
    }
};


// tag for the multi-index container
struct MsgPriorityTag
{
};

// tag for the multi-index container
struct MsgLookup2
{
};
// tag for the multi-index container
struct MsgLookup4
{
};
// tag for the multi-index container
struct MsgLookup8
{
};
// tag for the multi-index container
struct MsgLookup16
{
};

//! The pool of all current messages
class CMsgPool
{
protected:
    typedef boost::multi_index_container<
        CMsgRef,
        boost::multi_index::indexed_by<
            // sorted by message id (hash)
            boost::multi_index::ordered_unique<MsgHashExtractor>,
            // priority:  TODO: replace with random_access so we can grab the median element efficiently
            boost::multi_index::ordered_non_unique<boost::multi_index::tag<MsgPriorityTag>,
                boost::multi_index::identity<CMsgRef>,
                CompareCMsgRefByPriority>,
            boost::multi_index::
                hashed_non_unique<boost::multi_index::tag<MsgLookup2>, MsgLookupNExtractor<2>, ArrayHash2>,
            boost::multi_index::
                hashed_non_unique<boost::multi_index::tag<MsgLookup4>, MsgLookupNExtractor<4>, ArrayHash4>,
            boost::multi_index::
                hashed_non_unique<boost::multi_index::tag<MsgLookup8>, MsgLookupNExtractor<8>, ArrayHash<8> >,
            boost::multi_index::
                hashed_non_unique<boost::multi_index::tag<MsgLookup16>, MsgLookupNExtractor<16>, ArrayHash<16> > > >
        MessageContainer;

    mutable CSharedCriticalSection csMsgPool;
    MessageContainer msgs;

    typedef MessageContainer::nth_index<0>::type::iterator MsgIter;
    typedef MessageContainer::nth_index<1>::type::iterator MsgIterByPriority;
    typedef MessageContainer::nth_index<1>::type::reverse_iterator MsgReverseIterByPriority;

    /** track the size of all the messages in the pool */
    uint64_t size = 0;
    /** the largest this msg pool should become */
    uint64_t maxSize = DEFAULT_MSG_POOL_MAX_SIZE;

public:
    CMsgPool(uint64_t maxSz = DEFAULT_MSG_POOL_MAX_SIZE) : maxSize(maxSz) {}
    enum
    {
        DEFAULT_MSG_POOL_MAX_SIZE = 100 * 1024 * 1024
    };

    /** Return the minimum difficulty for a message to be accepted into this mempool and be elligible for forwarding
        A lower difficulty value is harder because the hash must be below the returned difficulty to be valid.
     */
    uint256 GetRelayDifficulty()
    {
        READLOCK(csMsgPool);
        return _GetRelayDifficulty();
    }
    uint256 _GetRelayDifficulty();

    /** Return the minimum difficulty for a message to be accepted into this mempool. */
    uint256 GetLocalDifficulty()
    {
        READLOCK(csMsgPool);
        return _GetLocalDifficulty();
    }
    uint256 _GetLocalDifficulty();

    /** Return the minimum priority for a message to be accepted into this mempool and be elligible for forwarding
     */
    PriorityType GetRelayPriority()
    {
        READLOCK(csMsgPool);
        return _GetRelayPriority();
    }
    PriorityType _GetRelayPriority();

    /** Return the minimum difficulty for a message to be accepted into this mempool. */
    PriorityType GetLocalPriority()
    {
        READLOCK(csMsgPool);
        return _GetLocalPriority();
    }
    PriorityType _GetLocalPriority();


    /** Add a message into the message pool.  Throws CMsgPoolException if the message was not added */
    void add(const CMsgRef &msg);

    /** Delete every message in the message pool */
    void clear();

    /** Set the message pool size in bytes */
    void SetMaxSize(unsigned int sz) { maxSize = sz; }
    /** Return the current size of the msg pool */
    uint64_t Size() { return size; }
    /** Returns a reference to the message whose id is hash, or a null pointer */
    CMsgRef find(const uint256 &hash) const;

    /** Content search */
    std::vector<CMsgRef> find(const std::vector<unsigned char> c) const;

    /** Remove enough lowest priority messages to make len bytes available in the msgpool */
    void pare(int len)
    {
        WRITELOCK(csMsgPool);
        _pare(len);
    }
    void _pare(int len);


    void _DbgDump();
};


extern CMsgPool msgpool;
