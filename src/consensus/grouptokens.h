// Copyright (c) 2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TOKEN_GROUPS_H
#define TOKEN_GROUPS_H

#include "chainparams.h"
//#include "coins.h"
#include "consensus/validation.h"
#include "pubkey.h"
#include <unordered_map>
class CWallet;
class CCoinsViewCache;

/** Transaction cannot be committed on my fork */
static const unsigned int REJECT_GROUP_IMBALANCE = 0x104;

/** What block height to start enforcing groups */
extern uint32_t enforceOpGroupStartHeight;
/** If true, the fork will set enforceOpGroupStartHeight to the fork height */
extern bool miningForkOpGroup;

enum class GroupTokenIdFlags : uint16_t
{
    NONE = 0,
    COVENANT = 1U, // covenants/ encumberances -- output script template must match input
    HOLDS_BCH = 1U << 1, // group inputs and outputs must balance BCH, token quantity MUST be 0
    GROUP_RESERVED_BITS = 0xFFFF & ~(COVENANT | HOLDS_BCH),
    DEFAULT = 0
};

enum class GroupAuthorityFlags : uint64_t
{
    AUTHORITY = 1ULL << 63, // Is this a controller utxo (forces negative number in amount)
    MINT = 1ULL << 62, // Can mint tokens
    MELT = 1ULL << 61, // Can melt tokens,
    BATON = 1ULL << 60, // Can create controller outputs
    RESCRIPT = 1ULL << 59, // Can change the redeem script
    SUBGROUP = 1ULL << 58,

    NONE = 0,
    ACTIVE_FLAG_BITS = AUTHORITY | MINT | MELT | BATON | RESCRIPT | SUBGROUP,
    ALL_FLAG_BITS = 0xffffULL << (64 - 16),
    RESERVED_FLAG_BITS = ACTIVE_FLAG_BITS & ~ALL_FLAG_BITS
};


enum class ScriptTemplateError : uint8_t
{
    OK = 0,
    NOT_A_TEMPLATE = 1U,
    INVALID = 2U
};

inline GroupTokenIdFlags operator|(const GroupTokenIdFlags a, const GroupTokenIdFlags b)
{
    GroupTokenIdFlags ret = (GroupTokenIdFlags)(((uint8_t)a) | ((uint8_t)b));
    return ret;
}

inline GroupTokenIdFlags operator~(const GroupTokenIdFlags a)
{
    GroupTokenIdFlags ret = (GroupTokenIdFlags)(~((uint8_t)a));
    return ret;
}

inline GroupTokenIdFlags operator&(const GroupTokenIdFlags a, const GroupTokenIdFlags b)
{
    GroupTokenIdFlags ret = (GroupTokenIdFlags)(((uint8_t)a) & ((uint8_t)b));
    return ret;
}

inline GroupTokenIdFlags &operator|=(GroupTokenIdFlags &a, const GroupTokenIdFlags b)
{
    a = (GroupTokenIdFlags)(((uint8_t)a) | ((uint8_t)b));
    return a;
}

inline GroupTokenIdFlags &operator&=(GroupTokenIdFlags &a, const GroupTokenIdFlags b)
{
    a = (GroupTokenIdFlags)(((uint8_t)a) & ((uint8_t)b));
    return a;
}
inline bool hasGroupTokenIdFlag(GroupTokenIdFlags object, GroupTokenIdFlags flag)
{
    return (((uint16_t)object) & ((uint16_t)flag)) == (uint16_t)flag;
}

// The definitions below are used internally.  They are defined here for use in unit tests.
class CGroupTokenID
{
protected:
    std::vector<unsigned char> data;
    enum
    {
        PARENT_GROUP_ID_SIZE = 32
    };

public:
    //* no token group
    CGroupTokenID() {}
    //* for testing only -- force a fake group ID
    CGroupTokenID(unsigned char c, GroupTokenIdFlags flags = GroupTokenIdFlags::NONE) : data(PARENT_GROUP_ID_SIZE)
    {
        data[0] = c;
        data[30] = ((unsigned int)flags) >> 8;
        data[31] = ((unsigned int)flags) & 255;
    }
    //* handles CKeyID and CScriptID
    CGroupTokenID(const uint160 &id) : data(ToByteVector(id)) {}
    //* handles single mint group id, and possibly future larger size CScriptID
    CGroupTokenID(const uint256 &id) : data(ToByteVector(id)) {}
    //* Assign the groupID from a vector
    CGroupTokenID(const std::vector<unsigned char> &id) : data(id)
    {
        // Token group IDs must be able to be pushed onto the stack, but this check interferes with consensus tests
        // DbgAssert(id.size() <= MAX_SCRIPT_ELEMENT_SIZE, );
    }

    void NoGroup(void) { data.resize(0); }
    bool operator==(const CGroupTokenID &id) const { return data == id.data; }
    bool operator!=(const CGroupTokenID &id) const { return data != id.data; }
    bool operator<(const CGroupTokenID &id) const { return data < id.data; }
    bool operator>(const CGroupTokenID &id) const { return data > id.data; }
    bool operator<=(const CGroupTokenID &id) const { return data <= id.data; }
    bool operator>=(const CGroupTokenID &id) const { return data >= id.data; }
    //* returns true if this is a user-defined group -- ie NOT bitcoin cash or no group
    bool isUserGroup(void) const;
    //* returns true if this is a subgroup
    bool isSubgroup(void) const;
    //* returns the parent group if this is a subgroup or itself.
    CGroupTokenID parentGroup(void) const;

    const std::vector<unsigned char> &bytes(void) const { return data; }
    //* Convert this token group ID into a mint/melt address
    // CTxDestination ControllingAddress(txnouttype addrType) const;
    //* Returns this groupID as a string in cashaddr format
    // std::string Encode(const CChainParams &params = Params()) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(data);
    }

    bool hasFlag(GroupTokenIdFlags flag) const;
};

namespace std
{
template <>
struct hash<CGroupTokenID>
{
public:
    size_t operator()(const CGroupTokenID &s) const
    {
        const std::vector<unsigned char> &v = s.bytes();
        int sz = v.size();
        if (sz >= 4)
            return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) << v[3];
        else if (sz > 0)
            return v[0]; // It would be better to return all bytes but sizes 1 to 3 currently unused
        else
            return 0;
    }
};
} // namespace std


inline GroupAuthorityFlags operator|(const GroupAuthorityFlags a, const GroupAuthorityFlags b)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(((uint64_t)a) | ((uint64_t)b));
    return ret;
}

inline GroupAuthorityFlags operator~(const GroupAuthorityFlags a)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(~((uint64_t)a));
    return ret;
}

inline GroupAuthorityFlags operator&(const GroupAuthorityFlags a, const GroupAuthorityFlags b)
{
    GroupAuthorityFlags ret = (GroupAuthorityFlags)(((uint64_t)a) & ((uint64_t)b));
    return ret;
}

inline GroupAuthorityFlags &operator|=(GroupAuthorityFlags &a, const GroupAuthorityFlags b)
{
    a = (GroupAuthorityFlags)(((uint64_t)a) | ((uint64_t)b));
    return a;
}

inline GroupAuthorityFlags &operator&=(GroupAuthorityFlags &a, const GroupAuthorityFlags b)
{
    a = (GroupAuthorityFlags)(((uint64_t)a) & ((uint64_t)b));
    return a;
}

inline bool hasCapability(GroupAuthorityFlags object, const GroupAuthorityFlags capability)
{
    return (((uint64_t)object) & ((uint64_t)capability)) != 0;
}

inline CAmount toAmount(GroupAuthorityFlags f) { return (CAmount)f; }
class CGroupTokenInfo
{
public:
    CGroupTokenInfo() : associatedGroup(), controllingGroupFlags(GroupAuthorityFlags::NONE), quantity(0), invalid(true)
    {
    }
    CGroupTokenInfo(const CGroupTokenID &associated, const GroupAuthorityFlags _controllingGroupFlags, CAmount qty = 0)
        : associatedGroup(associated), controllingGroupFlags(_controllingGroupFlags), quantity(qty), invalid(false)
    {
    }
    CGroupTokenInfo(const CKeyID &associated, const GroupAuthorityFlags _controllingGroupFlags, CAmount qty = 0)
        : associatedGroup(associated), controllingGroupFlags(_controllingGroupFlags), quantity(qty), invalid(false)
    {
    }
    // Return the controlling (can mint and burn) and associated (OP_GROUP in script) group of a script
    CGroupTokenInfo(const CScript &script);

    /** Reset the info in this object for subsequent use, equivalent to the default ctor */
    void clear()
    {
        associatedGroup = CGroupTokenID();
        controllingGroupFlags = GroupAuthorityFlags(GroupAuthorityFlags::NONE);
        quantity = 0;
        invalid = false;
    }

    CGroupTokenID associatedGroup; // The group announced by the script (or the bitcoin group if no OP_GROUP)
    GroupAuthorityFlags controllingGroupFlags; // if the utxo is a controller this is not NONE
    CAmount quantity; // The number of tokens specified in this script
    bool invalid;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(this->associatedGroup);
        READWRITE(this->quantity);
        READWRITE(this->invalid);
    }

    // return true if this object is a token authority.
    bool isAuthority() const
    {
        return ((controllingGroupFlags & GroupAuthorityFlags::AUTHORITY) == GroupAuthorityFlags::AUTHORITY);
    }
    // return true if this object is a new token creation output.
    // Note that the group creation nonce cannot be 0
    bool isGroupCreation(GroupTokenIdFlags tokenGroupIdFlags = GroupTokenIdFlags::NONE) const
    {
        bool hasNonce = ((uint64_t)quantity & (uint64_t)~GroupAuthorityFlags::ALL_FLAG_BITS) != 0;

        return (((controllingGroupFlags & GroupAuthorityFlags::AUTHORITY) == GroupAuthorityFlags::AUTHORITY) &&
                hasNonce && associatedGroup.hasFlag(tokenGroupIdFlags));
    }
    // return true if this object allows minting.
    bool allowsMint() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MINT);
    }
    // return true if this object allows melting.
    bool allowsMelt() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::MELT);
    }
    // return true if this object allows child controllers.
    bool allowsRenew() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::BATON)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::BATON);
    }
    // return true if this object allows rescripting.
    bool allowsRescript() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::RESCRIPT)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::RESCRIPT);
    }
    // return true if this object allows subgroups.
    bool allowsSubgroup() const
    {
        return (controllingGroupFlags & (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::SUBGROUP)) ==
               (GroupAuthorityFlags::AUTHORITY | GroupAuthorityFlags::SUBGROUP);
    }

    bool isInvalid() const { return invalid; };
    bool operator==(const CGroupTokenInfo &g)
    {
        if (g.invalid || invalid)
            return false;
        return ((associatedGroup == g.associatedGroup) && (controllingGroupFlags == g.controllingGroupFlags));
    }
};

// Verify that the token groups in this transaction properly balance
bool CheckGroupTokens(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &view);

// Return true if any output in this transaction is part of a group
bool IsAnyTxOutputGrouped(const CTransaction &tx);

bool IsAnyTxOutputGroupedCreation(const CTransaction &tx,
    const GroupTokenIdFlags tokenGroupIdFlags = GroupTokenIdFlags::NONE);

// Serialize a CAmount into an array of bytes.
// This serialization does not store the length of the serialized data within the serialized data.
// It is therefore useful only within a system that already identifies the length of this field (such as a CScript).
std::vector<unsigned char> SerializeAmount(CAmount num);

// Deserialize a CAmount from an array of bytes.
// This function uses the size of the vector to determine how many bytes were used in serialization.
// It is therefore useful only within a system that already identifies the length of this field (such as a CScript).
CAmount DeserializeAmount(opcodetype opcodeQty, std::vector<unsigned char> &vec);

/** Identify OP_GROUP script attribute sequence (i.e. data, data, OP_GROUP, OP_DROP, OP_DROP)
        @param[in] The script
        @param[inout] offsetInOut If not null, start at this offset in hashBytes, and if this a group attribute
                           advance this "program counter" to the byte AFTER the OP_GROUP attribute.
        @param[out] grp If not null, set to group info read from the script.
        @return true If this pointed to an OP_GROUP attribute sequence
*/
bool IsScriptGrouped(const CScript &script, CScript::const_iterator *pc = nullptr, CGroupTokenInfo *grp = nullptr);

/** Get the script's template hash if this script is a template
    @param[in] script The script
    @param[out] error Whether the script is a template, is not a template, or is an invalid template.
    @param[out] pcout Points to the script location after the script template.
    @return The script template's hash only if error is ScriptTemplateError::OK
 */
uint256 GetScriptTemplate(const CScript &script, ScriptTemplateError &error, CScript::const_iterator *pcout = nullptr);

// Convenience function to just extract the group from a script
inline CGroupTokenID GetGroupToken(const CScript &script) { return CGroupTokenInfo(script).associatedGroup; }
extern CGroupTokenID NoGroup;

#endif
