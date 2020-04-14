// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "grouptokens.h"
#include "base58.h"
#include "cashaddrenc.h"
#include "coincontrol.h"
#include "coins.h"
#include "consensus/validation.h"
#include "dstencode.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "random.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/standard.h"
#include "streams.h"
#include "unlimited.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include <algorithm>

bool IsAnyTxOutputGrouped(const CTransaction &tx)
{
    for (const CTxOut &txout : tx.vout)
    {
        CGroupTokenInfo grp(txout.scriptPubKey);
        if (grp.invalid)
            return true; // Its still grouped even if invalid
        if (grp.associatedGroup != NoGroup)
            return true;
    }

    return false;
}

#if 0 // TBD
bool IsAnyTxOutputGroupedCreation(const CTransaction &tx, const GroupTokenIdFlags tokenGroupIdFlags)
{
    for (const CTxOut& txout : tx.vout) {
        CGroupTokenInfo grp(txout.scriptPubKey);
        if (grp.invalid)
            return false;
        if (grp.isGroupCreation(tokenGroupIdFlags))
            return true;
    }
    return false;
}
#endif

std::vector<unsigned char> SerializeAmount(CAmount num)
{
    CDataStream strm(SER_NETWORK, CLIENT_VERSION);
    if (num < 0) // negative numbers are serialized at full length
    {
        ser_writedata64(strm, num);
    }
    /* Disallow amounts to be encoded as a single byte because these may need to have special encodings if
       the SCRIPT_VERIFY_MINIMALDATA flag is set
    else if (num < 256)
    {
        ser_writedata8(strm, num);
    }
    */
    else if (num <= std::numeric_limits<unsigned short>::max())
    {
        ser_writedata16(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata32(strm, num);
    }
    else
    {
        ser_writedata64(strm, num);
    }
    return std::vector<unsigned char>(strm.begin(), strm.end());
}

#if 0
CGroupTokenID ExtractControllingGroup(const CScript &scriptPubKey)
{
    txnouttype whichType;
    typedef std::vector<unsigned char> valtype;
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return CGroupTokenID();

    // only certain well known script types are allowed to mint or melt
    if ((whichType == TX_PUBKEYHASH) || (whichType == TX_GRP_PUBKEYHASH) || (whichType == TX_SCRIPTHASH) ||
        (whichType == TX_GRP_SCRIPTHASH))
    {
        return CGroupTokenID(uint160(vSolutions[0]));
    }
    return CGroupTokenID();
}
#endif

CGroupTokenInfo::CGroupTokenInfo(const CScript &script)
    : associatedGroup(), controllingGroupFlags(GroupAuthorityFlags::NONE), quantity(0), invalid(false)
{
    IsScriptGrouped(script, nullptr, this);
}


// local class that just keeps track of the amounts of each group coming into and going out of a transaction
class CBalance
{
public:
    CBalance()
        : ctrlPerms(GroupAuthorityFlags::NONE), allowedCtrlOutputPerms(GroupAuthorityFlags::NONE),
          allowedSubgroupCtrlOutputPerms(GroupAuthorityFlags::NONE), ctrlOutputPerms(GroupAuthorityFlags::NONE),
          input(0), output(0), numOutputs(0)
    {
    }
    GroupAuthorityFlags ctrlPerms; // what permissions are provided in inputs
    GroupAuthorityFlags allowedCtrlOutputPerms; // What permissions are provided in inputs with CHILD set
    GroupAuthorityFlags allowedSubgroupCtrlOutputPerms; // What permissions are provided in inputs with CHILD set
    GroupAuthorityFlags ctrlOutputPerms; // What permissions are enabled in outputs
    CAmount input;
    CAmount output;
    uint64_t numOutputs;
    // If covenant restricted, the hash of the first grouped & templated input's prevout is this group's covenant.
    uint256 covenant;
};


bool CheckGroupTokens(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &view)
{
    std::unordered_map<CGroupTokenID, CBalance> gBalance;
    // This is an optimization allowing us to skip single-mint hashes if there are no output groups
    bool anyOutputGroups = false;
    bool anyOutputControlGroups = false;

    CScript firstOpReturn;

    // Iterate through all the outputs constructing the final balances of every group.
    for (const auto &outp : tx.vout)
    {
        const CScript &scriptPubKey = outp.scriptPubKey;
        CGroupTokenInfo tokenGrp(scriptPubKey);
        if ((outp.nValue == 0) && (firstOpReturn.size() == 0) && (outp.scriptPubKey[0] == OP_RETURN))
        {
            firstOpReturn = outp.scriptPubKey; // Used later if this is a group creation transaction
        }
        if (tokenGrp.invalid)
            return state.Invalid(false, REJECT_INVALID, "bad OP_GROUP");
        if (tokenGrp.associatedGroup != NoGroup)
        {
            gBalance[tokenGrp.associatedGroup].numOutputs += 1;

            if (tokenGrp.quantity > 0)
            {
                if (std::numeric_limits<CAmount>::max() - gBalance[tokenGrp.associatedGroup].output < tokenGrp.quantity)
                    return state.Invalid(false, REJECT_INVALID, "token overflow");
                gBalance[tokenGrp.associatedGroup].output += tokenGrp.quantity;
                anyOutputGroups = true;
            }
            else if (tokenGrp.quantity == 0)
            {
                return state.Invalid(false, REJECT_INVALID, "OP_GROUP quantity is zero");
            }
            else // this is an authority output
            {
                gBalance[tokenGrp.associatedGroup].ctrlOutputPerms |= (GroupAuthorityFlags)tokenGrp.quantity;
                anyOutputControlGroups = true;
            }
        }
    }

    // Now iterate through the inputs applying them to match outputs.
    // If any input utxo address matches a non-bitcoin group address, defer since this could be a mint or burn
    for (const auto &inp : tx.vin)
    {
        const COutPoint &prevout = inp.prevout;
        CoinAccessor coin(view, prevout);
        if (coin->IsSpent()) // should never happen because you've already CheckInputs(tx,...)
        {
            DbgAssert(!"Checking token group for spent coin", );
            return state.Invalid(false, REJECT_INVALID, "already-spent");
        }
        // no prior coins can be grouped.
        if (coin->nHeight < miningEnforceOpGroup.Value())
            continue;
        const CScript &script = coin->out.scriptPubKey;
        CGroupTokenInfo tokenGrp(script);
        // The prevout should never be invalid because that would mean that this node accepted a block with an
        // invalid OP_GROUP tx in it.
        if (tokenGrp.invalid)
            continue;
        CAmount amount = tokenGrp.quantity;
        if (tokenGrp.controllingGroupFlags != GroupAuthorityFlags::NONE)
        {
            auto temp = tokenGrp.controllingGroupFlags;
            // outputs can have all the permissions of inputs, except for 1 special case
            // If CCHILD is not set, no outputs can be authorities (so unset the CTRL flag)
            if (hasCapability(temp, GroupAuthorityFlags::CCHILD))
            {
                gBalance[tokenGrp.associatedGroup].allowedCtrlOutputPerms |= temp;
                if (hasCapability(temp, GroupAuthorityFlags::SUBGROUP))
                    gBalance[tokenGrp.associatedGroup].allowedSubgroupCtrlOutputPerms |= temp;
            }
            // Track what permissions this transaction has
            gBalance[tokenGrp.associatedGroup].ctrlPerms |= temp;
        }

        ScriptTemplateError error;
        uint256 templateId = GetScriptTemplate(script, error);
        if (error == ScriptTemplateError::INVALID) // should never happen because this script is confirmed onchain
        {
            return state.Invalid(false, REJECT_INVALID, "invalid prevout template attribute");
        }

        // The first grouped template input is the covenant for this group (if group is covenanted).
        if ((error == ScriptTemplateError::OK) && (gBalance[tokenGrp.associatedGroup].covenant == uint256()))
        {
            gBalance[tokenGrp.associatedGroup].covenant = templateId;
        }

        if ((tokenGrp.associatedGroup != NoGroup) && !tokenGrp.isAuthority())
        {
            if (std::numeric_limits<CAmount>::max() - gBalance[tokenGrp.associatedGroup].input < amount)
                return state.Invalid(false, REJECT_INVALID, "token overflow");
            gBalance[tokenGrp.associatedGroup].input += amount;
        }
    }

    // Now pass thru the outputs applying parent group capabilities to any subgroups
    for (auto &txo : gBalance)
    {
        CGroupTokenID group = txo.first;
        CBalance &bal = txo.second;
        if (group.isSubgroup())
        {
            CGroupTokenID parentgrp = group.parentGroup();
            auto parentSearch = gBalance.find(parentgrp);
            if (parentSearch != gBalance.end()) // The parent group is part of the inputs
            {
                CBalance &parentData = parentSearch->second;
                if (hasCapability(parentData.ctrlPerms, GroupAuthorityFlags::SUBGROUP))
                {
                    // Give the subgroup has all the capabilities the parent group had,
                    // except no recursive subgroups so remove the subgrp authority bit.
                    bal.ctrlPerms |= parentData.ctrlPerms & ~(GroupAuthorityFlags::SUBGROUP);
                }

                // Give the subgroup authority printing permissions as specified by the parent group
                bal.allowedCtrlOutputPerms |=
                    parentData.allowedSubgroupCtrlOutputPerms & ~(GroupAuthorityFlags::SUBGROUP);
            }
        }
    }

    // Now pass thru the outputs ensuring balance or mint/melt permission
    for (auto &txo : gBalance)
    {
        CBalance &bal = txo.second;
        // If it has an authority, with no input authority, check mint
        if (hasCapability(bal.ctrlOutputPerms, GroupAuthorityFlags::CTRL) &&
            (bal.ctrlPerms == GroupAuthorityFlags::NONE))
        {
            CHashWriter mintGrp(SER_GETHASH, PROTOCOL_VERSION);
            mintGrp << tx.vin[0].prevout;
            if (firstOpReturn.size())
            {
                std::vector<unsigned char> data(firstOpReturn.begin(), firstOpReturn.end());
                mintGrp << data;
            }
            mintGrp << (((uint64_t)bal.ctrlOutputPerms) & ~((uint64_t)GroupAuthorityFlags::ALL_BITS));
            CGroupTokenID newGrpId(mintGrp.GetHash());

            if (newGrpId == txo.first) // This IS new group because id matches hash, so allow all authority.
            {
                if (bal.numOutputs != 1) // only allow the single authority tx during a create
                    return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-create",
                        "Multiple grouped outputs created during group creation transaction");
                bal.allowedCtrlOutputPerms = bal.ctrlPerms = GroupAuthorityFlags::ALL;
            }
#if 0 // TBD            
            else
            {
                if (((uint64_t)bal.ctrlOutputPerms & (uint64_t)~GroupAuthorityFlags::ALL_BITS) != 0)
                {
                    return state.Invalid(false, REJECT_INVALID, "grp-invalid-tx",
                         "Only mint transactions can have a nonce");
                }
            }
#endif
        }

        if ((bal.input > bal.output) && !hasCapability(bal.ctrlPerms, GroupAuthorityFlags::MELT))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-melt",
                "Group input exceeds output, but no melt permission");
        }
        if ((bal.input < bal.output) && !hasCapability(bal.ctrlPerms, GroupAuthorityFlags::MINT))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-mint",
                "Group output exceeds input, but no mint permission");
        }
        // Some output permissions are set that are not in the inputs
        if (((uint64_t)(bal.ctrlOutputPerms & GroupAuthorityFlags::ALL)) &
            ~((uint64_t)(bal.allowedCtrlOutputPerms & GroupAuthorityFlags::ALL)))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-perm",
                "Group output permissions exceeds input permissions");
        }
    }

    // Now pass thru the outputs ensuring group covenants, and that any templates are valid.
    for (const auto &outp : tx.vout)
    {
        const CScript &script = outp.scriptPubKey;
        CGroupTokenInfo grp(script);

        ScriptTemplateError error;
        uint256 templateId = GetScriptTemplate(script, error);
        if (error == ScriptTemplateError::INVALID)
        {
            return state.Invalid(false, REJECT_INVALID, "template-invalid", "invalid template in constraint script");
        }

        // If this output's group is covenanted, enforce it.
        if (grp.associatedGroup.hasFlag(GroupTokenIdFlags::SAME_SCRIPT))
        {
            CBalance &grpData = gBalance[grp.associatedGroup];

            // All covenanted groups must use templates
            if (error == ScriptTemplateError::NOT_A_TEMPLATE)
            {
                return state.Invalid(
                    false, REJECT_INVALID, "grp-covenant-no-template", "covenanted group output is not a template");
            }

            // If no inputs have the authority to change the covenant, then this output must match the covenant
            if (!hasCapability(grpData.ctrlPerms, GroupAuthorityFlags::RESCRIPT))
            {
                if (templateId != grpData.covenant)
                {
                    return state.Invalid(false, REJECT_INVALID, "grp-covenant-bad-template",
                        "covenant group has incorrect output template");
                }
            }
        }
    }
    return true;
}


bool CGroupTokenID::isUserGroup(void) const { return (!data.empty()); }
bool CGroupTokenID::isSubgroup(void) const { return (data.size() > PARENT_GROUP_ID_SIZE); }
CGroupTokenID CGroupTokenID::parentGroup(void) const
{
    if (data.size() <= PARENT_GROUP_ID_SIZE)
        return CGroupTokenID(data);
    return CGroupTokenID(std::vector<unsigned char>(data.begin(), data.begin() + PARENT_GROUP_ID_SIZE));
}

bool CGroupTokenID::hasFlag(GroupTokenIdFlags flag) const
{
    return data.size() >= PARENT_GROUP_ID_SIZE ? hasGroupTokenIdFlag((GroupTokenIdFlags)data[31], flag) : false;
}
