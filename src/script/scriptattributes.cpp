#include "consensus/grouptokens.h"
#include "interpreter.h"
#include "script.h"
#include "streams.h"
#include <vector>

CGroupTokenID NoGroup; // No group specified.

static bool IsPushOpcode(opcodetype opcode) { return opcode <= OP_16; }
CAmount DeserializeAmount(opcodetype opcodeQty, std::vector<unsigned char> &vec)
{
    /* Disallow raw opcodes or single byte sizes, because having them is an unnecessary decode complication
    if ((opcodeQty >= OP_1) && (opcodeQty <= OP_16))
    {
        return opcodeQty-OP_1+1;
    }
    if (opcodeQty == OP_1NEGATE)
    {
        return 0x81;
    }

    int sz = vec.size();
    if (sz == 1)
    {
        return vec[0];
    }
    */
    int sz = vec.size();
    // client version is 0 because it is unneeded for this read and is unavailable in libraries that include this code
    CDataStream strm(vec, SER_NETWORK, 0);
    if (sz == 2)
    {
        return ser_readdata16(strm);
    }
    if (sz == 4)
    {
        return ser_readdata32(strm);
    }
    if (sz == 8)
    {
        uint64_t v = ser_readdata64(strm);
        return (CAmount)v;
    }
    throw std::ios_base::failure("DeserializeAmount(): invalid format");
}

bool IsScriptGrouped(const CScript &script, CScript::const_iterator *pcin, CGroupTokenInfo *grp)
{
    CScript::const_iterator pc = pcin ? *pcin : script.begin();
    // If the caller isn't interested in the group data, then just dump it here.
    CGroupTokenInfo extra;
    if (grp == nullptr)
        grp = &extra;
    else
        grp->clear();

    std::vector<unsigned char> groupId;
    std::vector<unsigned char> tokenQty;
    std::vector<unsigned char> data;
    opcodetype opcode;
    opcodetype opcodeGrp;
    opcodetype opcodeQty;

    // mintMeltGroup = ExtractControllingGroup(script);

    if (!script.GetOp(pc, opcodeGrp, groupId))
    {
        grp->associatedGroup = NoGroup;
        return false;
    }

    if (!script.GetOp(pc, opcodeQty, tokenQty))
    {
        grp->associatedGroup = NoGroup;
        return false;
    }

    if (!script.GetOp(pc, opcode, data))
    {
        grp->associatedGroup = NoGroup;
        return false;
    }

    if (opcode != OP_GROUP)
    {
        grp->associatedGroup = NoGroup;
        return false;
    }
    else // If OP_GROUP is used, enforce rules on the other fields
    {
        // group must be 32 bytes or more
        if (opcodeGrp < 0x20)
        {
            grp->invalid = true;
            return false;
        }
        /* Disallow amounts to be encoded as a single byte because these may need to have special encodings if
   the SCRIPT_VERIFY_MINIMALDATA flag is set
    // quantity must be 1, 2, 4, or 8 bytes
    if (((opcodeQty < OP_1)||(opcodeQty > OP_16)) && (opcodeQty != OP_1NEGATE) && (opcodeQty != 1) && (opcodeQty != 2)
   && (opcodeQty != 4) && (opcodeQty != 8))
    {
        invalid = true;
        return;
    }
    */

        // Quantity must be a 2, 4, or 8 byte number
        if ((opcodeQty != 2) && (opcodeQty != 4) && (opcodeQty != 8))
        {
            grp->invalid = true;
            return false;
        }

        /* Group pops 2 items from the stack
        for (int i = 0; i < 2; i++) // 2 op_drops
        {
            if (!script.GetOp(pc, opcode, data))
            {
                grp->invalid = true;
                return false;
            }
            if (opcode != OP_DROP)
            {
                grp->invalid = true;
                return false;
            }
        }
        */
    }

    try
    {
        grp->quantity = DeserializeAmount(opcodeQty, tokenQty);
    }
    catch (std::ios_base::failure &f)
    {
        grp->invalid = true;
        return false;
    }
    if (grp->quantity < 0)
    {
        grp->controllingGroupFlags = (GroupAuthorityFlags)grp->quantity;
    }
    grp->associatedGroup = groupId;
    // Since the script matched the opgroup syntax, move the caller's pc foward.
    if (pcin)
        *pcin = pc;
    return true;
}

/* nonstandard
bool MatchGroupedPayToPubkey(const CScript &script, valtype &pubkey, CGroupTokenInfo& grp)
{
    // Standard tx, sender provides pubkey, receiver adds signature
    // Template: "CScript() << OP_PUBKEY << OP_CHECKSIG"
    CScript::const_iterator pc = script.begin();
    if (!IsScriptGrouped(script, &pc, &grp)) return false;
    unsigned int offset = &pc[0] - &begin()[0];

    if ((script.size() == offset + CPubKey::PUBLIC_KEY_SIZE + 2) && (script[0] == CPubKey::PUBLIC_KEY_SIZE) &&
        (script.back() == OP_CHECKSIG))
    {
        pubkey = valtype(pc + 1, pc + CPubKey::PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }

    if ((script.size() == offset + CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 2) &&
        (script[0] == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE) &&
        (script.back() == OP_CHECKSIG))
    {
        pubkey = valtype(pc + 1, pc + CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1);
        return CPubKey::ValidSize(pubkey);
    }
    return false;
}
*/

uint256 GetScriptTemplate(const CScript &script, ScriptTemplateError &error, CScript::const_iterator *pcout)
{
    error = ScriptTemplateError::NOT_A_TEMPLATE;
    uint256 nothing = uint256();
    opcodetype opcode;
    opcodetype opcodeTemplateData;
    CScript::const_iterator pc = script.begin();
    IsScriptGrouped(script, &pc); // Move past the group

    // If its not an OP_TEMPLATE, then return the hash of the script with the OP_GROUP prefix stripped off
    CScript restScript = CScript(pc, script.end());
    std::vector<unsigned char> rest = ToByteVector(restScript);
    CSHA256 sha;
    sha.Write(&rest[0], rest.size());
    uint256 restHash;
    sha.Finalize(restHash.begin());

    // expecting DATA OP_TEMPLATE

    // next will be the template hash if it exists
    std::vector<unsigned char> templateId;
    if (!script.GetOp(pc, opcodeTemplateData, templateId))
    {
        return restHash;
    }
    if (!IsPushOpcode(opcodeTemplateData))
        return restHash;

    // Now the template opcode
    std::vector<unsigned char> betterBeNoData;
    if (!script.GetOp(pc, opcode, betterBeNoData))
    {
        return restHash;
    }

    if (opcode != OP_TEMPLATE)
    {
        return restHash;
    }

    // template hash must be 32 bytes
    if (opcodeTemplateData != 0x20)
    {
        error = ScriptTemplateError::INVALID;
        return nothing;
    }

    if (pcout)
        *pcout = pc;
    error = ScriptTemplateError::OK;
    return uint256(templateId);
}

bool MatchGroupedPayToPubkeyHash(const CScript &script, std::vector<uint8_t> &pubkeyhash, CGroupTokenInfo &grp)
{
    // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
    // Template: "OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG"
    CScript::const_iterator pc = script.begin();
    if (!IsScriptGrouped(script, &pc, &grp))
        return false;
    unsigned int offset = &pc[0] - &script.begin()[0];

    if (script.size() == offset + 25 && pc[0] == OP_DUP && pc[1] == OP_HASH160 &&
        pc[2] == CPubKey::PUBLIC_KEY_HASH160_SIZE && pc[23] == OP_EQUALVERIFY && pc[24] == OP_CHECKSIG)
    {
        pubkeyhash = std::vector<uint8_t>(pc + 3, pc + CPubKey::PUBLIC_KEY_HASH160_SIZE + 3);
        return true;
    }
    return false;
}
