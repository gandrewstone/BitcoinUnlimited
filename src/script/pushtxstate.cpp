// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/pushtxstate.h"
#include "amount.h"
#include "hashwrapper.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "uint256.h"


uint256 GetPrevoutHash(const CTransaction &txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++)
    {
        ss << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction &txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++)
    {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction &txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vout.size(); n++)
    {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}


uint256 PushTxStateSigHash(uint32_t flavor, const ScriptImportedState &sis)
{
    uint256 hashSequence;
    uint256 hashOutputs;

    /*
    if (!(nHashType & SIGHASH_ANYONECANPAY))
    {
        hashPrevouts = GetPrevoutHash(sis.tx);
    }

    if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE &&
        (nHashType & 0x1f) != SIGHASH_NONE)
    {
        hashSequence = GetSequenceHash(sis.tx);
    }

    if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE)
    {
        hashOutputs = GetOutputsHash(sis.tx);
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < sis.tx.vout.size())
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << txTo.vout[nIn];
        hashOutputs = ss.GetHash();
    }
    */

    CHashWriter ss(SER_GETHASH, 0);
    VchType nah(1, 0);
    // Version
    if (flavor & SigHashFlavors::VERSION)
        ss << sis.tx->nVersion;
    else
        ss << nah;

    // Input prevouts/nSequence (none/all, depending on flags)
    if (flavor & SigHashFlavors::PREVOUTS_HASH)
    {
        uint256 hashPrevouts = GetPrevoutHash(*sis.tx);
        ss << hashPrevouts;
    }
    else
        ss << nah;

    /*
    ss << hashSequence;
    // The input being signed (replacing the scriptSig with scriptCode +
    // amount). The prevout may already be contained in hashPrevout, and the
    // nSequence may already be contain in hashSequence.
    ss << txTo.vin[nIn].prevout;
    ss << static_cast<const CScriptBase &>(scriptCode);
    ss << amount;
    ss << txTo.vin[nIn].nSequence;
    // Outputs (none/one/all, depending on flags)
    ss << hashOutputs;
    // Locktime
    ss << txTo.nLockTime;
    // Sighash type
    ss << nHashType;
    */

    uint256 sighash = ss.GetHash();
    // printf("SigHash: %s\n", sighash.GetHex().c_str());
    return sighash;
}

ScriptError EvalPushTxState(const VchType &specifier, const ScriptImportedState &sis, Stack &stack)
{
    ScriptError ret = SCRIPT_ERR_OK;

    auto specIter = specifier.begin();
    auto specEnd = specifier.end();

    while (specIter != specEnd)
    {
        auto specCur = specIter;
        specIter++;
        switch (*specCur)
        {
        case PushTxStateSpecifier::TX_VERSION:
            stack.push_back(CScriptNum(sis.tx->nVersion).vchStackItem());
            break;
        case PushTxStateSpecifier::TX_ID:
        {
            uint256 hash = sis.tx->GetHash();
            stack.push_back(StackItem(hash.begin(), hash.end()));
        }
        break;
        case PushTxStateSpecifier::TX_SIGHASH:
            break;
        case PushTxStateSpecifier::GROUP_TOKEN_SUPPLY:
            assert(0); // TODO: Not implemented
            break;
        case PushTxStateSpecifier::GROUP_BCH_SUPPLY:
            assert(0); // TODO: Not implemented
            break;
        }
    }

    return ret;
}
