// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/bignum.h"
#include "script/script.h"

#ifndef ANDROID
const BigNum bnZero = 0_BN;
const BigNum bnOne = 1_BN;
const BigNum &bnFalse(bnZero);
const BigNum &bnTrue(bnOne);

BigNum bigNumUpperLimit = bnOne << 4096; // if !(x < upperLimit) throw NUMBER_OUT_OF_RANGE;
BigNum bigNumLowerLimit = -bigNumUpperLimit; // if !(x > lowerLimit) throw NUMBER_OUT_OF_RANGE;

bool BigNumScriptOp(BigNum &bn,
    opcodetype opcode,
    const BigNum &bn1,
    const BigNum &bn2,
    const BigNum &bmd,
    ScriptError *serror)
{
    switch (opcode)
    {
    case OP_ADD:
        bn = bn1 + bn2;
        break;

    case OP_SUB:
        bn = bn1 - bn2;
        break;

    case OP_DIV:
        // denominator must not be 0
        if (bn2 == 0_BN)
        {
            return set_error(serror, SCRIPT_ERR_DIV_BY_ZERO);
        }
        bn = bn1 / bn2;
        break;

    case OP_MOD:
        // divisor must not be 0
        if (bn2 == 0_BN)
        {
            return set_error(serror, SCRIPT_ERR_MOD_BY_ZERO);
        }
        bn = bn1 % bn2;
        break;

    case OP_BOOLAND:
        bn = (bn1 != bnZero && bn2 != bnZero);
        break;
    case OP_BOOLOR:
        bn = (bn1 != bnZero || bn2 != bnZero);
        break;
    case OP_NUMEQUAL:
        bn = (bn1 == bn2);
        break;
    case OP_NUMEQUALVERIFY:
        bn = (bn1 == bn2);
        break;
    case OP_NUMNOTEQUAL:
        bn = (bn1 != bn2);
        break;
    case OP_LESSTHAN:
        bn = (bn1 < bn2);
        break;
    case OP_GREATERTHAN:
        bn = (bn1 > bn2);
        break;
    case OP_LESSTHANOREQUAL:
        bn = (bn1 <= bn2);
        break;
    case OP_GREATERTHANOREQUAL:
        bn = (bn1 >= bn2);
        break;
    case OP_MIN:
        bn = (bn1 < bn2 ? bn1 : bn2);
        break;
    case OP_MAX:
        bn = (bn1 > bn2 ? bn1 : bn2);
        break;
    case OP_MUL:
        bn = bn1 * bn2;
        break;
    default:
        assert(!"invalid opcode");
        break;
    }
    bn = bn.tdiv(bmd);
    return true;
}

#else
const BigNum bnZero;
const BigNum bnOne;
const BigNum &bnFalse(bnZero);
const BigNum &bnTrue(bnOne);

BigNum bigNumUpperLimit;
BigNum bigNumLowerLimit;

bool BigNumScriptOp(BigNum &bn,
    opcodetype opcode,
    const BigNum &bn1,
    const BigNum &bn2,
    const BigNum &bmd,
    ScriptError *serror)
{
    return false;
}
#endif
