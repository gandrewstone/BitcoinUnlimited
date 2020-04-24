// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/bignum.h"
#include "script/script.h"

mpz_t bigNumUpperLimit; // if (x > upperLimit) throw NUMBER_OUT_OF_RANGE;
mpz_t bigNumLowerLimit; // if (x < lowerLimit) throw NUMBER_OUT_OF_RANGE;

void BigNumInit()
{
    mpz_init_set_ui(bigNumUpperLimit, 1);
    mpz_mul_2exp(bigNumUpperLimit, bigNumUpperLimit, 4096);
    mpz_neg(bigNumLowerLimit, bigNumUpperLimit);
    mpz_sub_ui(bigNumUpperLimit, bigNumUpperLimit, 1);
    mpz_add_ui(bigNumLowerLimit, bigNumLowerLimit, 1);
}

static const BigNum bnZero = 0_BN;
static const BigNum bnOne = 1_BN;
static const BigNum &bnFalse(bnZero);
static const BigNum &bnTrue(bnOne);


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
    default:
        assert(!"invalid opcode");
        break;
    }
    bn = bn.tdiv(bmd);
    return true;
}
