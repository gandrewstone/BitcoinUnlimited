// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUSHTXSTATE_H
#define BITCOIN_PUSHTXSTATE_H
#include "interpreter.h"
#include "script/script_error.h"

#include <vector>

enum PushTxStateSpecifier
{
    TX_VERSION = 0x1,
    TX_ID = 0x2,
    TX_SIGHASH = 0x3,
    GROUP_TOKEN_SUPPLY = 0x4,
    GROUP_BCH_SUPPLY = 0x5,
};

enum SigHashFlavors
{
    VERSION = 1 << 0,
    PREVOUTS_HASH = 1 << 1,
    PREVOUTS_SEQUENCE_HASH = 1 << 2,
    OUTPOINT = 1 << 3,
    SCRIPT_CODE = 1 << 4,
    PREVOUT_VALUE = 1 << 5,
    SEQUENCE = 1 << 6,
    OUTPUTS_HASH = 1 << 7,
    NTH_OUTPUT_HASH = 1 << 8,
    LOCK_TIME = 1 << 9
};

class ScriptImportedState;

typedef std::vector<unsigned char> VchType;

ScriptError EvalPushTxState(const VchType &specifier, const ScriptImportedState &sis, Stack &stack);

#endif
