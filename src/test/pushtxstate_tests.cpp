// Copyright (c) 2020 G. Andrew Stone
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "core_io.h"
#include "script/interpreter.h"
#include "script/pushtxstate.h"
#include "script/script.h"
#include "scriptnum10.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <stdint.h>

BOOST_FIXTURE_TEST_SUITE(pushtxstate_tests, BasicTestingSetup)

void testScript(const CScript &s,
    const CMutableTransaction *tx,
    unsigned int inputIdx,
    unsigned int amountIn,
    bool expectedRet,
    bool expectedStackTF,
    ScriptError expectedError)
{
    ScriptImportedStateSig sis(tx, inputIdx, amountIn);
    ScriptMachine sm(0, sis, 0xffffffff, 0xffffffff);
    bool ret = sm.Eval(s);
    BOOST_CHECK_MESSAGE(
        ret == expectedRet, "Received " << ret << " expected " << expectedError << " for script: " << FormatScript(s));
    if (expectedRet)
    {
        BOOST_CHECK(sm.getStack().size() == 1);
        BOOST_CHECK(((bool)sm.getStack()[0]) == expectedStackTF);
    }
    else
    {
        BOOST_CHECK_MESSAGE(sm.getError() == expectedError,
            "got: " << ScriptErrorString(sm.getError()) << " (" << sm.getError() << ")");
    }
}

void testScript(const CScript &s,
    const CMutableTransaction *tx,
    unsigned int inputIdx = 0,
    unsigned int amountIn = 0,
    bool expectedStackTF = true)
{
    testScript(s, tx, inputIdx, amountIn, true, expectedStackTF, SCRIPT_ERR_OK);
}
void testScript(const CScript &s,
    const CMutableTransaction *tx,
    unsigned int inputIdx,
    unsigned int amountIn,
    ScriptError expectedError)
{
    testScript(s, tx, inputIdx, amountIn, false, false, expectedError);
}


BOOST_AUTO_TEST_CASE(pushtxstate)
{
    CScript s;
    CMutableTransaction tx;
    tx.nVersion = 1234;
    s = CScript() << PushTxStateSpecifier::TX_VERSION << OP_PUSH_TX_STATE << 1234 << OP_EQUAL;
    testScript(s, &tx);
    s = CScript() << PushTxStateSpecifier::TX_VERSION << OP_PUSH_TX_STATE << 1235 << OP_EQUAL;
    testScript(s, &tx, 0, 0, false);

    // impossible if s is the constraint script because s changes the hash which changes dependent tx input.
    s = CScript() << PushTxStateSpecifier::TX_ID << OP_PUSH_TX_STATE << tx.GetHash() << OP_EQUAL;
    testScript(s, &tx);

    // Try a double specifier
    std::vector<unsigned char> v;
    v.push_back(PushTxStateSpecifier::TX_VERSION);
    v.push_back(PushTxStateSpecifier::TX_VERSION);
    s = CScript() << v << OP_PUSH_TX_STATE << OP_EQUAL;
    testScript(s, &tx);
}


BOOST_AUTO_TEST_SUITE_END()
