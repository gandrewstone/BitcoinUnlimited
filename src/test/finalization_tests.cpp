// Copyright (c) 2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "config.h"
#include "test/test_bitcoin.h"
#include "validation/validation.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(finalization_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(finalizationDelay)
{
    CScript p2pk_scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CBlock block;

    LOCK(cs_main);

    // We should have no finalized block because the 100 blocks generated by the
    // test setup are too close to "now";
    BOOST_CHECK_MESSAGE(
        GetFinalizedBlock() == nullptr, "No block finalized (tip at height " << chainActive.Tip()->nHeight << ")");

    // Create maxreorgdepth blocks. Auto-finalization will not occur because
    // the delay is not expired
    int64_t mockedTime = GetTime();
    for (int i = 0; i < DEFAULT_MAX_REORG_DEPTH; i++)
    {
        block = CreateAndProcessBlock({}, p2pk_scriptPubKey);
        // These blocks are too recent.
        BOOST_CHECK_MESSAGE(
            GetFinalizedBlock() == nullptr, "No block finalized (tip at height " << chainActive.Tip()->nHeight << ")");
    }

    // Make the finalization time to expire
    mockedTime += DEFAULT_MIN_FINALIZATION_DELAY + 1;
    SetMockTime(mockedTime);

    // Next maxreorgdepth blocks should cause auto-finalization
    CBlockIndex *blockToFinalize = chainActive.Tip()->GetAncestor(chainActive.Tip()->nHeight - DEFAULT_MAX_REORG_DEPTH);

    for (int i = 0; i < DEFAULT_MAX_REORG_DEPTH; i++)
    {
        blockToFinalize = chainActive.Next(blockToFinalize);
        block = CreateAndProcessBlock({}, p2pk_scriptPubKey);
        BOOST_CHECK_MESSAGE(GetFinalizedBlock() == blockToFinalize,
            "Block finalized at height " << blockToFinalize->nHeight << " (tip at height " << chainActive.Tip()->nHeight
                                         << ")");
    }

    // Next blocks won't cause auto-finalization because the delay is not
    // expired
    for (int i = 0; i < DEFAULT_MAX_REORG_DEPTH; i++)
    {
        block = CreateAndProcessBlock({}, p2pk_scriptPubKey);
        // These blocks are finalized.
        BOOST_CHECK_MESSAGE(GetFinalizedBlock() == blockToFinalize,
            "Finalized block remains unchanged at height " << blockToFinalize->nHeight << " (tip at height "
                                                           << chainActive.Tip()->nHeight << ")");
    }

    // Make the finalization time to expire
    mockedTime += DEFAULT_MIN_FINALIZATION_DELAY + 1;
    SetMockTime(mockedTime);

    blockToFinalize = chainActive.Tip()->GetAncestor(chainActive.Tip()->nHeight - DEFAULT_MAX_REORG_DEPTH);

    // Create some more blocks.
    // Finalization should start moving again.
    for (int i = 0; i < DEFAULT_MAX_REORG_DEPTH; i++)
    {
        blockToFinalize = chainActive.Next(blockToFinalize);
        block = CreateAndProcessBlock({}, p2pk_scriptPubKey);
        BOOST_CHECK_MESSAGE(GetFinalizedBlock() == blockToFinalize,
            "Block finalized at height " << blockToFinalize->nHeight << " (tip at height " << chainActive.Tip()->nHeight
                                         << ")");
    }
}

BOOST_AUTO_TEST_SUITE_END()
