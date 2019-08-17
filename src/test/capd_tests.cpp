// Copyright (c) 2016-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "capd.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(capd_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(capd_testvectors)
{
    BOOST_CHECK(1 == 1);

    {  // Probabilistically check that the default constructor inits everything and that CalcHash is reproducible
        CMsg msg1;
        CMsg msg2;
        uint256 msghash1 = msg1.CalcHash();
        uint256 msghash2 = msg2.CalcHash();
        BOOST_CHECK(msghash1 == msghash2);
        printf("%s\n", msghash1.ToString().c_str());
    }

    {
        
        CMsg msg1("this is a test");
        arith_uint256 target = UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg1.difficultyBits = target.GetCompact();
        msg1.Mine();
        printf("Soln found: %u\n", msg1.nonce);
    }

}

BOOST_AUTO_TEST_CASE(capd_testhttp)
{
    BOOST_CHECK(1 == 1);

}

BOOST_AUTO_TEST_SUITE_END()
