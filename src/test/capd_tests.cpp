// Copyright (c) 2016-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "capd.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(capd_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(capd_msg_test_vectors)
{
    BOOST_CHECK(1 == 1);

    {  // Probabilistically check that the default constructor inits everything and that CalcHash is reproducible
        CMsg msg1;
        CMsg msg2;
        uint256 msghash1 = msg1.CalcHash();
        uint256 msghash2 = msg2.CalcHash();
        BOOST_CHECK(msghash1 == msghash2);
        printf("%s\n", msghash1.ToString().c_str());

        // Check serialization
        CDataStream ss(SER_NETWORK, 0);
        // encode
        ss << msg1;
        // decode
        CMsg msg3;
        ss >> msg3;
        BOOST_CHECK_MESSAGE(msg1.CalcHash() == msg3.CalcHash(), "serialization/deserialization issue");
    }

    {
        CMsg msg1("this is a test");
        arith_uint256 target = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg1.difficultyBits = target.GetCompact();
        msg1.Mine();
        printf("Soln found: %lu\n", msg1.nonce);

        CMsg msg2("shorter");
        msg2.difficultyBits = target.GetCompact();
        msg2.Mine();
        double startPri = msg1.Priority();

        auto t2 = GetStopwatchMicros();
        CMsg msg3("this is a test");
        target = UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg3.difficultyBits = target.GetCompact();
        msg3.Mine();
        auto t3 = GetStopwatchMicros();
        CMsg msg4("this is a test");
        target = UintToArith256(uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg4.difficultyBits = target.GetCompact();
        msg4.Mine();
        auto t4 = GetStopwatchMicros();
        CMsg msg5("this is a test");
        target = UintToArith256(uint256S("000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg5.difficultyBits = target.GetCompact();
        msg5.Mine();
        auto t5 = GetStopwatchMicros();

        printf("Priorities: %f %f %f\n%f (time: %lu)\n%f (time: %lu)\n%f (time: %lu)\n", startPri, msg1.Priority(), msg2.Priority(),
               msg3.Priority(),
               (t3 - t2),
               msg4.Priority(),
               (t4 - t3),
               msg5.Priority(),
               (t5 - t4)
            );

        // use an old createtime to test lowering priority
        msg5.createTime = GetTime() -  (MSG_LIFETIME_SEC+1);
        msg5.Mine();

        printf("Time expired message: %f\n", msg5.Priority());
        BOOST_CHECK(msg5.Priority() < 0);
        
    }

    if (0)
    {
        CMsg msg("this is a test");
        msg.SetDifficulty(UintToArith256(uint256S("00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
        for (unsigned int i=0;i<1000000;i++)
        {
            msg.SetDifficultyHarderThan(msg.GetDifficulty());
            printf("%s\n", msg.GetDifficulty().GetHex().c_str());
        }
    }

    msgpool.clear();
    msgpool.SetMaxSize(2000);
    uint256 diff = msgpool.GetAdmissionDifficulty();
    BOOST_CHECK(diff ==  MIN_FORWARD_MSG_DIFFICULTY);  // because no messages in the pool
}

BOOST_AUTO_TEST_CASE(capd_pool_test_vectors)
{
    CMsg msg1("this is a test");

    const unsigned int TEST_MSGPOOL_SIZE=4000;
    CMsgPool mp(TEST_MSGPOOL_SIZE);
    // Empty pool must be  minimum difficulty
    BOOST_CHECK(msgpool.GetAdmissionDifficulty() == MIN_FORWARD_MSG_DIFFICULTY);

    try
    {
    mp.add(MsgRefCopy(msg1));
    BOOST_FAIL("Expected exception because message has bad nonce");
    }
    catch(CMsgPoolException &e)
    {
    }
    msg1.SetDifficulty(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    uint256 d = msg1.GetDifficulty();
    printf("%s\n", d.GetHex().c_str());
    msg1.Mine();
    try
    {
    mp.add(MsgRefCopy(msg1));
    BOOST_FAIL("Expected exception because message difficulty is too low");
    }
    catch(CMsgPoolException &e)
    {
    }

    msg1.SetDifficulty(msgpool.GetAdmissionDifficulty());
    msg1.Mine();

    BOOST_CHECK(mp.GetLocalDifficulty() == MIN_LOCAL_MSG_DIFFICULTY); // empty pool difficulty
    BOOST_CHECK(mp.GetAdmissionDifficulty() == MIN_FORWARD_MSG_DIFFICULTY); // empty pool difficulty
    
    auto tmp = mp.find(msg1.GetHash());  // test nonexistent message
    BOOST_CHECK(tmp == nullmsgref);
        
    mp.add(MsgRefCopy(msg1));  // Should not throw an exception since the difficulty is correct and we mined it.
    tmp = mp.find(msg1.GetHash());
    BOOST_CHECK(tmp != nullmsgref);  // add should have worked
    
    BOOST_CHECK(mp.Size() == msg1.RamSize());
    // non-full pool must be minimum difficulty
    BOOST_CHECK(mp.GetAdmissionDifficulty() == MIN_FORWARD_MSG_DIFFICULTY);
    BOOST_CHECK(mp.GetLocalDifficulty() == MIN_LOCAL_MSG_DIFFICULTY);

    // Add a lot of messages and validate msgpool characteristics

    uint256 oldDiff = mp.GetAdmissionDifficulty();
    for(int count=0;count<100;count++)
    {
        CMsg m(" message12345678 " + std::to_string(count));
        CMsg m1(" message87654321 " + std::to_string(count));
        m.data[0] = count;
        m1.data[0] = count;
        auto diff = mp.GetAdmissionDifficulty();
        BOOST_CHECK(!(oldDiff < diff));  // difficulty must be getting harder since no messages time expired

        m.SetDifficultyHarderThan(mp.GetAdmissionDifficulty());
        BOOST_CHECK(!(mp.GetAdmissionDifficulty() > mp.GetLocalDifficulty()));
        BOOST_CHECK(!(m.GetDifficulty() > mp.GetAdmissionDifficulty()));
        m.Mine();
        // mp._DbgDump();
        mp.add(MsgRefCopy(m));

        m1.SetDifficultyHarderThan(mp.GetAdmissionDifficulty());
        m1.Mine();
        mp.add(MsgRefCopy(m1));
        
        oldDiff = diff;
        //printf("%d: %s\n", count, diff.GetHex().c_str());
        BOOST_CHECK(mp.Size() <= TEST_MSGPOOL_SIZE);

        printf("Messages matching 2 bytes: %c:\n", count);
        std::vector<unsigned char> srch = {(unsigned char) count, 'm' };
        auto findings = mp.find(srch);
        int qty=0;
        for (auto f : findings)
        {
            printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            if (f->data[0] != count) break;
            qty++;
        }
        BOOST_CHECK(qty == 2);

        printf("Messages matching 4 bytes: %c:\n", count);
        srch = {(unsigned char) count, 'm', 'e', 's' };
        findings = mp.find(srch);
        qty=0;
        for (auto f : findings)
        {
            printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            if (f->data[0] != count) break;
            qty++;
        }
        BOOST_CHECK(qty == 2);

        printf("Messages matching 8 bytes: %c:\n", count);
        srch = {(unsigned char) count, 'm', 'e', 's', 's', 'a', 'g', 'e' };
        findings = mp.find(srch);
        qty=0;
        for (auto f : findings)
        {
            printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            if (f->data[0] != count) break;
            qty++;
        }
        BOOST_CHECK(qty == 2);

        printf("Messages matching 16 bytes\n");
        srch = {(unsigned char) count, 'm', 'e', 's', 's', 'a', 'g', 'e', '1','2','3','4','5','6','7','8' };
        findings = mp.find(srch);
        qty=0;
        for (auto f : findings)
        {
            printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            if (f->data[0] != count) break;
            qty++;
        }
        BOOST_CHECK(qty == 1);

        printf("Messages matching 16 bytes\n");
        srch = {(unsigned char) count, 'm', 'e', 's', 's', 'a', 'g', 'e', '8','7','6','5','4','3','2','1' };
        findings = mp.find(srch);
        qty=0;
        for (auto f : findings)
        {
            printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            if (f->data[0] != count) break;
            qty++;
        }
        BOOST_CHECK(qty == 1);

        
    }

    
}

BOOST_AUTO_TEST_CASE(capd_testhttp)
{
    BOOST_CHECK(1 == 1);

}

BOOST_AUTO_TEST_SUITE_END()
