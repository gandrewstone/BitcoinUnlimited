// Copyright (c) 2016-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tgmath.h>

#include "capd.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "test/test_random.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(capd_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(vector_span)
{
    CDataStream ss(SER_DISK, 0);
    std::vector<int> vi(10);

    for (int i = 0; i < 10; i++)
    {
        vi[i] = i + 1000;
    }

    ss << VectorSpan<int>(vi, 1, 3);

    std::vector<int> vo;

    ss >> vo;
    BOOST_CHECK(vo.size() == 3);
    BOOST_CHECK(vo[0] == 1001);
    BOOST_CHECK(vo[1] == 1002);
    BOOST_CHECK(vo[2] == 1003);

    ss.clear();

    // Test count overflow
    ss << VectorSpan<int>(vi, 5, 9);
    ss >> vo;
    BOOST_CHECK(vo.size() == 5);
    BOOST_CHECK(vo[0] == 1005);
    BOOST_CHECK(vo[4] == 1009);

    // Test too big start
    ss << VectorSpan<int>(vi, 12, 5);
    ss >> vo;
    BOOST_CHECK(vo.size() == 0);

    // Test 0 size
    ss << VectorSpan<int>(vi, 1, 0);
    ss >> vo;
    BOOST_CHECK(vo.size() == 0);

    // Test max size
    ss << VectorSpan<int>(vi, 0, 10);
    ss >> vo;
    BOOST_CHECK(vo.size() == 10);
    BOOST_CHECK(vi == vo);
}


BOOST_AUTO_TEST_CASE(capd_msg_test_vectors)
{
    {
        arith_uint256 tmp;
        double val = 1;
        for (int i = 1; i < 10; i++)
        {
            val *= insecure_rand() & 0xffff;

            printf("val = %f\n", val);
            tmp.setdouble(val);
            printf("int256 = %s  double = %f\n", tmp.GetHex().c_str(), tmp.getdouble());
            // precision BOOST_CHECK(val == tmp.getdouble());
        }
    }

    arith_uint256 CONVERSION_ERROR_MASK = ~arith_uint256((1024 * PRIORITY_CONVERSION_FRAC) - 1);

    // check that Priority() and PriorityToDifficulty() are inverse
    {
        {
            arith_uint256 tmp("0123456fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            PriorityType p = Priority(tmp, NOMINAL_MSG_SIZE, 0);
            arith_uint256 tmp1 = aPriorityToDifficultyTarget(p, NOMINAL_MSG_SIZE, 0);
            // printf("%s\n", tmp.GetHex().c_str());
            // printf("%s\n", tmp1.GetHex().c_str());
            BOOST_CHECK((tmp & CONVERSION_ERROR_MASK) == (tmp1 & CONVERSION_ERROR_MASK));
        }

        // check that Priority() increases as difficulty target gets smaller
        {
            arith_uint256 tmp1("0123456fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            PriorityType p1 = Priority(tmp1, NOMINAL_MSG_SIZE, 0);
            arith_uint256 tmp2("0023456fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            PriorityType p2 = Priority(tmp2, NOMINAL_MSG_SIZE, 0);

            BOOST_CHECK(p1 < p2);

            // check that the priority of a bigger message is smaller
            PriorityType p3 = Priority(tmp2, 2 * NOMINAL_MSG_SIZE, 0);
            BOOST_CHECK(p3 < p2);

            // check that the priority of an older message is smaller
            PriorityType p4 = Priority(tmp2, NOMINAL_MSG_SIZE, 20);
            BOOST_CHECK(p4 < p2);
        }


        uint256 tmp;
        for (unsigned int i = 0; i < 100; i++)
        {
            // numbers that are too big overflow, and too small have rounding errors but difficulty will not
            // be either of these extremes anyway.
            int zeros = insecure_rand() % 26 + 2;

            for (unsigned int j = 0; j < tmp.size(); j++)
                if (j > tmp.size() - zeros)
                    *(tmp.begin() + j) = 0;
                else
                    *(tmp.begin() + j) = insecure_rand() & 255;

            auto utmp = UintToArith256(tmp);
            auto priority = Priority(utmp, 2 * NOMINAL_MSG_SIZE, 0);
            auto tmp2 = aPriorityToDifficultyTarget(priority, 2 * NOMINAL_MSG_SIZE, 0);

            // since difficulty target to priority has precision errors, we need to test that the numbers are
            // approximately equal by taking the log and then rounding to a few decimal places.
            // printf("%f %f\n", log(UintToArith256(tmp).getdouble()), log(tmp2.getdouble()));
            BOOST_CHECK(floorf(1000 * log(UintToArith256(tmp).getdouble())) == floorf(1000 * log(tmp2.getdouble())));
            // printf("%f\n", priority);
            // printf("%s\n", tmp.GetHex().c_str());
            // printf("%s\n", tmp2.GetHex().c_str());
        }
    }

    { // Probabilistically check that the default constructor inits everything and that CalcHash is reproducible
        CapdMsg msg1;
        CapdMsg msg2;
        uint256 msghash1 = msg1.CalcHash();
        uint256 msghash2 = msg2.CalcHash();
        BOOST_CHECK(msghash1 == msghash2);
        printf("%s\n", msghash1.ToString().c_str());

        // Check serialization
        CDataStream ss(SER_NETWORK, 0);
        // encode
        ss << msg1;
        // decode
        CapdMsg msg3;
        ss >> msg3;
        BOOST_CHECK_MESSAGE(msg1.CalcHash() == msg3.CalcHash(), "serialization/deserialization issue");
    }

    {
        CapdMsg msg1("this is a test");
        arith_uint256 target =
            UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg1.difficultyBits = target.GetCompact();
        msg1.Solve();
        printf("Soln found: %lu\n", msg1.nonce);

        CapdMsg msg2("shorter");
        msg2.difficultyBits = target.GetCompact();
        msg2.Solve();

        // auto t2 = GetStopwatchMicros();
        CapdMsg msg3("this is a test");
        target = UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg3.difficultyBits = target.GetCompact();
        msg3.Solve();
        // auto t3 = GetStopwatchMicros();
        CapdMsg msg4("this is a test");
        target = UintToArith256(uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg4.difficultyBits = target.GetCompact();
        msg4.Solve();
        // auto t4 = GetStopwatchMicros();
        CapdMsg msg5("this is a test");
        target = UintToArith256(uint256S("000007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        msg5.difficultyBits = target.GetCompact();
        msg5.Solve();
        // Expiration time is essentially the same but msg5 has more work
        BOOST_CHECK(msg5.Priority() > msg4.Priority());
        // auto t5 = GetStopwatchMicros();

        /*
        printf("Priorities: %f %f %f\n%f (time: %lu)\n%f (time: %lu)\n%f (time: %lu)\n", startPri, msg1.Priority(),
        msg2.Priority(),
               msg3.Priority(),
               (t3 - t2),
               msg4.Priority(),
               (t4 - t3),
               msg5.Priority(),
               (t5 - t4)
            );
        */

        // use an old createtime to test lowering priority
        msg5.Solve(GetTime() - (MSG_LIFETIME_SEC + 1) / 2);

        PriorityType p1 = msg5.Priority();
        printf("Time expired message priority: %f\n", p1);

        msg5.Solve(GetTime() - (MSG_LIFETIME_SEC + 1));
        PriorityType p2 = msg5.Priority();
        printf("Time expired message priority: %f\n", p2);

        BOOST_CHECK_MESSAGE(p2 < p1, "Older messages have lower priority");
    }

    if (0)
    {
        CapdMsg msg("this is a test");
        msg.SetDifficulty(UintToArith256(uint256S("00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));
        for (unsigned int i = 0; i < 1000000; i++)
        {
            msg.SetDifficultyHarderThan(msg.GetDifficulty());
            printf("%s\n", msg.GetDifficulty().GetHex().c_str());
        }
    }

    msgpool.clear();
    msgpool.SetMaxSize(2000);
    uint256 diff = msgpool.GetRelayDifficulty();
    BOOST_CHECK(diff == ArithToUint256(MIN_FORWARD_MSG_DIFFICULTY)); // because no messages in the pool
}

BOOST_AUTO_TEST_CASE(capd_pool_test_vectors)
{
    int64_t now = GetTime();
    SetMockTime(now); // Freeze the time at now

    CapdMsg msg1("this is a test");

    const unsigned int TEST_MSGPOOL_SIZE = 4000;
    CapdMsgPool mp(TEST_MSGPOOL_SIZE);
    // Empty pool must be  minimum difficulty
    BOOST_CHECK(msgpool.GetRelayDifficulty() == ArithToUint256(MIN_FORWARD_MSG_DIFFICULTY));

    try
    {
        mp.add(MsgRefCopy(msg1));
        BOOST_FAIL("Expected exception because message has bad nonce");
    }
    catch (CapdMsgPoolException &e)
    {
    }

    msg1.SetDifficulty(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    uint256 d = msg1.GetDifficulty();
    printf("%s\n", d.GetHex().c_str());
    msg1.Solve();
    try
    {
        printf("expecting exception:");
        mp.add(MsgRefCopy(msg1));
        BOOST_FAIL("Expected exception because message difficulty is too low");
    }
    catch (CapdMsgPoolException &e)
    {
    }

    msg1.SetDifficulty(msgpool.GetRelayDifficulty());
    msg1.Solve();

    BOOST_CHECK(mp.GetLocalDifficulty() == ArithToUint256(MIN_LOCAL_MSG_DIFFICULTY)); // empty pool difficulty
    BOOST_CHECK(mp.GetRelayDifficulty() == ArithToUint256(MIN_FORWARD_MSG_DIFFICULTY)); // empty pool difficulty

    auto tmp = mp.find(msg1.GetHash()); // test nonexistent message
    BOOST_CHECK(tmp == nullmsgref);

    mp.add(MsgRefCopy(msg1)); // Should not throw an exception since the difficulty is correct and we mined it.
    tmp = mp.find(msg1.GetHash());
    BOOST_CHECK(tmp != nullmsgref); // add should have worked

    BOOST_CHECK(mp.Size() == msg1.RamSize());
    // non-full pool must be minimum difficulty
    BOOST_CHECK(mp.GetRelayDifficulty() == ArithToUint256(MIN_FORWARD_MSG_DIFFICULTY));
    BOOST_CHECK(mp.GetLocalDifficulty() == ArithToUint256(MIN_LOCAL_MSG_DIFFICULTY));

    // Add a lot of messages and validate msgpool characteristics

    uint256 oldDiff = mp.GetRelayDifficulty();
    for (int count = 0; count < 80; count++)
    {
        unsigned char prefix = count + '!';
        printf("%d: inserting '%c' (%u)\n", count, prefix, (unsigned int)prefix);
        CapdMsg m(" message12345678 " + std::to_string(count));
        m.data[0] = prefix;
        auto diff = mp.GetRelayDifficulty();
        BOOST_CHECK(!(oldDiff < diff)); // difficulty must be getting harder since no messages time expired

        m.SetDifficultyHarderThan(diff);
        BOOST_CHECK(!(mp.GetRelayDifficulty() > mp.GetLocalDifficulty()));
        BOOST_CHECK(!(m.GetDifficulty() > mp.GetRelayDifficulty()));
        m.Solve();
        mp.add(MsgRefCopy(m));
        // mp._DbgDump();

        CapdMsg m1(" message87654321 " + std::to_string(count));
        m1.data[0] = prefix;
        m1.SetDifficultyHarderThan(mp.GetRelayDifficulty());
        m1.Solve();
        mp.add(MsgRefCopy(m1));

        // mp._DbgDump();
        oldDiff = diff;
        // printf("%d: %s\n", count, diff.GetHex().c_str());
        BOOST_CHECK(mp.Size() <= TEST_MSGPOOL_SIZE);

        printf("Messages matching 2 bytes: %c:\n", prefix);
        std::vector<unsigned char> srch = {(unsigned char)prefix, 'm'};
        auto findings = mp.find(srch);
        int qty = 0;
        for (auto f : findings)
        {
            printf("%.*s\n", (int)f->data.size(), &f->data[0]);
            BOOST_CHECK(f->data[0] == prefix);
            qty++;
        }
        BOOST_CHECK(qty == 2);

        // printf("Messages matching 4 bytes: %c:\n", prefix);
        srch = {(unsigned char)prefix, 'm', 'e', 's'};
        findings = mp.find(srch);
        qty = 0;
        for (auto f : findings)
        {
            // printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            BOOST_CHECK(f->data[0] == prefix);
            qty++;
        }
        BOOST_CHECK(qty == 2);

        // printf("Messages matching 8 bytes: %c:\n", prefix);
        srch = {(unsigned char)prefix, 'm', 'e', 's', 's', 'a', 'g', 'e'};
        findings = mp.find(srch);
        qty = 0;
        for (auto f : findings)
        {
            // printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            BOOST_CHECK(f->data[0] == prefix);
            qty++;
        }
        BOOST_CHECK(qty == 2);

        // printf("Messages matching 16 bytes\n");
        srch = {(unsigned char)prefix, 'm', 'e', 's', 's', 'a', 'g', 'e', '1', '2', '3', '4', '5', '6', '7', '8'};
        findings = mp.find(srch);
        qty = 0;
        for (auto f : findings)
        {
            // printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            BOOST_CHECK(f->data[0] == prefix);
            qty++;
        }
        BOOST_CHECK(qty == 1);

        // printf("Messages matching 16 bytes\n");
        srch = {(unsigned char)prefix, 'm', 'e', 's', 's', 'a', 'g', 'e', '8', '7', '6', '5', '4', '3', '2', '1'};
        findings = mp.find(srch);
        qty = 0;
        for (auto f : findings)
        {
            // printf("%.*s\n", (int) f->data.size(), &f->data[0]);
            BOOST_CHECK(f->data[0] == prefix);
            qty++;
        }
        BOOST_CHECK_MESSAGE(qty == 1, strprintf("expected 1 got %d", qty).c_str());
    }

    SetMockTime(now + MSG_LIFETIME_SEC);
    // Every message inserted should have a negative priority at this point
    if (mp.GetRelayPriority() != MIN_RELAY_PRIORITY)
    {
        printf("problem!\n");
    }

    // although other messages have expired, a new message should be easily added
    {
        CapdMsgRef m = std::make_shared<CapdMsg>("zz message12345678 ");

        PriorityType priority = mp.GetRelayPriority();
        m->SetDifficultyHarderThanPriority(priority);
        m->Solve();
        mp.add(m);
        auto findings = mp.find({'z', 'z'});
        BOOST_CHECK(findings.size() == 1);
    }
}


// This test checks the persistence of a high work message, and then ensures that it ages out
BOOST_AUTO_TEST_CASE(capd_pool_test_vectors2)
{
    int64_t now = GetTime();
    SetMockTime(now); // Freeze the time at now

    const unsigned int TEST_MSGPOOL_SIZE = 2000;
    CapdMsgPool mp(TEST_MSGPOOL_SIZE);

    // Insert a high POW message
    CapdMsg msg1("!!this is a test");
    msg1.SetDifficulty(uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    uint256 d = msg1.GetDifficulty();
    printf("%s\n", d.GetHex().c_str());
    msg1.Solve();
    mp.add(MsgRefCopy(msg1));

    // Add a lot of minimum POW messages
    uint256 oldDiff = mp.GetRelayDifficulty();
    for (int count = 0; count < 100; count++)
    {
        unsigned char prefix = count + '!';
        // printf("%d: inserting '%c' (%u)\n", count, prefix, (unsigned int) prefix);
        CapdMsg m(" message12345678 " + std::to_string(count));
        m.data[0] = prefix;
        auto diff = mp.GetRelayDifficulty();
        BOOST_CHECK(!(oldDiff < diff)); // difficulty must be getting harder since no messages time expired

        m.SetDifficultyHarderThan(diff);
        BOOST_CHECK(!(mp.GetRelayDifficulty() > mp.GetLocalDifficulty()));
        BOOST_CHECK(!(m.GetDifficulty() > mp.GetRelayDifficulty()));
        m.Solve();
        mp.add(MsgRefCopy(m));
    }

    // Verify that the high POW message remains
    std::vector<unsigned char> srch = {'!', '!'};
    auto findings = mp.find(srch);
    BOOST_CHECK(findings.size() == 1);

    // Add a lot of minimum POW messages
    for (int count = 0; count < 1000; count++)
    {
        // Move forward to where the high priority message should be aged out
        SetMockTime(now + MSG_LIFETIME_SEC + count);

        CapdMsg m(" message12345678 " + std::to_string(count));
        auto diff = mp.GetRelayDifficulty();
        m.SetDifficultyHarderThan(diff);
        m.Solve();
        mp.add(MsgRefCopy(m));
    }

    // Verify that the high POW message aged out
    findings = mp.find(srch);
    BOOST_CHECK(findings.size() == 0);
}


BOOST_AUTO_TEST_CASE(capd_http) { BOOST_CHECK(1 == 1); }
class CMsgMaker
{
public:
    CDataStream &pkt;

    CMsgMaker(CDataStream &serializedMsg, CNode &node, const char *msgtype) : pkt(serializedMsg)
    {
        pkt << CMessageHeader(node.GetMagic(Params()), msgtype, 0);
    }


    ~CMsgMaker()
    {
        unsigned int nSize = pkt.size() - CMessageHeader::HEADER_SIZE;
        WriteLE32((uint8_t *)&pkt[CMessageHeader::MESSAGE_SIZE_OFFSET], nSize);
    }
};

template <typename Fn>
CDataStream MsgMaker(CNode &node, const char *msgtype, Fn f)
{
    CDataStream pkt(SER_NETWORK, CLIENT_VERSION);
    pkt << CMessageHeader(node.GetMagic(Params()), msgtype, 0);
    f(pkt);
    unsigned int nSize = pkt.size() - CMessageHeader::HEADER_SIZE;
    WriteLE32((uint8_t *)&pkt[CMessageHeader::MESSAGE_SIZE_OFFSET], nSize);
    return pkt;
}


bool HandleCapdMessage(CNode &node, CDataStream &pkt)
{
    CMessageHeader hdr(node.GetMagic(Params()));
    pkt >> hdr;
    auto s = hdr.GetCommand();
    bool result = capdProtocol.HandleCapdMessage(&node, s, pkt, 0);
    return result;
}

BOOST_AUTO_TEST_CASE(capd_p2p)
{
    SOCKET hSocket = INVALID_SOCKET;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0x7f000001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest = "";
    bool fInboundIn = false;

    CNode node1(hSocket, addr, pszDest, fInboundIn);
    CapdNode capdNode1;

    CapdMsg msg1("!!this is a test");
    msg1.SetDifficulty(uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    msg1.Solve();

    {
        CDataStream pkt(SER_NETWORK, CLIENT_VERSION);
        std::vector<uint256> invs;
        invs.push_back(msg1.GetHash());
        pkt << CMessageHeader(node1.GetMagic(Params()), NetMsgType::CAPDINV, 0);
        WriteCompactSize(pkt, CapdProtocol::CAPD_MSG_TYPE);
        pkt << invs;
        unsigned int nSize = pkt.size() - CMessageHeader::HEADER_SIZE;
        WriteLE32((uint8_t *)&pkt[CMessageHeader::MESSAGE_SIZE_OFFSET], nSize);

        // Check cases were capd is not enabled

        CMessageHeader hdr(node1.GetMagic(Params()));
        pkt >> hdr;
        auto s = hdr.GetCommand();
        bool result = capdProtocol.HandleCapdMessage(&node1, s, pkt, 0);
        BOOST_CHECK(result == false);

        node1.isCapdEnabled = true;

        pkt.Rewind(pkt.ReadPos());
        pkt >> hdr;
        s = hdr.GetCommand();
        result = capdProtocol.HandleCapdMessage(&node1, s, pkt, 0);
        BOOST_CHECK(result == false);

        node1.capd = &capdNode1;

        // Check the basic 1 message case
        pkt.Rewind(pkt.ReadPos());
        pkt >> hdr;
        s = hdr.GetCommand();
        result = capdProtocol.HandleCapdMessage(&node1, s, pkt, 0);
        BOOST_CHECK(result == true);

        // Check bad object type
        pkt.clear();
        WriteCompactSize(pkt, CapdProtocol::CAPD_MSG_TYPE + 1);
        pkt << invs;
        result = capdProtocol.HandleCapdMessage(&node1, s, pkt, 0);
        BOOST_CHECK(result == false);
    }

    // too many INV objects
    {
        CDataStream pkt(SER_NETWORK, CLIENT_VERSION);
        pkt << CMessageHeader(node1.GetMagic(Params()), NetMsgType::CAPDINV, 0);
        pkt = MsgMaker(node1, NetMsgType::CAPDINV, [](auto &p) {
            std::vector<uint256> invs;
            for (unsigned int i = 0; i < CAPD_MAX_INV_TO_SEND + 2; i++)
            {
                uint256 h;
                *h.begin() = i; // don't really care what it is
                invs.push_back(h);
            }
            WriteCompactSize(p, CapdProtocol::CAPD_MSG_TYPE);
            p << invs;
        });

        bool result = HandleCapdMessage(node1, pkt);
        BOOST_CHECK(result == false);
    }

    // Inject a message into the pool
    CDataStream pkt(SER_NETWORK, CLIENT_VERSION);
    {
        CMsgMaker m(pkt, node1, NetMsgType::CAPDMSG);
        std::vector<CapdMsg> msgs;
        msgs.push_back(msg1);
        m.pkt << msgs;
    }

    bool result = HandleCapdMessage(node1, pkt);
    BOOST_CHECK(result == true);
    BOOST_CHECK(msgpool.Size() == msg1.RamSize()); // Message was accepted into the pool

    // Request a message from the pool
    pkt = MsgMaker(node1, NetMsgType::CAPDGETMSG, [msg1](auto &p) {
        std::vector<uint256> msgs;
        msgs.push_back(msg1.GetHash());
        p << MIN_RELAY_PRIORITY << msgs;
    });
    result = HandleCapdMessage(node1, pkt);
    BOOST_CHECK(result == true);
    // There should be a message waiting to be sent since we asked for one
    BOOST_CHECK(capdNode1.sendMsgs.size() == 1);

    // Request a nonexistent message from the pool
    pkt = MsgMaker(node1, NetMsgType::CAPDGETMSG, [msg1](auto &p) {
        std::vector<uint256> msgs;
        uint256 h;
        *h.begin() = 5;
        msgs.push_back(h);
        p << MIN_RELAY_PRIORITY << msgs;
    });
    result = HandleCapdMessage(node1, pkt);
    BOOST_CHECK(result == true); // if the message does not exist, drop the request so fn returns true
    // No addtl message should be enqueued
    BOOST_CHECK(capdNode1.sendMsgs.size() == 1);

    // Request too many messages
    pkt = MsgMaker(node1, NetMsgType::CAPDGETMSG, [msg1](auto &p) {
        std::vector<uint256> msgs;
        for (unsigned int i = 0; i < CAPD_MAX_MSG_TO_REQUEST + 1; i++)
        {
            uint256 h;
            *h.begin() = i; // don't really care what it is
            msgs.push_back(h);
        }
        p << MIN_RELAY_PRIORITY << msgs;
    });
    result = HandleCapdMessage(node1, pkt);
    BOOST_CHECK(result == false);

    // Request exact maximum messages
    pkt = MsgMaker(node1, NetMsgType::CAPDGETMSG, [msg1](auto &p) {
        std::vector<uint256> msgs;
        for (unsigned int i = 0; i < CAPD_MAX_MSG_TO_REQUEST; i++)
        {
            uint256 h;
            *h.begin() = i; // don't really care what it is
            msgs.push_back(h);
        }
        p << MIN_RELAY_PRIORITY << msgs;
    });
    result = HandleCapdMessage(node1, pkt);
    BOOST_CHECK(result == true);

    // No addtl message should be enqueued since all these hashes were bogus
    BOOST_CHECK(capdNode1.sendMsgs.size() == 1);
}

BOOST_AUTO_TEST_SUITE_END()
