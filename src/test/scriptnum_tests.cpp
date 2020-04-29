// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/script.h"
#include "script/bignum.h"
#include "script/interpreter.h"
#include "scriptnum10.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <limits.h>
#include <stdint.h>

BOOST_FIXTURE_TEST_SUITE(scriptnum_tests, BasicTestingSetup)

/** A selection of numbers that do not trigger int64_t overflow
 *  when added/subtracted. */
static const int64_t values[] = {0, 1, -2, 127, 128, -255, 256, (1LL << 15) - 1, -(1LL << 16), (1LL << 24) - 1,
    (1LL << 31), 1 - (1LL << 32), 1LL << 40};

static const int64_t offsets[] = {1, 0x79, 0x80, 0x81, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x10000};

static bool verify(const CScriptNum10 &bignum, const CScriptNum &scriptnum)
{
    return bignum.getvch() == scriptnum.getvch() && bignum.getint() == scriptnum.getint();
}

static void CheckCreateVch(const int64_t &num)
{
    CScriptNum10 bignum(num);
    CScriptNum scriptnum(num);
    BOOST_CHECK(verify(bignum, scriptnum));

    std::vector<unsigned char> vch = bignum.getvch();

    CScriptNum10 bignum2(bignum.getvch(), false);
    vch = scriptnum.getvch();
    CScriptNum scriptnum2(scriptnum.getvch(), false);
    BOOST_CHECK(verify(bignum2, scriptnum2));

    CScriptNum10 bignum3(scriptnum2.getvch(), false);
    CScriptNum scriptnum3(bignum2.getvch(), false);
    BOOST_CHECK(verify(bignum3, scriptnum3));
}

static void CheckCreateInt(const int64_t &num)
{
    CScriptNum10 bignum(num);
    CScriptNum scriptnum(num);
    BOOST_CHECK(verify(bignum, scriptnum));
    BOOST_CHECK(verify(CScriptNum10(bignum.getint()), CScriptNum(scriptnum.getint())));
    BOOST_CHECK(verify(CScriptNum10(scriptnum.getint()), CScriptNum(bignum.getint())));
    BOOST_CHECK(verify(
        CScriptNum10(CScriptNum10(scriptnum.getint()).getint()), CScriptNum(CScriptNum(bignum.getint()).getint())));
}


static void CheckAdd(const int64_t &num1, const int64_t &num2)
{
    const CScriptNum10 bignum1(num1);
    const CScriptNum10 bignum2(num2);
    const CScriptNum scriptnum1(num1);
    const CScriptNum scriptnum2(num2);
    CScriptNum10 bignum3(num1);
    CScriptNum10 bignum4(num1);
    CScriptNum scriptnum3(num1);
    CScriptNum scriptnum4(num1);

    // int64_t overflow is undefined.
    bool invalid = (((num2 > 0) && (num1 > (std::numeric_limits<int64_t>::max() - num2))) ||
                    ((num2 < 0) && (num1 < (std::numeric_limits<int64_t>::min() - num2))));
    if (!invalid)
    {
        BOOST_CHECK(verify(bignum1 + bignum2, scriptnum1 + scriptnum2));
        BOOST_CHECK(verify(bignum1 + bignum2, scriptnum1 + num2));
        BOOST_CHECK(verify(bignum1 + bignum2, scriptnum2 + num1));
    }
}

static void CheckNegate(const int64_t &num)
{
    const CScriptNum10 bignum(num);
    const CScriptNum scriptnum(num);

    // -INT64_MIN is undefined
    if (num != std::numeric_limits<int64_t>::min())
        BOOST_CHECK(verify(-bignum, -scriptnum));
}

static void CheckSubtract(const int64_t &num1, const int64_t &num2)
{
    const CScriptNum10 bignum1(num1);
    const CScriptNum10 bignum2(num2);
    const CScriptNum scriptnum1(num1);
    const CScriptNum scriptnum2(num2);
    bool invalid = false;

    // int64_t overflow is undefined.
    invalid = ((num2 > 0 && num1 < std::numeric_limits<int64_t>::min() + num2) ||
               (num2 < 0 && num1 > std::numeric_limits<int64_t>::max() + num2));
    if (!invalid)
    {
        BOOST_CHECK(verify(bignum1 - bignum2, scriptnum1 - scriptnum2));
        BOOST_CHECK(verify(bignum1 - bignum2, scriptnum1 - num2));
    }

    invalid = ((num1 > 0 && num2 < std::numeric_limits<int64_t>::min() + num1) ||
               (num1 < 0 && num2 > std::numeric_limits<int64_t>::max() + num1));
    if (!invalid)
    {
        BOOST_CHECK(verify(bignum2 - bignum1, scriptnum2 - scriptnum1));
        BOOST_CHECK(verify(bignum2 - bignum1, scriptnum2 - num1));
    }
}

static void CheckCompare(const int64_t &num1, const int64_t &num2)
{
    const CScriptNum10 bignum1(num1);
    const CScriptNum10 bignum2(num2);
    const CScriptNum scriptnum1(num1);
    const CScriptNum scriptnum2(num2);

    BOOST_CHECK((bignum1 == bignum1) == (scriptnum1 == scriptnum1));
    BOOST_CHECK((bignum1 != bignum1) == (scriptnum1 != scriptnum1));
    BOOST_CHECK((bignum1 < bignum1) == (scriptnum1 < scriptnum1));
    BOOST_CHECK((bignum1 > bignum1) == (scriptnum1 > scriptnum1));
    BOOST_CHECK((bignum1 >= bignum1) == (scriptnum1 >= scriptnum1));
    BOOST_CHECK((bignum1 <= bignum1) == (scriptnum1 <= scriptnum1));

    BOOST_CHECK((bignum1 == bignum1) == (scriptnum1 == num1));
    BOOST_CHECK((bignum1 != bignum1) == (scriptnum1 != num1));
    BOOST_CHECK((bignum1 < bignum1) == (scriptnum1 < num1));
    BOOST_CHECK((bignum1 > bignum1) == (scriptnum1 > num1));
    BOOST_CHECK((bignum1 >= bignum1) == (scriptnum1 >= num1));
    BOOST_CHECK((bignum1 <= bignum1) == (scriptnum1 <= num1));

    BOOST_CHECK((bignum1 == bignum2) == (scriptnum1 == scriptnum2));
    BOOST_CHECK((bignum1 != bignum2) == (scriptnum1 != scriptnum2));
    BOOST_CHECK((bignum1 < bignum2) == (scriptnum1 < scriptnum2));
    BOOST_CHECK((bignum1 > bignum2) == (scriptnum1 > scriptnum2));
    BOOST_CHECK((bignum1 >= bignum2) == (scriptnum1 >= scriptnum2));
    BOOST_CHECK((bignum1 <= bignum2) == (scriptnum1 <= scriptnum2));

    BOOST_CHECK((bignum1 == bignum2) == (scriptnum1 == num2));
    BOOST_CHECK((bignum1 != bignum2) == (scriptnum1 != num2));
    BOOST_CHECK((bignum1 < bignum2) == (scriptnum1 < num2));
    BOOST_CHECK((bignum1 > bignum2) == (scriptnum1 > num2));
    BOOST_CHECK((bignum1 >= bignum2) == (scriptnum1 >= num2));
    BOOST_CHECK((bignum1 <= bignum2) == (scriptnum1 <= num2));
}

static void RunCreate(const int64_t &num)
{
    CheckCreateInt(num);
    CScriptNum scriptnum(num);
    if (scriptnum.getvch().size() <= CScriptNum::MAXIMUM_ELEMENT_SIZE)
    {
        CheckCreateVch(num);
    }
    else
    {
        BOOST_CHECK_THROW(CheckCreateVch(num), scriptnum10_error);
    }
}

static void RunOperators(const int64_t &num1, const int64_t &num2)
{
    CheckAdd(num1, num2);
    CheckSubtract(num1, num2);
    CheckNegate(num1);
    CheckCompare(num1, num2);
}

BOOST_AUTO_TEST_CASE(creation)
{
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    {
        for (size_t j = 0; j < sizeof(offsets) / sizeof(offsets[0]); ++j)
        {
            RunCreate(values[i]);
            RunCreate(values[i] + offsets[j]);
            RunCreate(values[i] - offsets[j]);
        }
    }
}

BOOST_AUTO_TEST_CASE(operators)
{
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    {
        for (size_t j = 0; j < sizeof(offsets) / sizeof(offsets[0]); ++j)
        {
            RunOperators(values[i], values[i]);
            RunOperators(values[i], -values[i]);
            RunOperators(values[i], values[j]);
            RunOperators(values[i], -values[j]);
            RunOperators(values[i] + values[j], values[j]);
            RunOperators(values[i] + values[j], -values[j]);
            RunOperators(values[i] - values[j], values[j]);
            RunOperators(values[i] - values[j], -values[j]);
            RunOperators(values[i] + values[j], values[i] + values[j]);
            RunOperators(values[i] + values[j], values[i] - values[j]);
            RunOperators(values[i] - values[j], values[i] + values[j]);
            RunOperators(values[i] - values[j], values[i] - values[j]);
        }
    }
}

static void CheckMinimalyEncode(std::vector<uint8_t> data, const std::vector<uint8_t> &expected)
{
    bool alreadyEncoded = CScriptNum::IsMinimallyEncoded(data, data.size());
    bool hasEncoded = CScriptNum::MinimallyEncode(data);
    BOOST_CHECK_EQUAL(hasEncoded, !alreadyEncoded);
    BOOST_CHECK(data == expected);
}

BOOST_AUTO_TEST_CASE(minimize_encoding_test)
{
    CheckMinimalyEncode({}, {});

    // Check that positive and negative zeros encode to nothing.
    std::vector<uint8_t> zero, negZero;
    for (size_t i = 0; i < MAX_SCRIPT_ELEMENT_SIZE; i++)
    {
        zero.push_back(0x00);
        CheckMinimalyEncode(zero, {});

        negZero.push_back(0x80);
        CheckMinimalyEncode(negZero, {});

        // prepare for next round.
        negZero[negZero.size() - 1] = 0x00;
    }

    // Keep one leading zero when sign bit is used.
    std::vector<uint8_t> n{0x80, 0x00}, negn{0x80, 0x80};
    std::vector<uint8_t> npadded = n, negnpadded = negn;
    for (size_t i = 0; i < MAX_SCRIPT_ELEMENT_SIZE; i++)
    {
        CheckMinimalyEncode(npadded, n);
        npadded.push_back(0x00);

        CheckMinimalyEncode(negnpadded, negn);
        negnpadded[negnpadded.size() - 1] = 0x00;
        negnpadded.push_back(0x80);
    }

    // Mege leading byte when sign bit isn't used.
    std::vector<uint8_t> k{0x7f}, negk{0xff};
    std::vector<uint8_t> kpadded = k, negkpadded = negk;
    for (size_t i = 0; i < MAX_SCRIPT_ELEMENT_SIZE; i++)
    {
        CheckMinimalyEncode(kpadded, k);
        kpadded.push_back(0x00);

        CheckMinimalyEncode(negkpadded, negk);
        negkpadded[negkpadded.size() - 1] &= 0x7f;
        negkpadded.push_back(0x80);
    }
}

BOOST_AUTO_TEST_CASE(bignum_test)
{
    BigNum m1;

    m1 = BigNum(100) * 10_BN;
    BOOST_CHECK(m1 == 1000_BN);

    m1 = BigNum(100) * 0x10_BN;
    BOOST_CHECK(m1 == 1600_BN);

    m1 = BigNum(12345678910111213) * 1234567891011121314151617181920_BN;
    BOOST_CHECK(m1 == 15241578775156478982436124619934121108852868960_BN);

    // check multiplication and constructor equivalence
    BOOST_CHECK(m1 * BigNum(12345) == m1 * 12345_BN);
    BOOST_CHECK(m1 * BigNum(-12345) == m1 * -12345_BN);

    BOOST_CHECK(m1 * 3_BN == m1 + m1 + m1);
    BOOST_CHECK(m1 * 3_BN - m1 == m1 + m1);

    BigNum biggest =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_BN;
    // BOOST_CHECK_EXCEPTION(biggest + 1_BN, OutOfBounds, [](auto &e) -> bool { return strcmp(e.what(), "Numerical upper
    // bound exceeded")==0; });

    // BigNum smallest = (-biggest) - 1_BN;
    // printf("%s\n", smallest.str().c_str());
    // BOOST_CHECK_EXCEPTION(smallest - 1_BN, OutOfBounds, [](auto &e) -> bool { return strcmp(e.what(), "Numerical
    // lower bound exceeded")==0; });

    // Check truncated division "modulo"
    BOOST_CHECK((1234_BN).tdiv(123) == 4_BN);
    BOOST_CHECK((-1234_BN).tdiv(123) == -4_BN);

    unsigned char buf[520];
    memset(buf, 0xff, 520);
    VchType buf2;

    BigNum b2;
    auto b1 = 1000_BN;
    b1.serialize(buf, 2);
    BOOST_CHECK(buf[0] == 232); // Check LE
    BOOST_CHECK(buf[1] == 3);
    BOOST_CHECK(buf[2] == 0); // Check sign
    BOOST_CHECK(buf[3] == 0xff); // Check untouched

    buf2 = b1.serialize(2);
    BOOST_CHECK(buf2.size() == 3);
    BOOST_CHECK(buf2[0] == 232); // Check LE
    BOOST_CHECK(buf2[1] == 3);
    BOOST_CHECK(buf2[2] == 0); // Check sign
    buf2 = b1.serialize(3);
    BOOST_CHECK(buf2.size() == 4);
    BOOST_CHECK(buf2[0] == 232); // Check LE
    BOOST_CHECK(buf2[1] == 3);
    BOOST_CHECK(buf2[2] == 0); // Check zero-extend
    BOOST_CHECK(buf2[3] == 0); // Check sign

    b2.deserialize(buf, 3);
    BOOST_CHECK(b1 == b2);

    b1 = -2000_BN;
    BOOST_CHECK(b1.serialize(buf, 2) == 3);
    BOOST_CHECK(buf[0] == 208); // Check LE
    BOOST_CHECK(buf[1] == 7);
    BOOST_CHECK(buf[2] == 0x80); // Check sign
    BOOST_CHECK(buf[3] == 0xff); // Check untouched
    b2.deserialize(buf, 3);
    BOOST_CHECK(b1 == b2);

    buf2 = b1.serialize(2);
    BOOST_CHECK(buf2.size() == 3);
    BOOST_CHECK(buf2[0] == 208); // Check LE
    BOOST_CHECK(buf2[1] == 7);
    BOOST_CHECK(buf2[2] == 0x80); // Check sign
    buf2 = b1.serialize(3);
    BOOST_CHECK(buf2.size() == 4);
    BOOST_CHECK(buf2[0] == 208); // Check LE
    BOOST_CHECK(buf2[1] == 7);
    BOOST_CHECK(buf2[2] == 0); // Check zero-extend
    BOOST_CHECK(buf2[3] == 0x80); // Check sign

    b1.serialize(buf, 4);
    BOOST_CHECK(buf[0] == 208); // Check LE
    BOOST_CHECK(buf[1] == 7);
    BOOST_CHECK(buf[2] == 0); // Check pad
    BOOST_CHECK(buf[3] == 0);
    BOOST_CHECK(buf[4] == 0x80); // Check sign
    BOOST_CHECK(buf[5] == 0xff); // Check untouched
    b2.deserialize(buf, 5);
    BOOST_CHECK(b1 == b2);

    std::vector<unsigned char> vec = CScriptNum::serialize(1000);
    b2 = 0_BN;
    b2.deserialize(&vec[0], vec.size());
    BOOST_CHECK(b2 == 1000_BN);

    vec = CScriptNum::serialize(-1234);
    b2 = 0_BN;
    b2.deserialize(&vec[0], vec.size());
    BOOST_CHECK(b2 == -1234_BN);

    BOOST_CHECK(biggest.serialize(buf, 10) == -513); // Check correct requested size error
}

std::vector<unsigned char> bns(long int i, size_t pad = 8) { return BigNum(i).serialize(pad); }
void testScript(const CScript &s, bool expectedRet, bool expectedStackTF, ScriptError expectedError)
{
    BaseSignatureChecker sigChecker;
    ScriptMachine sm(0, sigChecker, 0xffffffff, 0xffffffff);
    bool ret = sm.Eval(s);
    BOOST_CHECK(ret == expectedRet);
    if (expectedRet)
    {
        BOOST_CHECK(sm.getStack().size() == 1);
        BOOST_CHECK(((bool)sm.getStack()[0]) == expectedStackTF);
    }
    else
    {
        BOOST_CHECK_MESSAGE(sm.getError() == expectedError, "got: " << ScriptErrorString(sm.getError()) << " ("
                                                                    << sm.getError() << ")");
    }
}

void testScript(const CScript &s, bool expectedStackTF) { testScript(s, true, expectedStackTF, SCRIPT_ERR_OK); }
void testScript(const CScript &s, ScriptError expectedError) { testScript(s, false, false, expectedError); }
BOOST_AUTO_TEST_CASE(bignumscript_test)
{
    CScript s;
    // Should wrap due to mod
    testScript(CScript() << 0x1000 << OP_SETBMD << bns(0xfff) << OP_BIN2BIGNUM << OP_1 << OP_ADD, false);
    // Should not wrap
    testScript(CScript() << 0x1000 << OP_SETBMD << bns(0xffe) << OP_BIN2BIGNUM << OP_1 << OP_ADD, true);

    // Check equality
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << bns(0xffeff) << OP_BIN2BIGNUM << OP_EQUAL, true);

    testScript(CScript() << bns(0xffeff) << bns(0xefeff) << OP_BIN2BIGNUM << OP_EQUAL, false);

    testScript(
        CScript() << bns(0xffeff) << OP_BIN2BIGNUM << OP_4 << OP_RSHIFT << bns(0xffef) << OP_BIN2BIGNUM << OP_EQUAL,
        true);
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << bns(4) << OP_BIN2BIGNUM << OP_RSHIFT << bns(0xffef)
                         << OP_BIN2BIGNUM << OP_EQUAL,
        true);

    testScript(
        CScript() << bns(0xffeff) << OP_BIN2BIGNUM << OP_4 << OP_LSHIFT << bns(0xffeff0) << OP_BIN2BIGNUM << OP_EQUAL,
        true);
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << bns(4) << OP_BIN2BIGNUM << OP_LSHIFT << bns(0xffeff0)
                         << OP_BIN2BIGNUM << OP_EQUAL,
        true);

    // Can't shift by negative numbers
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << -20 << OP_RSHIFT, SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << bns(-20) << OP_BIN2BIGNUM << OP_LSHIFT,
        SCRIPT_ERR_BAD_OPERATION_ON_TYPE);

    // Shift too big
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << 10000 << OP_LSHIFT, SCRIPT_ERR_INVALID_NUMBER_RANGE);
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << 10000 << OP_BIN2BIGNUM << OP_LSHIFT,
        SCRIPT_ERR_INVALID_NUMBER_RANGE);

    // Big right shift becomes 0
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << 10000 << OP_BIN2BIGNUM << OP_RSHIFT, false);
    testScript(CScript() << bns(0xffeff) << OP_BIN2BIGNUM << 10000 << OP_BIN2BIGNUM << OP_RSHIFT, false);

    // multiply only enabled for bignum
    testScript(CScript() << 10 << 20 << OP_MUL, SCRIPT_ERR_DISABLED_OPCODE);
    // Try 1 bignum arg
    testScript(CScript() << 10 << OP_BIN2BIGNUM << 20 << OP_MUL << 1 << OP_NUM2BIN << 200 << OP_EQUAL, true);
    testScript(CScript() << 10 << 20 << OP_BIN2BIGNUM << OP_MUL << 200 << OP_BIN2BIGNUM << OP_EQUAL, true);
    // Try negative
    testScript(CScript() << 10 << -20 << OP_BIN2BIGNUM << OP_MUL << -200 << OP_BIN2BIGNUM << OP_EQUAL, true);

    s = CScript() << (0x100000000000000000000000000000000_BN).serialize(256 / 8) << OP_SETBMD
                  << (0x123456789abcdef_BN).serialize(256 / 8) << OP_BIN2BIGNUM
                  << (0xfedcba9876543210_BN).serialize(256 / 8) << OP_BIN2BIGNUM << OP_MUL
                  << (1505644448203263502622459810266844400_BN).serialize(256 / 8) << OP_BIN2BIGNUM << OP_EQUAL;
    testScript(s, true);

    // Test mul with BMD modular operation
    testScript(CScript() << (0x100000000000000000000000000000000_BN).serialize(256 / 8) << OP_SETBMD
                         << (0x123456789abcdef_BN).serialize(256 / 8) << OP_BIN2BIGNUM
                         << (0xfedcba9876543210_BN).serialize(256 / 8) << OP_BIN2BIGNUM
                         << (0x123456789a_BN).serialize(256 / 8) << OP_SETBMD << OP_MUL << bns(46379439580)
                         << OP_BIN2BIGNUM << OP_EQUAL,
        true);

    // This is the same as prior because MOD kind-of-distributes through *, (A*B)%C == ((A%C)*(B%C))%C
    testScript(CScript() << (0x123456789a_BN).serialize(256 / 8) << OP_SETBMD
                         << (0x123456789abcdef_BN).serialize(256 / 8) << OP_BIN2BIGNUM
                         << (0xfedcba9876543210_BN).serialize(256 / 8) << OP_BIN2BIGNUM << OP_MUL << bns(46379439580)
                         << OP_BIN2BIGNUM << OP_EQUAL,
        true);

    // Try negative mul with BMD mod
    testScript(CScript() << (0x123456789a_BN).serialize(256 / 8) << OP_SETBMD
                         << (-0x123456789abcdef_BN).serialize(256 / 8) << OP_BIN2BIGNUM
                         << (0xfedcba9876543210_BN).serialize(256 / 8) << OP_BIN2BIGNUM << OP_MUL << bns(-46379439580)
                         << OP_BIN2BIGNUM << OP_EQUAL,
        true);

    CScript() << (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_BN).serialize(256 / 8)
              << OP_SETBMD;
}


BOOST_AUTO_TEST_SUITE_END()
