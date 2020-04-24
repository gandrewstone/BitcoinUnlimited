#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sighashtype.h"
#include "script/sign.h"
#include "test/scriptflags.h"
#include "test/test_bitcoin.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"

#include <fstream>
#include <stdint.h>
#include <string>
#include <vector>
#include <boost/test/unit_test.hpp>
#include <univalue.h>

BOOST_FIXTURE_TEST_SUITE(scripttemplate_tests, BasicTestingSetup)

class AlwaysGoodSignatureChecker : public BaseSignatureChecker
{
protected:
    unsigned int nFlags = SCRIPT_ENABLE_SIGHASH_FORKID;

public:
    //! Verifies a signature given the pubkey, signature and sighash
    virtual bool VerifySignature(const std::vector<uint8_t> &vchSig,
        const CPubKey &vchPubKey,
        const uint256 &sighash) const
    {
        if (vchSig.size() > 0)
            return true;
        return false;
    }

    //! Verifies a signature given the pubkey, signature, script, and transaction (member var)
    virtual bool CheckSig(const std::vector<unsigned char> &scriptSig,
        const std::vector<unsigned char> &vchPubKey,
        const CScript &scriptCode) const
    {
        if (scriptSig.size() > 0)
            return true;
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const { return true; }
    virtual bool CheckSequence(const CScriptNum &nSequence) const { return true; }
    virtual ~AlwaysGoodSignatureChecker() {}
};

uint256 hash256(const CScript& script)
{
    return Hash(script.begin(), script.end());
}

std::vector<unsigned char> vch(const CScript& script)
{
    return std::vector<unsigned char>(script.begin(), script.end());
}


BOOST_AUTO_TEST_CASE(verifytemplate)
{
    AlwaysGoodSignatureChecker ck;
    ScriptError error;
    ScriptMachineResourceTracker tracker;
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    CScript templat = CScript() << OP_FROMALTSTACK << OP_SUB;
    CScript templat2 = CScript() << OP_FROMALTSTACK << OP_ADD;
    CScript constraint = CScript() << OP_9;
    CScript satisfier = CScript() << OP_10;

    CScript badSatisfier = CScript() << OP_9;
    CScript badConstraint = CScript() << OP_10;
    bool ret;

    ret = VerifyTemplate(templat, constraint, satisfier, flags, 100, 0, ck, &error, &tracker);
    BOOST_CHECK(ret == true);
    ret = VerifyTemplate(templat, constraint, badSatisfier, flags, 100, 0, ck, &error, &tracker);
    BOOST_CHECK(!ret);
    ret = VerifyTemplate(templat, badConstraint, satisfier, flags, 100, 0, ck, &error, &tracker);
    BOOST_CHECK(!ret);

    // Now wrap these scripts into scriptSig and scriptPubKeys

    CScript scriptPubKey = (CScript() << hash256(templat) << OP_TEMPLATE) + constraint;
    CScript scriptSig = (CScript() << vch(templat)) + satisfier;

    CScript badScriptSigTemplate = (CScript() << vch(templat2)) + satisfier;

    CScript badScriptPubKey = (CScript() << hash256(templat) << OP_TEMPLATE) + badConstraint;
    CScript badScriptSig = (CScript() << vch(templat)) + badSatisfier;

    ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(ret == true);
    ret = VerifyScript(badScriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);
    ret = VerifyScript(badScriptSigTemplate, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);
    ret = VerifyScript(scriptSig, badScriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);
}

BOOST_AUTO_TEST_CASE(opexec)
{
    AlwaysGoodSignatureChecker ck;
    ScriptError error;
    ScriptMachineResourceTracker tracker;
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    bool ret;

    {
    CScript execed = CScript() << OP_ADD;
    CScript scriptSig = CScript() << vch(execed) << OP_4 << OP_6;
    CScript scriptPubKey = CScript() << OP_2 << OP_1 << OP_EXEC << OP_10 << OP_EQUAL;

    ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(ret);

    ret = VerifyScript(CScript() << vch(execed) << OP_5 << OP_6, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);

    ret = VerifyScript(CScript() << vch(execed) << OP_5, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);

    ret = VerifyScript(CScript() << vch(execed), scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);

    ret = VerifyScript(CScript(), scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);

    ret = VerifyScript(CScript() << OP_FALSE << OP_5 << OP_5, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);
    ret = VerifyScript(CScript() << vch(CScript() << OP_CHECKSIGVERIFY) << OP_5 << OP_5, scriptPubKey, flags, 100, ck, &error, &tracker);
    BOOST_CHECK(!ret);
    }

    // Verify op_exec.md:T.o2 (empty script is valid)
    {
        CScript execed = CScript();
        CScript scriptSig = CScript() << vch(execed);
        CScript scriptPubKey = CScript() << OP_0 << OP_0 << OP_EXEC << OP_1;
        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(ret);
    }

    // Verify op_exec.md:T.L4
    {
        // This script simply pushes the parameters needed for the next op_exec so that the constraint script
        // can be 20 OP_EXEC in a row.
        CScript execed = CScript() << OP_DUP << OP_1 << OP_4;
        CScript scriptSig = CScript() << vch(execed);
        CScript scriptPubKeyOk = CScript() << OP_DUP << OP_1 << OP_4
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_1;
        CScript scriptPubKeyNok = CScript() << OP_DUP << OP_1 << OP_4
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                         << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_1;
        ret = VerifyScript(scriptSig, scriptPubKeyOk, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(ret);

        ret = VerifyScript(scriptSig, scriptPubKeyNok, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_COUNT_EXCEEDED);
    }


    {
        CScript execed = CScript() << OP_1;
        CScript execedFalse = CScript() << OP_0;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_0 << OP_1 << OP_EXEC;
        CScript scriptPubKeyF = CScript() << vch(execedFalse) << OP_0 << OP_1 << OP_EXEC;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(ret);
        // execed script returns OP_O so script should fail because that false is left on the stack
        ret = VerifyScript(scriptSig, scriptPubKeyF, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(!ret);
    }

    {
        CScript execed = CScript();
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_0 << OP_0 << OP_EXEC << OP_TRUE;
        CScript scriptPubKeyRet1 = CScript() << vch(execed) << OP_0 << OP_1 << OP_EXEC << OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(ret);

        // Expecting more returned data than the subscript provides
        ret = VerifyScript(scriptSig, scriptPubKeyRet1, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    {
        CScript execed = CScript() << OP_DUP << OP_0 << OP_0 << OP_EXEC;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_DUP << OP_0 << OP_0 << OP_EXEC;

        // script was expecting 1 param
        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    {
        CScript execed = CScript() << OP_DUP << OP_1 << OP_0 << OP_EXEC;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_DUP << OP_1 << OP_0 << OP_EXEC;

        // test that a recursive script fails
        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_DEPTH_EXCEEDED);
    }

    {
        // This script recursively calls itself the number of times passed as a parameter, and ends by pushing true to the stack.
        CScript execed = CScript() << OP_DUP << OP_IF << OP_1 << OP_SUB << OP_SWAP << OP_TUCK << OP_2 << OP_1 << OP_EXEC << OP_ELSE << OP_1 << OP_ENDIF;
        CScript scriptSig = CScript();
        CScript scriptPubKey2 = CScript() << vch(execed) << OP_DUP << OP_2 << OP_SWAP << OP_2 << OP_1 << OP_EXEC;
        CScript scriptPubKey3 = CScript() << vch(execed) << OP_DUP << OP_3 << OP_SWAP << OP_2 << OP_1 << OP_EXEC;

        // test that the max recursion depth succeeds
        tracker.clear();
        ret = VerifyScript(scriptSig, scriptPubKey2, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(ret);
        // test that 1+max recursion depth fails
        tracker.clear();
        ret = VerifyScript(scriptSig, scriptPubKey3, flags, 100, ck, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_DEPTH_EXCEEDED);

        // test that max operations can be exceeded
        ret = VerifyScript(scriptSig, scriptPubKey2, flags, 25, ck, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_OP_COUNT);
        
    }


}

BOOST_AUTO_TEST_SUITE_END()
