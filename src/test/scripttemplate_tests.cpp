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
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    CScript templat = CScript() << OP_FROMALTSTACK << OP_SUB;
    CScript templat2 = CScript() << OP_FROMALTSTACK << OP_ADD;
    CScript constraint = CScript() << OP_9;
    CScript satisfier = CScript() << OP_10;

    CScript badSatisfier = CScript() << OP_9;
    CScript badConstraint = CScript() << OP_10;
    bool ret;

    ScriptError error;
    ScriptMachineResourceTracker tracker;
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


BOOST_AUTO_TEST_SUITE_END()
