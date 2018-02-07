// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "bitfield.h"
#include "bitmanip.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "uint256.h"
#include "util.h"

typedef std::vector<unsigned char> valtype;
extern bool CastToBool(const StackItem &vch);

bool VerifyTemplate(const CScript &templat,
    const CScript &constraint,
    const CScript &satisfier,
    unsigned int flags,
    unsigned int maxOps,
    unsigned int maxActualSigops,
    const ScriptImportedState &sis,
    ScriptError *serror,
    ScriptMachineResourceTracker *tracker)
{
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if (!satisfier.IsPushOnly())
    {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    // Note, if the constraint script is allowed to look at the satisfier stack and modify is own output stack,
    // then it could prevent the satisfier from executing certain template codepaths by identifying them based
    // on satisfier data and deliberately failing.

    // If there is any use case for "allowing the constraint script is allowed to look at the satisfier stack",
    // then an option is to disregard any errors in the constraint script execution (i.e. a bad constraint script
    // execution does not render the tx invalid).

    // However, for now, do not let the constraint script see the satisfier data, and so we can insist on push-only
    if (!constraint.IsPushOnly())
    {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    ScriptMachine ssm(flags, sis, maxOps, maxActualSigops);

    // Step 1, evaluate the satisfier to produce a stack
    if (!ssm.Eval(satisfier))
    {
        if (serror)
            *serror = ssm.getError();
        return false;
    }

    // Step 2, evaluate the constraint script
    ScriptMachine sm = ssm;  // Keep the operation counts
    sm.ClearStack();
    //sm.setAltStack(ssm.stack());  // constraint can look at the stack the satisfier will provide
    sm.ClearAltStack();

    if (!sm.Eval(constraint))
    {
        if (serror)
            *serror = sm.getError();
        return false;
    }

    // The data the constraint script leaves for the template goes on the altstack.
    sm.setAltStack(sm.getStack());
    // The data the satisfier script leaves for the template goes on the main stack (just like traditional BTC).
    sm.setStack(ssm.getStack());

    // Step 3, evaluate the template
    if (!sm.Eval(templat))
    {
        if (serror)
            *serror = sm.getError();
        return false;
    }

    if (tracker)
    {
        auto smStats = sm.getStats();
        tracker->update(smStats);
    }

    const Stack &smStack = sm.getStack();
    if (smStack.size() > 1)
        return set_error(serror, SCRIPT_ERR_CLEANSTACK);
    if (smStack.size() == 0)
    {
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }
    if (!((bool)smStack.back()))
    {
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }

    return set_success(serror);
}
