// Copyright (c) 2020 G. Andrew Stone

// Counterparty and protocol discovery
#include "arith_uint256.h"
#include "capd.h"
#include "clientversion.h"
#include "dosman.h"
#include "net.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"

#include "hashwrapper.h"
#include "httpserver.h"
#include "rpc/server.h"
#include "utilstrencodings.h"

UniValue CapdMsg2UniValue(CapdMsgRef msg)
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", msg->GetHash().ToString());
    ret.pushKV("created", msg->createTime);
    if (msg->expiration != std::numeric_limits<uint16_t>::max())
        ret.pushKV("expiration", msg->expiration);
    ret.pushKV("difficultyBits", (uint64_t) msg->difficultyBits);
    ret.pushKV("priority", msg->Priority());
    ret.pushKV("initialPriority", msg->InitialPriority());
    ret.pushKV("difficulty", msg->GetDifficulty().ToString());
    ret.pushKV("nonce", GetHex(msg->nonce));
    ret.pushKV("size", msg->RamSize());
    ret.pushKV("data", GetHex(msg->data));

    return ret;
}

UniValue capdrpc(const UniValue &params, bool fHelp)
{
    if (fHelp)
        throw std::runtime_error("capd\n"
                            "\nCAPD RPC calls.\n"
                            "\nResult\n"
                            "various\n"
                            "\nExamples:\n" +
                            HelpExampleCli("capd", "info") + HelpExampleRpc("capd", "info"));

    if ((params.size() == 0)||(params[0].get_str() == "info"))
    {
        UniValue ret(UniValue::VOBJ);
        ret.pushKV("size", msgpool.Size());
        ret.pushKV("count", msgpool.Count());
        ret.pushKV("relayPriority", msgpool.GetRelayPriority());
        ret.pushKV("minPriority", msgpool.GetLocalPriority());
        return ret;
    }

    std::string cmd = params[0].get_str();
    if (cmd == "get")
    {
        if (params.size() != 2)
        {
            throw std::runtime_error("Incorrect number of parameters, missing hash");
        }
        uint256 hash(uint256S(params[1].get_str()));
        CapdMsgRef msg  = msgpool.find(hash);
        if (msg == nullptr)
        {
            throw std::runtime_error("no such message");
        }
        UniValue ret = CapdMsg2UniValue(msg);
        return ret;
    }
    if (cmd == "list")
    {
        UniValue ret(UniValue::VARR);
        msgpool.visit([&ret](CapdMsgRef msg)->bool { ret.push_back(msg->GetHash().GetHex()); return true; });
        return ret;
    }
    throw std::runtime_error("unknown subcommand");
}


/* clang-format off */
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "network",            "capd",                    &capdrpc,               true  }
};
/* clang-format on */

void RegisterCapdRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}
