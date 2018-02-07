#include "chainparams.h"
#include "consensus/merkle.h"
#include "core_io.h"
#include "init.h"
#include "unlimited.h"
#include "versionbits.h" // bip135 added

#include "rpc/server.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <stdexcept>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

extern UniValue token(const UniValue &params, bool fHelp);
UniValue genesis(const UniValue &params, bool fHelp);

/* clang-format off */
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "genesis",                &genesis,                true  },
    { "wallet",             "token",                  &token,                  true  }
};
/* clang-format on */

void RegisterNextChainRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}


static CBlock CreateGenesisBlock(const char *genesisText,
    const CScript &genesisOutputScript,
    uint32_t nTime,
    uint32_t nNonce,
    uint32_t nBits,
    const CAmount &genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << ((int)0) << CScriptNum(7227)
                                       << std::vector<unsigned char>((const unsigned char *)genesisText,
                                              (const unsigned char *)genesisText + strlen(genesisText));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.vtx.push_back(MakeTransactionRef(txNew));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.nVersion = CBlock::CURRENT_VERSION;
    return genesis;
}

UniValue genesis(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw std::runtime_error("genesis\n"
                                 "\ncreate a genesis block"
                                 "  chainName (string) what chain parameters\n"
                                 "  minerComment (string) miner comment\n"
                                 "  difficulty (int) genesis difficulty in nBits format\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("genesis", "") + HelpExampleRpc("genesis", ""));

    std::string chainName = params[0].getValStr();
    std::string genesisComment = params[1].getValStr();
    std::string genesisDiffs = params[2].getValStr();
    int genesisDiff = boost::lexical_cast<int>(genesisDiffs);
    const CChainParams &chp = Params(chainName);

    const CScript genesisOutputScript = CScript() << OP_1;
    // CAmount genesisReward(5000000000);
    CAmount genesisReward(0);
    CBlock block =
        CreateGenesisBlock(genesisComment.c_str(), genesisOutputScript, GetTime(), 0, genesisDiff, genesisReward);

    CBlock *pblock = &block;
    const Consensus::Params &conp = chp.GetConsensus();

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(genesisDiff, &fNegative, &fOverflow);
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(conp.powLimit))
        throw std::runtime_error("Invalid nBits difficulty");

    while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, conp))
    {
        ++pblock->nNonce;
        if (ShutdownRequested())
            throw std::runtime_error("aborted");
        if ((pblock->nNonce & 0xfff) == 0)
        {
            LOGA("GENESIS nonce: ", pblock->nNonce);
        }
    }

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << block;
    std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());

    std::ostringstream logs;
    logs << "GENESIS Block: Time: " << pblock->nTime << " Nonce: " << pblock->nNonce << " Bits: " << pblock->nBits
         << " Version: " << pblock->nVersion << " Reward: " << genesisReward << "extraNonce: " << 7227
         << " Comment: " << genesisComment << " Script: " << FormatScript(genesisOutputScript)
         << " Hash: " << pblock->GetHash().GetHex() << " Hex: " << strHex << "\n";
    LOGA(logs.str().c_str());

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pblock->nTime);
    ret.pushKV("nonce", (uint64_t)pblock->nNonce);
    ret.pushKV("bits", (uint64_t)pblock->nBits);
    ret.pushKV("version", pblock->nVersion);
    ret.pushKV("reward", genesisReward);
    ret.pushKV("extraNonce", 7227);
    ret.pushKV("comment", genesisComment);
    ret.pushKV("script", FormatScript(genesisOutputScript));
    ret.pushKV("hash", pblock->GetHash().GetHex());
    ret.pushKV("hex", strHex);
    return ret;
}
