#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
logging.basicConfig(format='%(asctime)s.%(levelname)s: %(message)s', level=logging.INFO,stream=sys.stdout)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.nodemessages import *
import test_framework.key as key

import cashlib

try:
    import bchscript
except ModuleNotFoundError:
    print("You must create a symlink called bchscript in this directory to a local copy of https://github.com/gandrewstone/bchscript subdirectory bchscript")
    sys.exit(1)

# bchscript.mode(bchscript.BCH_REGTEST)

def waitUntil(fn, timeout):
    while timeout>0:
        if fn(): return True
        time.sleep(.5)
        timeout -= .5
    return False

class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        #initialize_chain(self.options.tmpdir)
        # pick this one to start at 0 mined blocks
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)
        # Number of nodes to initialize ----------> ^

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        # Nodes to start --------^
        # Note for this template I readied 4 nodes but only started 2

        # Now interconnect the nodes
        connect_nodes_bi(self.nodes,0,1)
        # Let the framework know if the network is fully connected.
        # If not, the framework assumes this partition: (0,1) and (2,3)
        # For more complex partitions, you can't use the self.sync* member functions
        self.is_network_split=False
        self.sync_all()

    def run_test (self):
        # Each bet participant has a node
        # "mine" a block so that nodes[0] has a balance of 500.0
        self.nodes[0].generate(101)
        self.sync_blocks()
        assert waitUntil(lambda: self.nodes[0].getbalance() > 0, 5)

        # "mine" a block so that nodes[1] has a balance of 500.0
        self.nodes[1].generate(101)
        self.sync_blocks()
        assert waitUntil(lambda: self.nodes[1].getbalance() > 0, 5)

        with open("testscripts.bch","r") as scriptfile:
            scriptprog = scriptfile.read()

        with open("testbetscripts.bch", "r") as scriptfile:
            scriptprog = scriptprog + scriptfile.read()

        # get 2 new addresses for bet participants' win output 
        addr0 = self.nodes[0].getnewaddress()
        addrbin = bchscript.bitcoinAddress2bin(addr0)
        privb58 = self.nodes[0].dumpprivkey(addr0)
        tmp = decodeBase58(privb58)
        privkey0 = tmp[1:-5]  # chop network from front and compressed, checksum from end
        pubkey0 = cashlib.pubkey(privkey0)

        assert addrbin == hash160(pubkey0)

        addr1 = self.nodes[1].getnewaddress()
        priv2b58 = self.nodes[1].dumpprivkey(addr1)
        tmp = decodeBase58(priv2b58)
        privkey1 = tmp[1:-5]  # chop network from front and compressed, checksum from end
        pubkey1 = cashlib.pubkey(privkey1)

        t1 = scriptprog + ("""
            scriptify!("betlock", p2sh(hash160!(betSimple(%s, %s, OP_1))))
            scriptify!("betspend", betSimple(%s, %s, OP_1))
        """ % (addr0, addr1, addr0, addr1))

        result = bchscript.compile(t1)

        # ----------------------------------------------------------
        # Transaction 1: Forming the simplest bet using a P2SH

        tx = CTransaction()

        # grab the p2sh spendScript that will be used to create this simple bet's new UTXO
        #  (to keep it simple we won't have any change or bet escape outputs)
        outputscript = bchscript.script2bin(result["betlock"]["script"])
        tx.vout.append(CTxOut(10000000000, outputscript))

        # create the bet inputs using one utxo from each participant
        wallet0 = self.nodes[0].listunspent()
        wallet1 = self.nodes[1].listunspent()
        utxo0 = wallet0[0]
        utxo1 = wallet1[0]
        tx.vin.append(CTxIn(COutPoint(utxo0["txid"], utxo0["vout"]),utxo0.get("sig", b""), 0xffffffff))
        tx.vin.append(CTxIn(COutPoint(utxo1["txid"], utxo1["vout"]),utxo1.get("sig", b""), 0xffffffff))
        
        # prepare the signatures for the input UTXOs
        txbin = tx.serialize()
        txhex = hexlify(txbin).decode("utf-8")

        coinbasescript0 = utxo0["scriptPubKey"] # bchscript.script2bin(result["p2pkh0"]["script"])
        coinbasescript1 = utxo1["scriptPubKey"] # bchscript.script2bin(result["p2pkh1"]["script"])
        
        # get keys used in the coinbase transactions
        privk0 = decodeBase58(self.nodes[0].dumpprivkey(utxo0["address"]))[1:-5]
        pubk0 = cashlib.pubkey(privk0)
        pubk0Hex = hexlify(pubk0).decode("utf-8")
        privk1 = decodeBase58(self.nodes[1].dumpprivkey(utxo1["address"]))[1:-5]
        pubk1 = cashlib.pubkey(privk1)
        pubk1Hex = hexlify(pubk1).decode("utf-8")

        assert hash160(pubk0) == bchscript.bitcoinAddress2bin(utxo0["address"])
        
        assert pubk0Hex == coinbasescript0[2:-2] # chop off front OP_DATA_33 and end OP_CHECKSIG
        assert pubk1Hex == coinbasescript1[2:-2] # chop off front OP_DATA_33 and end OP_CHECKSIG

        sighashtype = 0xc1 # bitwise OR of 0x01, 0x40, and 0x80 for ALL|ANYONECANPAY --> 0xc1
        sig0 = cashlib.signtx(txbin, 0, 5000000000, coinbasescript0, sighashtype, privk0)
        sig1 = cashlib.signtx(txbin, 1, 5000000000, coinbasescript1, sighashtype, privk1)
        tx.vin[0].scriptSig = cashlib.spendscript(sig0) # note: pubk already in coinbase spend script
        tx.vin[1].scriptSig = cashlib.spendscript(sig1) # note: pubk already in coinbase spend script

        signedTxHex = ToHex(tx)

        # One of the nodes submits the bet transaction
        txid1 = self.nodes[0].sendrawtransaction(signedTxHex)

        initialBalance0 = self.nodes[0].getbalance()
        self.nodes[0].generate(1)

        assert waitUntil(lambda: self.nodes[0].getbalance() == initialBalance0 + 100, 5)

        # -----------------------------------------------------
        # Transaction 4: P2SH

        tx4 = CTransaction()
        p2shOutputscript = bchscript.script2bin(result["p2sh"]["script"])
        tx4.vout.append(CTxOut(100000000, p2shOutputscript))
        tx4.vin.append(CTxIn(COutPoint(txid1, 0), b"", 0xffffffff))
        sig4 = cashlib.signtx(tx4, 0, 100000000, outputscript, sighashtype, privkey)
        spendScript = cashlib.spendscript(sig4, pubkey)
        tx4.vin[0].scriptSig = spendScript
        txid4 = self.nodes[0].sendrawtransaction(ToHex(tx4))

        self.nodes[0].generate(1)

        # now spend the p2sh

        tx5 = CTransaction()
        spendoutscript = bchscript.script2bin(result["bet"]["script"])
        tx5.vout.append(CTxOut(100000000, outputscript))
        tx5.vin.append(CTxIn(COutPoint(txid4, 0), b"", 0xffffffff))
        sig5 = cashlib.signtx(tx5, 0, 100000000, spendoutscript, sighashtype, privkey2)

        spendScript = cashlib.spendscript( sig5, pubkey2[:15], pubkey2[15:], spendoutscript )
        tx5.vin[0].scriptSig = spendScript
        txid5 = self.nodes[0].sendrawtransaction(ToHex(tx5))

        assert self.nodes[0].getmempoolinfo()['size'] == 1
        self.nodes[0].generate(1)

        



if __name__ == '__main__':
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }


    flags = []
    # you may want these additional flags:
    # flags.append("--nocleanup")
    # flags.append("--noshutdown")

    # Execution is much faster if a ramdisk is used, so use it if one exists in a typical location
    if os.path.isdir("/ramdisk/test"):
        flags.append("--tmpdir=/ramdisk/test")

    # Out-of-source builds are awkward to start because they need an additional flag
    # automatically add this flag during testing for common out-of-source locations
    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.exists(os.path.abspath(here + "/../../src/bitcoind")):
        dbg = os.path.abspath(here + "/../../debug/src/bitcoind")
        rel = os.path.abspath(here + "/../../release/src/bitcoind")
        if os.path.exists(dbg):
            print("Running from the debug directory (%s)" % dbg)
            flags.append("--srcdir=%s" % os.path.dirname(dbg))
        elif os.path.exists(rel):
            print("Running from the release directory (%s)" % rel)
            flags.append("--srcdir=%s" % os.path.dirname(rel))

    t.main(flags, bitcoinConf, None)
