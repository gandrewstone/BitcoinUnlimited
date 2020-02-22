#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.bunode import BasicBUCashNode, BUProtocolHandler
from test_framework.mininode import NetworkThread
from test_framework.nodemessages import *
from test_framework.bumessages import *

CAPD_XVERSION_STR = '0000000000020006'

class CapdProtoHandler(BUProtocolHandler):
    def __init__(self):
        BUProtocolHandler.__init__(self)
        self.lastCapdGetMsg = None
        self.numCapdGetMsg = 0

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self,conn, message)
        conn.send_message(msg_xversion({int(CAPD_XVERSION_STR,16): 1}))

    def on_xversion(self, conn, message):
        BUProtocolHandler.on_xversion(self, conn, message)
        conn.send_message(msg_xverack())

    def on_capdinv(self, conn, message):
        pdb.set_trace()

    def on_capdmsg(self, conn, message):
        pdb.set_trace()

    def on_capdgetmsg(self, conn, message):
        self.lastCapdGetMsg = message
        self.numCapdGetMsg += 1

class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        bitcoinConfDict.update({ "net.capd": 1})
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        self.is_network_split=False
        self.sync_blocks()

        self.pynode = pynode = BasicBUCashNode()

        self.conn = pynode.connect(0, '127.0.0.1', p2p_port(0), self.nodes[0],
                       protohandler = CapdProtoHandler(),
                       send_initial_version = True)
        self.nt = NetworkThread()
        self.nt.start()

    def run_test (self):

        logging.info("CAPD message pool test")

        # generate 1 block to kick nodes out of IBD mode
        self.nodes[0].generate(1)
        self.sync_blocks()

        result = self.nodes[0].capd()

        # Check the empty msg pool
        assert_equal(result['size'], 0)
        assert_equal(result['count'], 0)
        assert_equal(result['relayPriority'], 2)
        assert_equal(result['minPriority'], 1)

        hdlr = self.pynode.cnxns[0]
        self.conn.handle_write()
        hdlr.send_message(msg_buversion(addrFromPort = 12345))
        hdlr.wait_for_verack()
        hdlr.wait_for_xverack()

        result = self.nodes[0].getpeerinfo()
        for n in result:
            # if n["subver"] == "": # This is the python node so skip checking its XVERSION string
            #   continue
            # Note that this tests both the C code exchanging CAPD xversion and this python node
            capdVer = int(n["xversion_map"][CAPD_XVERSION_STR])
            assert_equal(capdVer, 1)

        capdStats = self.nodes[0].capd()
        assert_equal(capdStats["count"], 0)

        # Send an INV and expect a getmsg back asking for the message
        hdlr.lastCapdGetMsg = None
        hdlr.send_message(msg_capdinv([hash256(b'0')]))
        while hdlr.lastCapdGetMsg == None:
            time.sleep(.25)
        getmsg = hdlr.lastCapdGetMsg
        assert_equal(len(getmsg.hashes), 1)
        assert_equal(getmsg.hashes[0],hash256(b'0'))
        # I sent a bogus hash, no just ignore the message request


        pdb.set_trace()



if __name__ == '__main__':
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb=True
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }


    flags = standardFlags()
    flags.append("--tmpdir=/ramdisk/test/t")
    t.main(flags, bitcoinConf, None)
