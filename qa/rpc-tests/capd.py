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
        self.lastCapdInvHashes = None
        self.numInvMsgs = 0

        self.msgs = {}

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self,conn, message)
        conn.send_message(msg_xversion({int(CAPD_XVERSION_STR,16): 1}))

    def on_xversion(self, conn, message):
        BUProtocolHandler.on_xversion(self, conn, message)
        conn.send_message(msg_xverack())

    def on_capdinv(self, conn, message):
        self.lastCapdInvHashes = message.hashes
        self.numInvMsgs += 1
        # print("CAPD INV:")
        # for m in message.hashes:
        #    print("  " + m.hex())

    def on_capdmsg(self, conn, message):
        pdb.set_trace()

    def on_capdgetmsg(self, conn, message):
        self.lastCapdGetMsg = message
        self.numCapdGetMsg += 1

        # If test should automatically reply to this incoming message, then fill self.msgs with possible replies
        replymsgs = []
        for h in message.hashes:
            if h in self.msgs:
                replymsgs.append(self.msgs[h])
        if len(replymsgs)>0:
            self.send_message(msg_capdmsg(replymsgs))


class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        bitcoinConfDict.update({ "net.capd": 100000})
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
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
        # I sent a bogus hash, nothing to do except ignore the message request

        m = CapdMsg(b"this is a test")
        m.solve(4)
        print("hash: " + m.calcHash().hex() )

        hdlr.send_message(msg_capdmsg([m]))
        # Wait for the node to INV me with my own message
        while hdlr.lastCapdInvHashes == None:
            print("waiting for INV")
            time.sleep(1)

        # This checks the communications protocol and that both sides calculated the same hash for the same message, which
        # tests both the message serialization integrity, the hash algorithm, and endianness when converting hash bytes to numbers
        # because if the conversion is wrong, the incorrect hash-as-integer will be very likely to be > the target so won't be inserted or relayed
        assert_equal(hdlr.lastCapdInvHashes[0], m.calcHash())

        # Test propagation protocol since node 0 and node 1 should run the INV, GETCAPDMSG, CAPDMSG protocol when I gave node 0 a new message
        assert_equal(self.nodes[1].capd()["count"], 1)

        l0 = self.nodes[0].capd("list")
        l1 = self.nodes[1].capd("list")
        assert_equal(l0, l1)

        print("Create 300 messages")
        # Let's create a lot of messages
        hdlr.msgs = {}
        EXP_MSGS = 301
        for i in range(0,EXP_MSGS-1):
            m = CapdMsg(i.to_bytes(2,"big") + (b" msg count %d" % i))
            m.solve(7)
            hdlr.msgs[m.getHash()] = m

        hdlr.send_message(msg_capdinv([ x.getHash() for x in hdlr.msgs.values()]))

        try:
            waitFor(15, lambda: self.nodes[0].capd()["count"] == EXP_MSGS)
        except TimeoutException:
            print(self.nodes[0].capd())
            pdb.set_trace()

        try:
            waitFor(5, lambda: sorted(self.nodes[0].capd("list")) == sorted(self.nodes[1].capd("list")))
        except TimeoutException:
            print ("not equal")

        if 0:
            for x in self.nodes:
                print()
                print(x.capd())
                print(x.capd("list"))

        l0 = self.nodes[0].capd("list")
        l1 = self.nodes[1].capd("list")
        assert_equal(sorted(l0),sorted(l1))
        if sorted(l0) != sorted(l1):
            print("incomplete propagation")
            s0 = set(l0)
            s1 = set(l1)
            sleft = s0 - s1
            print("unpropagated: ", len(sleft))
            print (sleft)


        # pdb.set_trace()
        # reduce the capd message size and validate that it gets pared down
        self.nodes[1].set("net.capd=1000")
        st0 = self.nodes[1].capd()
        assert(st0["size"] < 1000)
        print(st0)

        print("Create 2000 messages, overflow pool")
        # Generate acceptable messages, given a full msg pool
        hdlr.msgs={}
        while i < 5000:
            i+=1
            st0 = self.nodes[1].capd()
            pri = st0["relayPriority"]
            if i&127 == 0: print("%d: priority: %f" % (i,pri))
            m = CapdMsg(i.to_bytes(2,"big") + (b" 2nd msg count %d" % i))
            m.solve(pri + decimal.Decimal(0.1))
            hdlr.msgs[m.getHash()] = m
            hdlr.send_message(msg_capdinv([ m.getHash()]))
            # time.sleep(0.001)

        logging.info("CAPD test finished")
        time.sleep(1)
        pdb.set_trace()



if __name__ == '__main__':
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb=True
    bitcoinConf = {
        "debug": ["capd", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }


    flags = standardFlags()
    flags.append("--tmpdir=/ramdisk/test/t")
    t.main(flags, bitcoinConf, None)
