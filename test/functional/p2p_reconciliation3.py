#!/usr/bin/env python3
# Copyright (c) 2016-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test reconciliation-based transaction relay protocol.

"""

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.script import CScript, OP_TRUE, OP_DROP
from test_framework.messages import *


TXS = 100
HALF_SET = int(TXS / 2)
MAX_SYNDROMES = 50

FIELD_SIZE = 64
MODULO_LOW_BITS = 27

MASK64 = 0xffffffffffffffff

DEFAULT_Q = 0.04

def mul2(x):
    return ((MASK64 & (x << 1)) ^ (((-(x >> (FIELD_SIZE - 1)))) & MODULO_LOW_BITS))

def multiply_in_field(a, b):
    r = 0
    for i in range(FIELD_SIZE):
        r ^= (1 + ~(b & 1)) & a; a = mul2(a); b >>= 1;
    return r

def find_odd_syndromes(transactions, syndromes):
    elements = [GetShortID(x) for x in transactions]
    result = [0] * syndromes
    for el in elements:
        el_squared = multiply_in_field(el, el)
        cur_el = el
        for i in range(syndromes):
            result[i] ^= cur_el
            cur_el = multiply_in_field(cur_el, el_squared)
    return result


# TestP2PConn: A peer we use to send messages to bitcoind, and store responses.
class TestP2PConn(P2PDataStore):
    def __init__(self):
        super().__init__()
        self.reconcil_requested = False
        self.reconcil_responded = False
        self.reconcil_diff_received = False
        self.last_differences_heard = 0
        self.last_receiver_missing_transactions = []
        self.last_sender_missing_transactions = []
        self.last_heard_tx_hashes = []
        self.expecting_txs = 0
        self.expecting_getdatas = 0
        self.heard_all_tx = False
        self.heard_all_getdatas = False
        self.last_heard_getdatas = []


    def clear_state(self):
        self.reconcil_requested = False
        self.reconcil_responded = False
        self.reconcil_diff_received = False
        self.last_differences_heard = 0
        self.last_receiver_missing_transactions = []
        self.last_sender_missing_transactions = []
        self.last_heard_tx_hashes = []
        self.expecting_txs = 0
        self.last_heard_getdatas = []
        self.expecting_getdatas = 0
        self.heard_all_tx = False
        self.heard_all_getdatas = False
        self.last_syndromes_heard = []

    def on_tx(self, message):
        message.tx.rehash()
        if message.tx.hash in self.last_heard_tx_hashes:
            return
        self.last_heard_tx_hashes.append(message.tx.hash)
        if self.expecting_txs == len(self.last_heard_tx_hashes):
            self.heard_all_tx = True
        return

    def on_getdata(self, message):
        for inv in message.inv:
            if inv.hash in self.last_heard_getdatas:
                return
            self.last_heard_getdatas.append(inv)
        if (len(self.last_heard_getdatas) == self.expecting_getdatas):
            self.heard_all_getdatas = True
        return


    def on_reqreconcil(self, message):
        self.reconcil_requested = True
        return

    def on_resreconcil(self, message):
        self.reconcil_responded = True
        self.last_syndromes_heard = message.syndromes
        return

    def on_reconcildiff(self, message):
        self.reconcil_diff_received = True
        self.last_receiver_missing_transactions = message.receiver_missing_transactions
        self.last_sender_missing_transactions = message.sender_missing_transactions
        return

    # Requires caller to hold mininode_lock
    def received_res_reconcil(self):
        return self.reconcil_responded

    def received_req_reconcil(self):
        return self.reconcil_requested

    def received_reconcil_diff(self):
        return self.reconcil_diff_received

    def received_tx(self):
        return self.heard_all_tx

    def received_getdatas(self):
        return self.heard_all_getdatas

    def request_reconcil(self, local_txs_count, q, expected_syndromes, bisection = 0):
        msg = msg_reqreconcil()
        msg.local_set_size = local_txs_count
        msg.q = q
        msg.bisection = bisection
        self.send_message(msg)
        if bisection >= 0: # not Fallback
            wait_until(self.received_res_reconcil, timeout=30, lock=mininode_lock)
            assert(self.last_syndromes_heard == expected_syndromes)


    def send_reconcil_diff(self, local_txs, missing_txs, success=True):
        # TODO: announce TXs?
        msg = msg_reconcildiff()
        msg.success = success
        msg.sender_missing_transactions = [GetShortID(x) for x in missing_txs]
        msg.receiver_missing_transactions = [CInv(MSG_TX, x.sha256) for x in local_txs]
        self.send_message(msg)

    def compute_syndromes(self, local_txs, n_syns = MAX_SYNDROMES):
        print("n_syns ", n_syns)
        return find_odd_syndromes(local_txs, n_syns)

    def process_txs(self, expected_txs):
        self.expecting_txs = len(expected_txs)
        if self.expecting_txs == len(self.last_heard_tx_hashes):
            self.heard_all_tx =  True
        wait_until(self.received_tx, timeout=30, lock=mininode_lock)
        assert(sorted(self.last_heard_tx_hashes) == sorted([x.hash for x in expected_txs]))

    def process_getdatas(self, expected_getdatas):
        self.expecting_getdatas = len(expected_getdatas)
        if self.expecting_getdatas == len(self.last_heard_getdatas):
            self.heard_all_getdatas =  True
        wait_until(self.received_getdatas, timeout=30, lock=mininode_lock)
        assert(sorted([x.hash for x in self.last_heard_getdatas]) == sorted([x.sha256 for x in expected_getdatas]))

class ReconciliationTest3(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 5
        # self.extra_args = [["-reconciliation=1"]] * self.num_nodes
        self.extra_args = [["-reconciliation=0"]] * self.num_nodes
        # self.extra_args = [[]] * self.num_nodes



    def generate_transaction(self, node, coinbase):
        amount = 1.0
        to_address = node.getnewaddress()
        from_txid = node.getblock(coinbase)['tx'][0]
        inputs = [{ "txid" : from_txid, "vout" : 0}]
        outputs = { to_address : amount }
        rawtx = node.createrawtransaction(inputs, outputs)
        signresult = node.signrawtransactionwithwallet(rawtx)
        tx = CTransaction()
        tx.deserialize(BytesIO(hex_str_to_bytes(signresult['hex'])))
        tx.rehash()
        return tx

    def run_test(self):
        self.test_node = self.nodes[0]
        self.test_node.add_p2p_connection(TestP2PConn(), services=NODE_NETWORK)
        # self.test_node.add_p2p_connection(TestP2PConn(), services=NODE_NETWORK|NODE_RECONCILIATION)
        self.test_node.p2p.wait_for_verack()


        txs = []
        blocks = self.test_node.generate(nblocks=TXS*2+101)
        sync_blocks(self.nodes)

        # us initiating recociliation with peer, there is a shared transaction
        local_txs = []
        for i in range(TXS):
            tx = self.generate_transaction(self.test_node, blocks[i])
            self.test_node.p2p.send_txs_and_test([tx], self.test_node, success = True)
            time.sleep(0.14)

        time.sleep(10)

        for i in range(TXS, TXS*2):
            tx = self.generate_transaction(self.test_node, blocks[i])
            self.test_node.p2p.send_txs_and_test([tx], self.test_node, success = True)
            time.sleep(0.14)




def GetShortID(tx):
    return int(tx.hash, 16) & MASK64


if __name__ == '__main__':
    ReconciliationTest3().main()
