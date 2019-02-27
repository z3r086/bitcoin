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


RECONCIL_SET_SIZE = 20
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
        self.last_q_heard = 0
        self.last_bisection_heard = 0
        self.heard_all_tx = False
        self.expecting_txs = 0


    def clear_state(self):
        self.reconcil_requested = False
        self.reconcil_responded = False
        self.reconcil_diff_received = False
        self.last_differences_heard = 0
        self.last_receiver_missing_transactions = []
        self.last_sender_missing_transactions = []
        self.last_heard_tx_hashes = []
        self.last_syndromes_heard = []
        self.last_q_heard = 0
        self.last_bisection_heard = 0
        self.heard_all_tx = False
        self.expecting_txs = 0

    def on_tx(self, message):
        message.tx.rehash()
        if message.tx.hash in self.last_heard_tx_hashes:
            return
        self.last_heard_tx_hashes.append(message.tx.hash)
        if self.expecting_txs == len(self.last_heard_tx_hashes):
            self.heard_all_tx = True
        return


    def on_reqreconcil(self, message):
        if message.local_set_size == 0:
            return
        print(message)
        self.last_q_heard = message.q
        self.last_bisection_heard = message.bisection
        self.last_differences_heard = message.local_set_size
        self.reconcil_requested = True
        return

    def on_resreconcil(self, message):
        self.reconcil_responded = True
        self.last_syndromes_heard = message.syndromes
        return

    def on_reconcildiff(self, message):
        print(message)
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

    def request_reconcil(self, local_txs_count, q, expected_syndromes, bisection = 0):
        msg = msg_reqreconcil()
        msg.local_set_size = local_txs_count
        msg.q = q
        msg.bisection = bisection
        self.send_message(msg)
        if bisection >= 0: # not Fallback
            wait_until(self.received_res_reconcil, timeout=30, lock=mininode_lock)
            assert(self.last_syndromes_heard == expected_syndromes)

    def compute_syndromes(self, local_txs, n_syns = MAX_SYNDROMES):
        return find_odd_syndromes(local_txs, n_syns)

    def compute_bisection_syndromes(self, local_txs, n_syns = MAX_SYNDROMES):
        n_txs = len(local_txs)
        first_half = local_txs[0:int(n_txs/2)]
        first_quarter = local_txs[0:int(n_txs/4)]
        third_quarter = local_txs[int(n_txs/2):int(n_txs*3/4)]
        return find_odd_syndromes(first_half + first_quarter + third_quarter, n_syns)


    def process_reconcil_request(self, local_txs, syns_response = MAX_SYNDROMES, diffs_heard = RECONCIL_SET_SIZE, bisection = 0):
        wait_until(self.received_req_reconcil, timeout=30, lock=mininode_lock)
        assert(bisection == self.last_bisection_heard)
        if self.last_bisection_heard == 0:
            print(self.last_differences_heard)
            print(diffs_heard)
            assert(self.last_differences_heard == diffs_heard)
            msg = msg_resreconcil()
            msg.syndromes = self.compute_syndromes(local_txs, syns_response)
        # bisection
        elif self.last_bisection_heard == 1:
            msg = msg_resreconcil()
            # msg.syndromes = self.compute_bisection_syndromes(local_txs, syns_response)
            msg.syndromes = self.compute_syndromes(local_txs, syns_response)
        # simplification
        self.send_message(msg)

    def process_reconcil_diff(self, expected_receiver_missing_transactions, expected_sender_missing_transactions):
        wait_until(self.received_reconcil_diff, timeout=30, lock=mininode_lock)
        assert(set([x.hash for x in self.last_receiver_missing_transactions]) == set([x.sha256 for x in expected_receiver_missing_transactions]))
        assert(self.last_sender_missing_transactions == x.inv for x in expected_sender_missing_transactions)

    def process_txs(self, expected_txs):
        self.expecting_txs = len(expected_txs)
        wait_until(self.received_tx, timeout=30, lock=mininode_lock)
        assert(set(self.last_heard_tx_hashes) == set([x.hash for x in expected_txs]))


class ReconciliationTest2(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # self.num_nodes = 5
        # self.extra_args = [["-reconciliation=1"], ["-reconciliation=1"], [], [], []]
        self.num_nodes = 1
        self.extra_args = [["-reconciliation=1"]]



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
        self.test_node.add_p2p_connection(TestP2PConn(), services=NODE_NETWORK|NODE_RECONCILIATION)
        self.test_node.p2p.wait_for_verack()

        self.test_node2 = self.nodes[0].add_p2p_connection(TestP2PConn(), services=NODE_NETWORK|NODE_RECONCILIATION, node_outgoing=True)
        self.test_node2.wait_for_verack()

        txs = []
        blocks = self.test_node.generate(nblocks=256)
        sync_blocks(self.nodes)

        # peer init reconciling with us, we have no new transactions
        submitted_txs = []
        for i in range(RECONCIL_SET_SIZE):
            tx = self.generate_transaction(self.test_node, blocks[i])
            submitted_txs.append(tx)

        self.test_node.p2p.send_txs_and_test(submitted_txs, self.test_node, success = True)
        self.test_node2.process_reconcil_request([] * MAX_SYNDROMES)
        self.test_node2.process_reconcil_diff(submitted_txs, [])


        # peer init reconciliation, and there are shared and different transactions on both sides
        self.test_node2.clear_state()
        submitted_txs = []

        for i in range(2 * RECONCIL_SET_SIZE, 3 * RECONCIL_SET_SIZE):
            tx = self.generate_transaction(self.test_node, blocks[i])
            submitted_txs.append(tx)
        self.test_node.p2p.send_txs_and_test(submitted_txs, self.test_node, success = True)

        local_tx = self.generate_transaction(self.test_node, blocks[2 * RECONCIL_SET_SIZE + 1])
        local_txs = submitted_txs[1:] + [local_tx]
        self.test_node2.process_reconcil_request(local_txs)
        self.test_node2.process_reconcil_diff([submitted_txs[0]], [local_tx])
        #

        # peer failed to recover diff and asks for bisection
        self.test_node2.clear_state()
        txs = []

        for i in range(3 * RECONCIL_SET_SIZE, 4 * RECONCIL_SET_SIZE):
            tx = self.generate_transaction(self.test_node, blocks[i])
            txs.append(tx)


        local_txs = txs[3:]
        submitted_txs = txs[:-3]
        self.test_node.p2p.send_txs_and_test(submitted_txs, self.test_node, success = True)

        self.test_node2.process_reconcil_request(local_txs, syns_response = 4, diffs_heard = len(submitted_txs))
        self.test_node2.process_reconcil_request(local_txs, syns_response = 10, diffs_heard = len(submitted_txs), bisection = 1)
        self.test_node2.process_reconcil_diff(txs[:3], txs[-3:])


        # peer failed to recover diff and fallback after 2 bisections
        self.test_node2.clear_state()
        txs = []

        for i in range(4 * RECONCIL_SET_SIZE, 5 * RECONCIL_SET_SIZE):
            tx = self.generate_transaction(self.test_node, blocks[i])
            txs.append(tx)


        local_txs = txs[5:]
        submitted_txs = txs[:-5]
        self.test_node.p2p.send_txs_and_test(submitted_txs, self.test_node, success = True)

        self.test_node2.process_reconcil_request(local_txs, syns_response = 6, diffs_heard = len(submitted_txs))
        self.test_node2.process_reconcil_request(local_txs, syns_response = 7, diffs_heard = len(submitted_txs), bisection = 1)
        # self.test_node2.process_txs(submitted_txs)
        self.test_node2.process_reconcil_diff(submitted_txs, [])



def GetShortID(tx):
    return int(tx.hash, 16) & MASK64


if __name__ == '__main__':
    ReconciliationTest2().main()
