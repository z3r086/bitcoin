// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXRECONCILIATION_H
#define BITCOIN_TXRECONCILIATION_H

#include <net.h>
#include <sync.h>

#include <tuple>
#include <unordered_map>

/**
 * Transaction reconciliation is a way for nodes to efficiently announce transactions. This object
 * keeps track of all reconciliation-related communications with the peers.
 * 1. To register a peer for reconciliations, SuggestReconciling should be called first.
 */
class TxReconciliationTracker {
    // Avoid littering this header file with implementation details.
    class Impl;
    const std::unique_ptr<Impl> m_impl;

    public:

    explicit TxReconciliationTracker();
    ~TxReconciliationTracker();

    /**
     * Generates (and stores) a peer-specific salt which will be used for reconciliations.
     * Reconciliation roles (requestor/responder) based on inbound/outbound role in the connection.
     * Returns the following values which will be used to invite a peer to reconcile:
     * - whether we want to initiate reconciliations (request sketches)
     * - whether we agree to respond to reconciliations (send our sketches)
     * - reconciliation version (currently, 1)
     * - peer-specific salt
     * A peer can't be registered for future reconciliations without this call.
     */
    std::tuple<bool, bool, uint32_t, uint64_t> SuggestReconciling(const NodeId peer_id, bool inbound);
};

#endif // BITCOIN_TXRECONCILIATION_H
