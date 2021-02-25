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

    /**
     * Start tracking state of reconciliation with the peer, and add it to the reconciliation
     * queue if it is an outbound connection. Decide whether we should flood (certain) transactions
     * to the peer based on the number of existing outbound flood connections.
     * Should be called only after SuggestReconciling for the same peer and only once.
     * Returns false if a peer seems to violate the protocol rules.
     */
    bool EnableReconciliationSupport(const NodeId peer_id, bool inbound,
        bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt,
        size_t outbound_flooders);

    /**
     * Check if peer is registered to perform reconciliations with.
     */
    bool IsPeerRegistered(const NodeId peer_id) const;

    /**
     * Per BIP-330, we may want to flood certain transactions to a subset of peers with whom we
     * reconcile.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<bool> IsPeerChosenForFlooding(const NodeId peer_id) const;

    /**
     * Removes any reconciliation-related state/notion of the peer.
     */
    void RemovePeer(const NodeId peer_id);

    /**
     * Returns whether a given peer might respond to our reconciliation requests.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<bool> IsPeerResponder(const NodeId peer_id) const;

    /**
     * Returns the size of the reconciliation set we have locally for the given peer.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<size_t> GetPeerSetSize(const NodeId peer_id) const;

    /**
     * Adds new transactions we want to announce to the peer to the local reconciliation set of the
     * peer, so that those transactions will be reconciled later.
     */
    void StoreTxsToAnnounce(const NodeId peer_id, const std::vector<uint256>& txs_to_reconcile);

    /**
     * If a it's time to request a reconciliation from the peer, this function will return the
     * details of our local state (local reconciliation set size and local q-coef value), which
     * should be communicated to the peer so that they better know how to construct a sketch for us.
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<std::pair<uint16_t, uint16_t>> MaybeRequestReconciliation(const NodeId peer_id);

    /**
     * Record an (expected) reconciliation request with parameters to respond when time comes. All
     * initial reconciliation responses will be done at the same time to prevent privacy leaks.
     */
    void HandleReconciliationRequest(const NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q);

    /**
     * Once it's time to respond to reconciliation requests, we construct a sketch from the local
     * reconciliation set for the peer who requested a reconciliation, and send it to that peer.
     * If the peer was not previously registered for reconciliations or it's not the time yet,
     * returns nullopt.
     */
    std::optional<std::vector<uint8_t>> MaybeRespondToReconciliationRequest(const NodeId peer_id);

    /**
     * Once we received a signal of reconciliation finalization with a given result from the
     * initiating peer, return the following transactions to be announced:
     * - in case of a failure, return all transactions we had for that peer
     * - in case of a success, return transactions the peer asked for by short id (ask_shortids)
     */
    std::vector<uint256> FinalizeIncomingReconciliation(const NodeId peer_id,
        bool recon_result, const std::vector<uint32_t>& ask_shortids);

    /**
     * Received a response to the reconciliation request. May leak tx-related privacy if we announce
     * local transactions right away, in case the peer is strategic about sending sketches to us via
     * different connections (requires attacker to occupy multiple outgoing connections).
     * Returns a response we should send to the peer, and the transactions we should announce.
     */
    std::optional<std::tuple<bool, bool, std::vector<uint32_t>, std::vector<uint256>>> HandleSketch(
        const NodeId peer_id, int common_version, std::vector<uint8_t>& skdata);
};

#endif // BITCOIN_TXRECONCILIATION_H
