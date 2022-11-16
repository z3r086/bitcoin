// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXRECONCILIATION_H
#define BITCOIN_NODE_TXRECONCILIATION_H

#include <net.h>
#include <sync.h>

#include <memory>
#include <tuple>

/** Whether transaction reconciliation protocol should be enabled by default. */
static constexpr bool DEFAULT_TXRECONCILIATION_ENABLE{false};
/** Supported transaction reconciliation protocol version */
static constexpr uint32_t TXRECONCILIATION_VERSION{1};

enum class ReconciliationRegisterResult {
    NOT_FOUND,
    SUCCESS,
    PROTOCOL_VIOLATION,
};

/**
 * Transaction reconciliation is a way for nodes to efficiently announce transactions.
 * This object keeps track of all txreconciliation-related communications with the peers.
 * The high-level protocol is:
 * 0.  Txreconciliation protocol handshake.
 * 1.  Once we receive a new transaction, add it to the set instead of announcing immediately.
 * 2.  At regular intervals, a txreconciliation initiator requests a sketch from a peer, where a
 *     sketch is a compressed representation of short form IDs of the transactions in their set.
 * 3.  Once the initiator received a sketch from the peer, the initiator computes a local sketch,
 *     and combines the two sketches to attempt finding the difference in *sets*.
 * 4a. If the difference was not larger than estimated, see SUCCESS below.
 * 4b. If the difference was larger than estimated, initial txreconciliation fails. The initiator
 *     requests a larger sketch via an extension round (allowed only once).
 *     - If extension succeeds (a larger sketch is sufficient), see SUCCESS below.
 *     - If extension fails (a larger sketch is insufficient), see FAILURE below.
 *
 * SUCCESS. The initiator knows full symmetrical difference and can request what the initiator is
 *          missing and announce to the peer what the peer is missing.
 *
 * FAILURE. The initiator notifies the peer about the failure and announces all transactions from
 *          the corresponding set. Once the peer received the failure notification, the peer
 *          announces all transactions from their set.

 * This is a modification of the Erlay protocol (https://arxiv.org/abs/1905.10518) with two
 * changes (sketch extensions instead of bisections, and an extra INV exchange round), both
 * are motivated in BIP-330.
 */
class TxReconciliationTracker
{
private:
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxReconciliationTracker(uint32_t recon_version);
    ~TxReconciliationTracker();

    /**
     * Step 0. Generates initial part of the state (salt) required to reconcile txs with the peer.
     * The salt is used for short ID computation required for txreconciliation.
     * The function returns the salt.
     * A peer can't participate in future txreconciliations without this call.
     * This function must be called only once per peer.
     */
    uint64_t PreRegisterPeer(NodeId peer_id);

    /**
     * Step 0. Once the peer agreed to reconcile txs with us, generate the state required to track
     * ongoing reconciliations. Must be called only after pre-registering the peer and only once.
     */
    ReconciliationRegisterResult RegisterPeer(NodeId peer_id, bool is_peer_inbound,
                                                uint32_t peer_recon_version, uint64_t remote_salt);

    /**
     * Step 1. Add new transactions we want to announce to the peer to the local reconciliation set
     * of the peer, so that those transactions will be reconciled later.
     * The caller *must* check that the peer is registered for reconciliations.
     */
    void AddToSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile);

    /**
     * Before Step 2, we might want to remove a wtxid from the reconciliation set, for example if
     * the peer just announced the transaction to us.
     * The caller *must* check that the peer is registered for reconciliations.
     */
    void TryRemovingFromSet(NodeId peer_id, const uint256& wtxid_to_remove);

    /**
     * Step 2. If it's time to request a reconciliation from the peer, this function will return
     * the details of our local state, which should be communicated to the peer so that they better
     * know what we need:
     * - size of our reconciliation set for the peer
     * - our q-coefficient with the peer, formatted to be transmitted as integer value
     * If the peer was not previously registered for reconciliations, returns nullopt.
     */
    std::optional<std::pair<uint16_t, uint16_t>> MaybeRequestReconciliation(NodeId peer_id);

    /**
     * Step 2. Record an (expected) reconciliation request with parameters to respond when its time.
     * All initial reconciliation responses will be done not immediately but in batches after
     * a delay, to prevent privacy leaks.
     * If peer violates the protocol, do nothing.
     */
    void HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q);

    /**
     * Step 2. Once it's time to respond to reconciliation requests, we construct a sketch from
     * the local reconciliation set, and send it to the initiator.
     * If the peer was not previously registered for reconciliations or it's not the time yet,
     * returns false.
     */
    bool RespondToReconciliationRequest(NodeId peer_id, std::vector<uint8_t>& skdata);

    /**
     * Step 3. Process a response to our reconciliation request.
     * Returns false if the peer seems to violate the protocol.
     * Populates the vectors so that we know which transactions should be requested and announced,
     * and whether reconciliation succeeded (nullopt if the reconciliation is not over yet and
     * extension should be requested).
     */
    bool HandleSketch(NodeId peer_id, const std::vector<uint8_t>& skdata,
                      // returning values
                      std::vector<uint32_t>& txs_to_request, std::vector<uint256>& txs_to_announce, std::optional<bool>& result);

    /**
     * Step 5. Peer requesting extension after reconciliation they initiated failed on their side:
     * the sketch we sent to them was not sufficient to find the difference.
     * No privacy leak can happen here because sketch extension is constructed over the snapshot.
     * If the peer seems to violate the protocol, do nothing.
     */
    void HandleExtensionRequest(NodeId peer_id);

    /**
     * Step 4. Once we received a signal of reconciliation finalization with a given result from the
     * initiating peer, announce the following transactions:
     * - in case of a failure, all transactions we had for that peer
     * - in case of a success, transactions the peer asked for by short id (ask_shortids)
     * Return false if the peer seems to violate the protocol.
     */
    bool FinalizeInitByThem(NodeId peer_id, bool recon_result,
        const std::vector<uint32_t>& remote_missing_short_ids, std::vector<uint256>& remote_missing);

    /**
     * Returns the size of the reconciliation set we have locally for the given peer.
     */
    size_t GetPeerSetSize(NodeId peer_id) const;

    /**
     * Attempts to forget txreconciliation-related state of the peer (if we previously stored any).
     * After this, we won't be able to reconcile transactions with the peer.
     */
    void ForgetPeer(NodeId peer_id);

    /**
     * Check if a peer is registered to reconcile transactions with us.
     */
    bool IsPeerRegistered(NodeId peer_id) const;

    /**
     * Returns whether the peer is chosen as a low-fanout destination for a given tx.
     */
    bool ShouldFloodTo(NodeId peer_id, const uint256& wtxid) const;

    /**
     * Check whether a particular transaction is in the reconciliation set of a given peer.
     */
    bool IsAlreadyInPeerSet(NodeId peer_id, const uint256& wtxid) const;
};

#endif // BITCOIN_NODE_TXRECONCILIATION_H
