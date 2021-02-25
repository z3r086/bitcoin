// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txreconciliation.h>

#include <minisketch/include/minisketch.h>

namespace {

/** Current protocol version */
constexpr uint32_t RECON_VERSION = 1;
/** Static component of the salt used to compute short txids for transaction reconciliation. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";
/** The size of the field, used to compute sketches to reconcile transactions (see BIP-330). */
constexpr unsigned int RECON_FIELD_SIZE = 32;
/**
 * Allows to infer capacity of a reconciliation sketch based on it's char[] representation,
 * which is necessary to deserealize a received sketch.
 */
constexpr unsigned int BYTES_PER_SKETCH_CAPACITY = RECON_FIELD_SIZE / 8;
/** Limit sketch capacity to avoid DoS. */
constexpr uint16_t MAX_SKETCH_CAPACITY = 2 << 12;
/**
* It is possible that if sketch encodes more elements than the capacity, or
* if it is constructed of random bytes, sketch decoding may "succeed",
* but the result will be nonsense (false-positive decoding).
* Given this coef, a false positive probability will be of 1 in 2**coef.
*/
constexpr unsigned int RECON_FALSE_POSITIVE_COEF = 16;
static_assert(RECON_FALSE_POSITIVE_COEF <= 256,
    "Reducing reconciliation false positives beyond 1 in 2**256 is not supported");
/** Default coefficient used to estimate set difference for tx reconciliation. */
constexpr double DEFAULT_RECON_Q = 0.02;
/** Used to convert a floating point reconciliation coefficient q to an int for transmission.
  * Specified by BIP-330.
  */
constexpr uint16_t Q_PRECISION{(2 << 14) - 1};
/**
 * When considering whether we should flood to an outbound connection supporting reconciliation,
 * see how many outbound connections are already used for flooding. Flood only if the limit is not reached.
 * It helps to save bandwidth and reduce the privacy leak.
 */
constexpr uint32_t MAX_OUTBOUND_FLOOD_TO = 8;
/**
 * Interval between sending reconciliation request to the same peer.
 * This value allows to reconcile ~100 transactions (7 tx/s * 16s) during normal system operation
 * at capacity. More frequent reconciliations would cause significant constant bandwidth overhead
 * due to reconciliation metadata (sketch sizes etc.), which would nullify the efficiency.
 * Less frequent reconciliations would introduce high transaction relay latency.
 */
constexpr std::chrono::microseconds RECON_REQUEST_INTERVAL{16s};
/**
 * Interval between responding to peers' reconciliation requests.
 * We don't respond to reconciliation requests right away because that would enable monitoring
 * when we receive transactions (privacy leak).
 */
constexpr std::chrono::microseconds RECON_RESPONSE_INTERVAL{2s};

/**
 * Represents phase of the current reconciliation round with a peer.
 */
enum ReconciliationPhase {
    RECON_NONE,
    RECON_INIT_REQUESTED,
    RECON_INIT_RESPONDED,
};

/**
 * A salt is specified by BIP-330 is constructed from contributions from both peers, and is later
 * used to construct transaction short IDs to be used for efficient transaction reconciliations.
 */
uint256 ComputeSalt(uint64_t local_salt, uint64_t remote_salt)
{
    uint64_t salt1 = local_salt, salt2 = remote_salt;
    if (salt1 > salt2) std::swap(salt1, salt2);
    static const auto RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);
    return (CHashWriter(RECON_SALT_HASHER) << salt1 << salt2).GetSHA256();
}

/**
 * TODO: comment
 */
std::optional<std::pair<Minisketch, uint16_t>> ParseRemoteSketch(const std::vector<uint8_t>& skdata)
{
    uint16_t remote_sketch_capacity = uint16_t(skdata.size() / BYTES_PER_SKETCH_CAPACITY);
    if (remote_sketch_capacity != 0) {
        Minisketch remote_sketch = Minisketch(RECON_FIELD_SIZE, 0, remote_sketch_capacity).Deserialize(skdata);
        return std::make_pair(remote_sketch, remote_sketch_capacity);
    } else {
        return std::nullopt;
    }
}

/**
 * After a reconciliation round is over, the local q coefficient may be adjusted to enable
 * better accuracy of future set difference estimations.
 * Recompute q in case of full reconciliation success (both initially or after extension).
 * In case reconciliation completely failed (initial and extension), fallback to the default q,
 * set to cause an overestimation, but should converge to the reasonable q in the next round.
 * Note that accurate recompute in case of complete failure is difficult,
 * because it requires waiting for GETDATA/INV the peer would send to us, and find
 * the actual difference from there (also may be inaccurate due to the latencies).
 */
double RecomputeQ(uint8_t local_set_size, uint8_t actual_local_missing, uint8_t actual_remote_missing)
{
    const uint8_t remote_set_size = local_set_size + actual_local_missing - actual_remote_missing;
    const uint8_t set_size_diff = std::abs(local_set_size - remote_set_size);
    const uint8_t min_size = std::min(local_set_size, remote_set_size);
    const uint8_t actual_difference = actual_local_missing + actual_remote_missing;
    if (min_size != 0) {
        double result = double(actual_difference - set_size_diff) / min_size;
        assert(result >= 0 && result <= 2);
        return result;
    }
    return DEFAULT_RECON_Q;
}

/**
 * This struct is used to keep track of the reconciliations with a given peer,
 * and also short transaction IDs for the next reconciliation round.
 * Transaction reconciliation means an efficient synchronization of the known
 * transactions between a pair of peers.
 * One reconciliation round consists of a sequence of messages. The sequence is
 * asymmetrical, there is always a requestor and a responder. At the end of the
 * sequence, nodes are supposed to exchange transactions, so that both of them
 * have all relevant transactions. For more protocol details, refer to BIP-0330.
 */
class ReconciliationState {
    friend TxReconciliationTracker;

    /**
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches on request).
     * */
    bool m_we_initiate;

    /**
     * Since reconciliation-only approach makes transaction relay
     * significantly slower, we also announce some of the transactions
     * (currently, transactions received from inbound links)
     * to some of the peers:
     * - all pre-reconciliation peers supporting transaction relay;
     * - a limited number of outbound reconciling peers *for which this flag is enabled*.
     * We enable this flag based on whether we have a
     * sufficient number of outbound transaction relay peers.
     * This flooding makes transaction relay across the network faster
     * without introducing high the bandwidth overhead.
     * Transactions announced via flooding should not be added to
     * the reconciliation set.
     */
    bool m_flood_to;

    /**
     * Reconciliation involves computing and transmitting sketches,
     * which is a bandwidth-efficient representation of transaction IDs.
     * Since computing sketches over full txID is too CPU-expensive,
     * they will be computed over shortened IDs instead.
     * These short IDs will be salted so that they are not the same
     * across all pairs of peers, because otherwise it would enable network-wide
     * collisions which may (intentionally or not) halt relay of certain transactions.
     * Both of the peers contribute to the salt.
     */
    const uint64_t m_k0, m_k1;

    /**
     * Computing a set reconciliation sketch involves estimating the difference
     * between sets of transactions on two sides of the connection. More specifically,
     * a sketch capacity is computed as
     * |set_size - local_set_size| + q * (set_size + local_set_size) + c,
     * where c is a small constant, and q is a node+connection-specific coefficient.
     * This coefficient is recomputed by every node based on its previous reconciliations,
     * to better predict future set size differences.
     */
    double m_local_q;

    /**
     * The use of q coefficients is described above (see local_q comment).
     * The value transmitted from the peer with a reconciliation requests is stored here until
     * we respond to that request with a sketch.
     */
    double m_remote_q;

    /**
     * Store all transactions which we would relay to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute an efficient representation of this set ("sketch") and use it to efficient reconcile
     * this set with a similar set on the other side of the connection.
     */
    std::set<uint256> m_local_set;

    /**
     * A reconciliation request comes from a peer with a reconciliation set size from their side,
     * which is supposed to help us to estimate set difference size. The value is stored here until
     * we respond to that request with a sketch.
     */
    uint16_t m_remote_set_size;

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * This is a cache of these IDs enabling faster lookups of full wtxids,
     * useful when peer will ask for missing transactions by short IDs
     * at the end of a reconciliation round.
     */
    std::map<uint32_t, uint256> m_local_short_id_mapping;

    /**
     * When a reconciliation request is received, instead of responding to it right away,
     * we schedule a response for later, so that a spy can’t monitor our reconciliation sets.
     */
    std::chrono::microseconds m_next_recon_respond{0};

    /** Keep track of reconciliations with the peer. */
    ReconciliationPhase m_incoming_recon{RECON_NONE};
    ReconciliationPhase m_outgoing_recon{RECON_NONE};

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * Short IDs are salted with a link-specific constant value.
     */
    uint32_t ComputeShortID(const uint256 wtxid) const
    {
        const uint64_t s = SipHashUint256(m_k0, m_k1, wtxid);
        const uint32_t short_txid = 1 + (s & 0xFFFFFFFF);
        return short_txid;
    }

    /**
     * Estimate a capacity of a sketch we will send or use locally (to find set difference)
     * based on the local set size.
     */
    uint16_t EstimateSketchCapacity() const
    {
        const uint16_t set_size_diff = std::abs(uint16_t(m_local_set.size()) - m_remote_set_size);
        const uint16_t min_size = std::min(uint16_t(m_local_set.size()), m_remote_set_size);
        const uint16_t weighted_min_size = m_remote_q * min_size;
        const uint16_t estimated_diff = 1 + weighted_min_size + set_size_diff;
        return minisketch_compute_capacity(RECON_FIELD_SIZE, estimated_diff, RECON_FALSE_POSITIVE_COEF);
    }

    public:

    ReconciliationState(bool we_initiate, bool flood_to, uint64_t k0, uint64_t k1) :
        m_we_initiate(we_initiate), m_flood_to(flood_to),
        m_k0(k0), m_k1(k1), m_local_q(DEFAULT_RECON_Q) {}


    /**
     * Reconciliation involves computing a space-efficient representation of transaction identifiers
     * (a sketch). A sketch has a capacity meaning it allows reconciling at most a certain number
     * of elements (see BIP-330).
     */
    Minisketch ComputeSketch(uint16_t capacity)
    {
        Minisketch sketch;
        // Avoid serializing/sending an empty sketch.
        if (m_local_set.size() == 0 || capacity == 0) return sketch;

        std::vector<uint32_t> short_ids;
        for (const auto& wtxid: m_local_set) {
            uint32_t short_txid = ComputeShortID(wtxid);
            short_ids.push_back(short_txid);
            m_local_short_id_mapping.emplace(short_txid, wtxid);
        }

        capacity = std::min(capacity, MAX_SKETCH_CAPACITY);
        sketch = Minisketch(RECON_FIELD_SIZE, 0, capacity);
        if (sketch) {
            for (const uint32_t short_id: short_ids) {
                sketch.Add(short_id);
            }
        }
        return sketch;
    }

    /**
     * After a reconciliation round passed, transactions missing by our peer are known by short ID.
     * Look up their full wtxid locally to announce them to the peer.
     */
    std::vector<uint256> GetWTXIDsFromShortIDs(const std::vector<uint32_t>& remote_missing_short_ids) const
    {
        std::vector<uint256> remote_missing;
        for (const auto& missing_short_id: remote_missing_short_ids) {
            const auto local_tx = m_local_short_id_mapping.find(missing_short_id);
            if (local_tx != m_local_short_id_mapping.end()) {
                remote_missing.push_back(local_tx->second);
            }
        }
        return remote_missing;
    }

    /**
     * Once we are fully done with the incoming reconciliation, prepare the state for the following
     * reconciliations in the same direction.
     */
    void FinalizeIncomingReconciliation()
    {
        assert(!m_we_initiate);
        m_local_short_id_mapping.clear();
    }

    /**
     * When during reconciliation we find a set difference successfully (by combining sketches),
     * we want to find which transactions are missing on our and on their side.
     * For those missing on our side, we may only find short IDs.
     */
    std::pair<std::vector<uint32_t>, std::vector<uint256>> GetRelevantIDsFromShortIDs(const std::vector<uint64_t>& diff) const
    {
        std::vector<uint32_t> local_missing;
        std::vector<uint256> remote_missing;
        for (const auto& diff_short_id: diff) {
            const auto local_tx = m_local_short_id_mapping.find(diff_short_id);
            if (local_tx != m_local_short_id_mapping.end()) {
                remote_missing.push_back(local_tx->second);
            } else {
                local_missing.push_back(diff_short_id);
            }
        }
        return std::make_pair(local_missing, remote_missing);
    }
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl {

    mutable Mutex m_mutex;

    /**
     * Salt used to compute short IDs during transaction reconciliation.
     * Salt is generated randomly per-connection to prevent linking of
     * connections belonging to the same physical node.
     * Also, salts should be different per-connection to prevent halting
     * of relay of particular transactions due to collisions in short IDs.
     */
    std::unordered_map<NodeId, uint64_t> m_local_salts GUARDED_BY(m_mutex);

    /**
     * Used to keep track of ongoing reconciliations per peer.
     */
    std::unordered_map<NodeId, ReconciliationState> m_states GUARDED_BY(m_mutex);

    /**
     * Reconciliation should happen with peers in the same order, because the efficiency gain is the
     * highest when reconciliation set difference is predictable. This queue is used to maintain the
     * order of peers chosen for reconciliation.
     */
    std::deque<NodeId> m_queue GUARDED_BY(m_mutex);

    /**
     * Reconciliations are requested periodically:
     * every RECON_REQUEST_INTERVAL seconds we pick a peer from the queue.
     */
    std::chrono::microseconds m_next_recon_request{0};
    void UpdateNextReconRequest(std::chrono::microseconds now) EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        m_next_recon_request = now + RECON_REQUEST_INTERVAL / m_queue.size();
    }

    /**
     * Used to schedule the next initial response for any pending reconciliation request.
     * Respond to all requests at the same time to prevent transaction possession leak.
     */
    std::chrono::microseconds m_next_recon_respond{0};
    std::chrono::microseconds NextReconRespond()
    {
        auto current_time = GetTime<std::chrono::microseconds>();
        if (m_next_recon_respond < current_time) {
            m_next_recon_respond = current_time + RECON_RESPONSE_INTERVAL;
        }
        return m_next_recon_respond;
    }

    public:

    std::tuple<bool, bool, uint32_t, uint64_t> SuggestReconciling(const NodeId peer_id, bool inbound)
    {
        bool we_initiate_recon, we_respond_recon;
        // Currently reconciliation requests flow only in one direction inbound->outbound.
        if (inbound) {
            we_initiate_recon = false;
            we_respond_recon = true;
        } else {
            we_initiate_recon = true;
            we_respond_recon = false;
        }

        uint64_t m_local_recon_salt(GetRand(UINT64_MAX));
        WITH_LOCK(m_mutex, m_local_salts.emplace(peer_id, m_local_recon_salt));

        return std::make_tuple(we_initiate_recon, we_respond_recon, RECON_VERSION, m_local_recon_salt);
    }

    bool EnableReconciliationSupport(const NodeId peer_id, bool inbound,
        bool they_may_initiate, bool they_may_respond, uint32_t recon_version, uint64_t remote_salt,
        size_t outbound_flooders)
    {
        // Do not support reconciliation salt/version updates
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state != m_states.end()) return false;

        recon_version = std::min(recon_version, RECON_VERSION);
        if (recon_version < 1) return false;

        /* must match announcement logic */
        bool we_may_initiate = !inbound, we_may_respond = inbound;

        bool they_initiate = they_may_initiate && we_may_respond;
        bool we_initiate = we_may_initiate && they_may_respond;
        // If we ever announce us_sender && us_responder, this will need tie-breaking. For now,
        // this is mutually exclusive because of the inbound flag.
        assert(!(they_initiate && we_initiate));

        if (!(they_initiate || we_initiate)) return false;

        // Among reconciliation-enabled peers, flood only through a limited number of outbound
        // connections to save bandwidth.
        bool flood_to = !inbound && outbound_flooders < MAX_OUTBOUND_FLOOD_TO;

        // Reconcile with all outbound peers supporting reconciliation (even if we flood to them),
        // to not miss transactions they have for us but won't flood.
        if (we_initiate) {
            m_queue.push_back(peer_id);
        }

        uint256 full_salt = ComputeSalt(m_local_salts.at(peer_id), remote_salt);

        m_states.emplace(peer_id, ReconciliationState(we_initiate, flood_to,
            full_salt.GetUint64(0), full_salt.GetUint64(1)));
        return true;
    }

    bool IsPeerRegistered(const NodeId peer_id) const
    {
        LOCK(m_mutex);
        return m_states.find(peer_id) != m_states.end();
    }

    std::optional<bool> IsPeerChosenForFlooding(const NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return (*recon_state).second.m_flood_to;
    }

    void RemovePeer(const NodeId peer_id)
    {
        LOCK(m_mutex);
        m_queue.erase(std::remove(m_queue.begin(), m_queue.end(), peer_id), m_queue.end());
        m_local_salts.erase(peer_id);
        m_states.erase(peer_id);
    }

    std::optional<bool> IsPeerResponder(const NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return (*recon_state).second.m_we_initiate;
    }

    std::optional<size_t> GetPeerSetSize(const NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return (*recon_state).second.m_local_set.size();
    }

    void StoreTxsToAnnounce(const NodeId peer_id,
        const std::vector<uint256>& txs_to_reconcile)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        assert(recon_state != m_states.end());
        for (auto& wtxid: txs_to_reconcile) {
            recon_state->second.m_local_set.insert(wtxid);
        }
    }

    std::optional<std::pair<uint16_t, uint16_t>> MaybeRequestReconciliation(const NodeId peer_id)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return std::nullopt;
        if (recon_state->second.m_outgoing_recon != RECON_NONE) return std::nullopt;

        if (m_queue.size() > 0) {
            // Request transaction reconciliation periodically to efficiently exchange transactions.
            // To make reconciliation predictable and efficient, we reconcile with peers in order based on the queue,
            // and with a delay between requests.
            auto current_time = GetTime<std::chrono::seconds>();
            if (m_next_recon_request < current_time && m_queue.back() == peer_id) {
                recon_state->second.m_outgoing_recon = RECON_INIT_REQUESTED;
                m_queue.pop_back();
                m_queue.push_front(peer_id);
                UpdateNextReconRequest(current_time);
                return std::make_pair(recon_state->second.m_local_set.size(), recon_state->second.m_local_q * Q_PRECISION);
            }
        }
        return std::nullopt;
    }

    void HandleReconciliationRequest(const NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q)
    {
        double peer_q_converted = double(peer_q * Q_PRECISION);
        if (peer_q_converted < 0 || peer_q_converted > 2) return;

        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return;
        if (recon_state->second.m_incoming_recon != RECON_NONE) return;
        if (recon_state->second.m_we_initiate) return;

        recon_state->second.m_remote_q = peer_q;
        recon_state->second.m_remote_set_size = peer_recon_set_size;
        recon_state->second.m_next_recon_respond = NextReconRespond();
        recon_state->second.m_incoming_recon = RECON_INIT_REQUESTED;
    }

    std::optional<std::vector<uint8_t>> MaybeRespondToReconciliationRequest(const NodeId peer_id)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return std::nullopt;
        if (recon_state->second.m_we_initiate) return std::nullopt;
        // Respond to a requested reconciliation to enable efficient transaction exchange.
        // For initial requests, respond only periodically to a) limit CPU usage for sketch computation,
        // and, b) limit transaction possession privacy leak.
        // It's safe to respond to extension request without a delay because they are already limited by initial requests.

        auto current_time = GetTime<std::chrono::microseconds>();

        auto incoming_phase = recon_state->second.m_incoming_recon;
        bool timely_initial_request = incoming_phase == RECON_INIT_REQUESTED && current_time > recon_state->second.m_next_recon_respond;
        if (!timely_initial_request) {
            return std::nullopt;
        }

        std::vector<unsigned char> response_skdata;
        uint16_t sketch_capacity = recon_state->second.EstimateSketchCapacity();
        Minisketch sketch = recon_state->second.ComputeSketch(sketch_capacity);
        recon_state->second.m_incoming_recon = RECON_INIT_RESPONDED;
        if (sketch) response_skdata = sketch.Serialize();
        return response_skdata;
    }

    std::vector<uint256> FinalizeIncomingReconciliation(const NodeId peer_id, bool recon_result,
        const std::vector<uint32_t>& ask_shortids)
    {
        std::vector<uint256> remote_missing;
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return remote_missing;

        assert(!recon_state->second.m_we_initiate);
        const auto incoming_phase = recon_state->second.m_incoming_recon;
        const bool phase_init_responded = incoming_phase == RECON_INIT_RESPONDED;

        if (!phase_init_responded) return remote_missing;

        if (recon_result) {
            remote_missing = recon_state->second.GetWTXIDsFromShortIDs(ask_shortids);
        } else {
            remote_missing = std::vector<uint256>(recon_state->second.m_local_set.begin(), recon_state->second.m_local_set.end());
        }
        recon_state->second.FinalizeIncomingReconciliation();
        recon_state->second.m_incoming_recon = RECON_NONE;
        return remote_missing;
    }

    std::optional<std::tuple<bool, std::vector<uint32_t>, std::vector<uint256>>> HandleSketch(
        const NodeId peer_id, int common_version, std::vector<uint8_t>& skdata)
    {
        if (skdata.size() / BYTES_PER_SKETCH_CAPACITY > MAX_SKETCH_CAPACITY) {
            return std::nullopt;
        }

        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return std::nullopt;

        // We only may receive a sketch from reconciliation responder, not initiator.
        assert(recon_state->second.m_we_initiate);

        const auto outgoing_phase = recon_state->second.m_outgoing_recon;
        const bool phase_init_requested = outgoing_phase == RECON_INIT_REQUESTED;

        if (!phase_init_requested) return std::nullopt;

        Minisketch remote_sketch;
        uint16_t remote_sketch_capacity = 0;
        auto parsed_remote_sketch = ParseRemoteSketch(skdata);
        if (parsed_remote_sketch) {
            remote_sketch = (*parsed_remote_sketch).first;
            remote_sketch_capacity = (*parsed_remote_sketch).second;
        }

        Minisketch local_sketch = recon_state->second.ComputeSketch(remote_sketch_capacity);

        if (remote_sketch_capacity == 0 || !remote_sketch || !local_sketch) {
            LogPrint(BCLog::NET, "Outgoing reconciliation failed due to %s \n",
                remote_sketch_capacity == 0 ? "empty sketch" : "minisketch API failure");
            std::vector<uint256> remote_missing = std::vector<uint256>(recon_state->second.m_local_set.begin(), recon_state->second.m_local_set.end());
            recon_state->second.FinalizeOutgoingReconciliation(true, DEFAULT_RECON_Q);
            recon_state->second.m_outgoing_recon = RECON_NONE;
            return std::make_tuple(false, std::vector<uint32_t>(), remote_missing);
        }

        assert(remote_sketch);
        assert(local_sketch);
        // Attempt to decode the set difference
        std::vector<uint64_t> differences(remote_sketch_capacity);
        if (local_sketch.Merge(remote_sketch).Decode(differences)) {
            // Reconciliation over the current working sketch succeeded
            LogPrint(BCLog::NET, "Outgoing reconciliation succeeded\n");
            auto missing_txs = recon_state->second.GetRelevantIDsFromShortIDs(differences);
            std::vector<uint32_t> local_missing = missing_txs.first;
            std::vector<uint256> remote_missing = missing_txs.second;

            size_t local_set_size = recon_state->second.m_local_set.size();
            recon_state->second.FinalizeOutgoingReconciliation(true, RecomputeQ(local_set_size, local_missing.size(), remote_missing.size()));
            recon_state->second.m_outgoing_recon = RECON_NONE;
            return std::make_tuple(true, local_missing, remote_missing);
        } else {
            // Reconciliation over the current working sketch failed.
            // TODO handle failure.
            return std::nullopt;
        }
    }

};

TxReconciliationTracker::TxReconciliationTracker() :
    m_impl{std::make_unique<TxReconciliationTracker::Impl>()} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

std::tuple<bool, bool, uint32_t, uint64_t> TxReconciliationTracker::SuggestReconciling(const NodeId peer_id, bool inbound)
{
    return m_impl->SuggestReconciling(peer_id, inbound);
}

bool TxReconciliationTracker::EnableReconciliationSupport(const NodeId peer_id, bool inbound,
    bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt,
    size_t outbound_flooders)
{
    return m_impl->EnableReconciliationSupport(peer_id, inbound, recon_requestor, recon_responder,
        recon_version, remote_salt, outbound_flooders);
}

bool TxReconciliationTracker::IsPeerRegistered(const NodeId peer_id) const
{
    return m_impl->IsPeerRegistered(peer_id);
}

std::optional<bool> TxReconciliationTracker::IsPeerChosenForFlooding(const NodeId peer_id) const
{
    return m_impl->IsPeerChosenForFlooding(peer_id);
}

void TxReconciliationTracker::RemovePeer(const NodeId peer_id)
{
    m_impl->RemovePeer(peer_id);
}

std::optional<bool> TxReconciliationTracker::IsPeerResponder(const NodeId peer_id) const
{
    return m_impl->IsPeerResponder(peer_id);
}

std::optional<size_t> TxReconciliationTracker::GetPeerSetSize(const NodeId peer_id) const
{
    return m_impl->GetPeerSetSize(peer_id);
}

void TxReconciliationTracker::StoreTxsToAnnounce(const NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
{
    m_impl->StoreTxsToAnnounce(peer_id, txs_to_reconcile);
}

std::optional<std::pair<uint16_t, uint16_t>> TxReconciliationTracker::MaybeRequestReconciliation(const NodeId peer_id)
{
    return m_impl->MaybeRequestReconciliation(peer_id);
}

void TxReconciliationTracker::HandleReconciliationRequest(const NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q)
{
    m_impl->HandleReconciliationRequest(peer_id, peer_recon_set_size, peer_q);
}

std::optional<std::vector<uint8_t>> TxReconciliationTracker::MaybeRespondToReconciliationRequest(const NodeId peer_id)
{
    return m_impl->MaybeRespondToReconciliationRequest(peer_id);
}

std::vector<uint256> TxReconciliationTracker::FinalizeIncomingReconciliation(const NodeId peer_id,
    bool recon_result, const std::vector<uint32_t>& ask_shortids)
{
    return m_impl->FinalizeIncomingReconciliation(peer_id, recon_result, ask_shortids);
}

std::optional<std::tuple<bool, std::vector<uint32_t>, std::vector<uint256>>> TxReconciliationTracker::HandleSketch(
    const NodeId peer_id, int common_version, std::vector<uint8_t>& skdata)
{
    return m_impl->HandleSketch(peer_id, common_version, skdata);
}
