// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txreconciliation.h>

#include <minisketch/include/minisketch.h>

namespace {

/** Current protocol version */
constexpr uint32_t RECON_VERSION = 1;
/** Static component of the salt used to compute short txids for inclusion in sketches. */
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
/** Default value for the coefficient used to estimate reconciliation set differences. */
constexpr double DEFAULT_RECON_Q = 0.02;
/**
  * Used to convert a floating point reconciliation coefficient q to integer for transmission.
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
 * Interval between initiating reconciliations with a given peer.
 * This value allows to reconcile ~100 transactions (7 tx/s * 16s) during normal system operation.
 * More frequent reconciliations would cause significant constant bandwidth overhead
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
 * Salt is specified by BIP-330 is constructed from contributions from both peers. It is later used
 * to compute transaction short IDs, which are needed to construct a sketch representing a set of
 * transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t local_salt, uint64_t remote_salt)
{
    uint64_t salt1 = local_salt, salt2 = remote_salt;
    if (salt1 > salt2) std::swap(salt1, salt2);
    static const auto RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);
    return (CHashWriter(RECON_SALT_HASHER) << salt1 << salt2).GetSHA256();
}

/**
 * Track ongoing reconciliations with a giving peer which were initiated by us.
 */
struct ReconciliationInitByUs {
    /**
     * Computing a set reconciliation sketch involves estimating the difference
     * between sets of transactions on two sides of the connection. More specifically,
     * a sketch capacity is computed as
     * |set_size - local_set_size| + q * (set_size + local_set_size) + c,
     * where c is a small constant, and q is a node+connection-specific coefficient.
     * This coefficient is recomputed by every node based on the previous reconciliations,
     * to better estimate future set size differences.
     */
    double m_local_q{DEFAULT_RECON_Q};

    /** Keep track of the reconciliation phase with the peer. */
    ReconciliationPhase m_phase{RECON_NONE};
};

/**
 * Track ongoing reconciliations with a giving peer which were initiated by them.
 */
struct ReconciliationInitByThem {
    /**
     * The use of q coefficients is described above (see local_q comment).
     * The value transmitted from the peer with a reconciliation requests is stored here until
     * we respond to that request with a sketch.
     */
    double m_remote_q{DEFAULT_RECON_Q};

    /**
     * A reconciliation request comes from a peer with a reconciliation set size from their side,
     * which is supposed to help us to estimate set difference size. The value is stored here until
     * we respond to that request with a sketch.
     */
    uint16_t m_remote_set_size;

    /**
     * When a reconciliation request is received, instead of responding to it right away,
     * we schedule a response for later, so that a spy can’t monitor our reconciliation sets.
     */
    std::chrono::microseconds m_next_recon_respond{0};

    /** Keep track of the reconciliation phase with the peer. */
    ReconciliationPhase m_phase{RECON_NONE};

    /**
     * Estimate a capacity of a sketch we will send or use locally (to find set difference)
     * based on the local set size.
     */
    uint16_t EstimateSketchCapacity(size_t local_set_size) const
    {
        const uint16_t set_size_diff = std::abs(uint16_t(local_set_size) - m_remote_set_size);
        const uint16_t min_size = std::min(uint16_t(local_set_size), m_remote_set_size);
        const uint16_t weighted_min_size = m_remote_q * min_size;
        const uint16_t estimated_diff = 1 + weighted_min_size + set_size_diff;
        return minisketch_compute_capacity(RECON_FIELD_SIZE, estimated_diff, RECON_FALSE_POSITIVE_COEF);
    }
};

/**
 * After a reconciliation round is over, the local q coefficient may be adjusted to enable
 * better accuracy of future set difference estimations.
 */
double RecomputeQ(uint8_t local_set_size, uint8_t actual_local_missing, uint8_t actual_remote_missing)
{
    uint8_t remote_set_size = local_set_size + actual_local_missing - actual_remote_missing;
    uint8_t set_size_diff = std::abs(local_set_size - remote_set_size);
    uint8_t min_size = std::min(local_set_size, remote_set_size);
    uint8_t actual_difference = actual_local_missing + actual_remote_missing;
    if (min_size != 0) {
        double result = double(actual_difference - set_size_diff) / min_size;
        assert(result >= 0 && result <= 2);
        return result;
    }
    return DEFAULT_RECON_Q;
}

/**
 * Used to keep track of the ongoing reconciliations, the transactions we want to announce to the
 * peer when next transaction reconciliation happens, and also all parameters required to perform
 * reconciliations.
 */
class ReconciliationState {
    friend TxReconciliationTracker;

    /**
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches). This defines our role.
     * */
    const bool m_we_initiate;

    /**
     * We flood specific transactions to some of the peers we reconcile with to enable faster
     * transaction relay while still conserving bandwidth by reconciling in most of the cases.
     * More specifically, we flood to a limited number of outbound reconciling peers
     * *for which this flag is enabled* (and also to non-reconciling peers, although this is
     * irrelevant here).
     * This flag is enabled based on whether we have a sufficient number of outbound transaction
     * relay peers already.
     * Transactions announced via flooding should not be added to the reconciliation set.
     */
    const bool m_flood_to;

    /**
     * Reconciliation involves exchanging sketches, which efficiently represent transactions each
     * peer wants to announce. Sketches are computed over transaction short IDs.
     * These values are used to salt short IDs.
     */
    const uint64_t m_k0, m_k1;

    /**
     * Store all transactions which we would relay to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute an efficient representation of this set ("sketch") and use it to efficient reconcile
     * this set with a similar set on the other side of the connection.
     */
    std::set<uint256> m_local_set;

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * This is a cache of these IDs enabling faster lookups of full wtxids,
     * useful when peer will ask for missing transactions by short IDs
     * at the end of a reconciliation round.
     */
    std::map<uint32_t, uint256> m_local_short_id_mapping;

    /** Keep track of reconciliations with the peer. */
    ReconciliationInitByUs m_state_init_by_us;
    ReconciliationInitByThem m_state_init_by_them;

    ReconciliationState(bool we_initiate, bool flood_to, uint64_t k0, uint64_t k1) :
        m_we_initiate(we_initiate), m_flood_to(flood_to),
        m_k0(k0), m_k1(k1) {}

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
     * When during reconciliation we find a set difference successfully (by combining sketches),
     * we want to find which transactions are missing on our and on their side.
     * For those missing on our side, we may only find short IDs.
     */
    void GetRelevantIDsFromShortIDs(const std::vector<uint64_t>& diff,
        // returning values
        std::vector<uint32_t>& local_missing, std::vector<uint256>& remote_missing) const
    {
        for (const auto& diff_short_id: diff) {
            const auto local_tx = m_local_short_id_mapping.find(diff_short_id);
            if (local_tx != m_local_short_id_mapping.end()) {
                remote_missing.push_back(local_tx->second);
            } else {
                local_missing.push_back(diff_short_id);
            }
        }
    }

    /**
     * Once we are fully done with the reconciliation we initiated, prepare the state for the
     * following reconciliations we initiate.
     */
    void FinalizeInitByUs(bool clear_local_set, double updated_q)
    {
        assert(m_we_initiate);
        m_state_init_by_us.m_local_q = updated_q;
        if (clear_local_set) m_local_set.clear();
    }
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl {

    mutable Mutex m_mutex;

    /**
     * Per-peer salt is used to compute transaction short IDs, which will be later used to
     * construct reconciliation sketches.
     * Salt is generated randomly per-peer to prevent:
     * - linking of network nodes belonging to the same physical node
     * - halting of relay of particular transactions due to short ID collisions (DoS)
     */
    std::unordered_map<NodeId, uint64_t> m_local_salts GUARDED_BY(m_mutex);

    /**
     * Keeps track of ongoing reconciliations with a given peer.
     */
    std::unordered_map<NodeId, ReconciliationState> m_states GUARDED_BY(m_mutex);

    /**
     * Maintains a queue of reconciliations we should initiate. To achieve higher bandwidth
     * conservation and avoid overflows, we should reconcile in the same order, because then it’s
     * easier to estimate set differene size.
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

    std::tuple<bool, bool, uint32_t, uint64_t> SuggestReconciling(NodeId peer_id, bool inbound)
    {
        LogPrint(BCLog::NET, "Prepare to announce reconciliation support to peer=%d\n", peer_id);
        bool we_initiate_recon, we_respond_recon;
        // Currently reconciliation roles are defined by the connection direction: only the inbound
        // peer initiate reconciliations and the outbound peer is supposed to only respond.
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

    void EnableReconciliationSupport(NodeId peer_id, bool inbound,
        bool they_may_initiate, bool they_may_respond, uint32_t recon_version, uint64_t remote_salt,
        size_t outbound_flooders)
    {
        // We do not support reconciliation salt/version updates, so receiving this message
        // for the second time should not happen
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state != m_states.end()) return;

        recon_version = std::min(recon_version, RECON_VERSION);
        if (recon_version < 1) return;

        // Must match SuggestReconciliation logic.
        bool we_may_initiate = !inbound, we_may_respond = inbound;

        bool they_initiate = they_may_initiate && we_may_respond;
        bool we_initiate = we_may_initiate && they_may_respond;
        // If we ever announce we_initiate && we_may_respond, this will need tie-breaking. For now,
        // this is mutually exclusive because both are based on the inbound flag.
        assert(!(they_initiate && we_initiate));

        if (!(they_initiate || we_initiate)) return;

        if (we_initiate) {
            m_queue.push_back(peer_id);
        }

        // To save bandwidth, we never flood to inbound peers we reconcile with. We may flood *some*
        // transactions to a limited number outbound peers we reconcile with.
        bool flood_to = !inbound && outbound_flooders < MAX_OUTBOUND_FLOOD_TO;

        LogPrint(BCLog::NET, "Register peer=%d for reconciliation with the following params: "
            "we_initiate=%i, they_initiate=%i, flood_to=%i\n", peer_id, we_initiate, they_initiate, flood_to);

        uint256 full_salt = ComputeSalt(m_local_salts.at(peer_id), remote_salt);

        m_states.emplace(peer_id, ReconciliationState(we_initiate, flood_to,
            full_salt.GetUint64(0), full_salt.GetUint64(1)));
    }

    void StoreTxsToAnnounce(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        assert(recon_state != m_states.end());
        for (auto& wtxid: txs_to_reconcile) {
            recon_state->second.m_local_set.insert(wtxid);
        }
    }

    std::optional<std::pair<uint16_t, uint16_t>> MaybeRequestReconciliation(NodeId peer_id)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return std::nullopt;
        if (recon_state->second.m_state_init_by_us.m_phase != RECON_NONE) return std::nullopt;

        if (m_queue.size() > 0) {
            // Request transaction reconciliation periodically to efficiently exchange transactions.
            // To make reconciliation predictable and efficient, we reconcile with peers in order based on the queue,
            // and with a delay between requests.
            auto current_time = GetTime<std::chrono::seconds>();
            if (m_next_recon_request < current_time && m_queue.back() == peer_id) {
                recon_state->second.m_state_init_by_us.m_phase = RECON_INIT_REQUESTED;
                m_queue.pop_back();
                m_queue.push_front(peer_id);
                UpdateNextReconRequest(current_time);
                size_t local_set_size = recon_state->second.m_local_set.size();
                double local_q = recon_state->second.m_state_init_by_us.m_local_q;
                LogPrint(BCLog::NET, "Initiate reconciliation with peer=%d with the following params: "
                    "local_set_size=%i, local_q=%i\n", peer_id, local_set_size, local_q);
                return std::make_pair(local_set_size, local_q * Q_PRECISION);
            }
        }
        return std::nullopt;
    }

    void HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q)
    {
        double peer_q_converted = double(peer_q * Q_PRECISION);
        if (peer_q_converted < 0 || peer_q_converted > 2) return;

        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return;
        if (recon_state->second.m_state_init_by_them.m_phase != RECON_NONE) return;
        if (recon_state->second.m_we_initiate) return;

        recon_state->second.m_state_init_by_them.m_remote_q = peer_q_converted;
        recon_state->second.m_state_init_by_them.m_remote_set_size = peer_recon_set_size;
        recon_state->second.m_state_init_by_them.m_next_recon_respond = NextReconRespond();
        recon_state->second.m_state_init_by_them.m_phase = RECON_INIT_REQUESTED;
        LogPrint(BCLog::NET, "Reconciliation initiated by peer=%d with the following params: "
            "remote_q=%d, remote_set_size=%i\n", peer_id, peer_q_converted, peer_recon_set_size);
    }

    bool RespondToReconciliationRequest(NodeId peer_id, std::vector<uint8_t>& skdata)
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return false;
        if (recon_state->second.m_we_initiate) return false;

        ReconciliationPhase incoming_phase = recon_state->second.m_state_init_by_them.m_phase;

        // For initial requests, respond only periodically to a) limit CPU usage for sketch computation,
        // and, b) limit transaction possession privacy leak.
        auto current_time = GetTime<std::chrono::microseconds>();
        bool timely_initial_request = incoming_phase == RECON_INIT_REQUESTED &&
            current_time > recon_state->second.m_state_init_by_them.m_next_recon_respond;
        if (!timely_initial_request) {
            return false;
        }

        // Compute a sketch over the local reconciliation set.
        uint16_t sketch_capacity = recon_state->second.m_state_init_by_them.EstimateSketchCapacity(
            recon_state->second.m_local_set.size());
        Minisketch sketch = recon_state->second.ComputeSketch(sketch_capacity);

        recon_state->second.m_state_init_by_them.m_phase = RECON_INIT_RESPONDED;
        if (sketch) skdata = sketch.Serialize();
        LogPrint(BCLog::NET, "Responding with a sketch to reconciliation initiated by peer=%d: "
            "sending sketch of capacity=%i\n", peer_id, sketch_capacity);
        return true;
    }

    bool HandleSketch(NodeId peer_id, const std::vector<uint8_t>& skdata,
        // returning values
        std::vector<uint32_t>& txs_to_request, std::vector<uint256>& txs_to_announce, bool& result)
    {
        uint16_t remote_sketch_capacity = uint16_t(skdata.size() / BYTES_PER_SKETCH_CAPACITY);
        // Protocol violation: our peer exceeded the sketch capacity, or sent a malformed sketch.
        if (remote_sketch_capacity > MAX_SKETCH_CAPACITY) {
            return false;
        }

        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) return false;

        // We only may receive a sketch from reconciliation responder, not initiator.
        assert(recon_state->second.m_we_initiate);

        ReconciliationPhase outgoing_phase = recon_state->second.m_state_init_by_us.m_phase;
        bool phase_init_requested = outgoing_phase == RECON_INIT_REQUESTED;

        if (!phase_init_requested) return false;

        Minisketch local_sketch = recon_state->second.ComputeSketch(remote_sketch_capacity);
        Minisketch remote_sketch;
        if (remote_sketch_capacity != 0) {
            remote_sketch = Minisketch(RECON_FIELD_SIZE, 0, remote_sketch_capacity).Deserialize(skdata);
        }

        // Early exit due to empty sketch or API failure.
        if (remote_sketch_capacity == 0 || !remote_sketch || !local_sketch) {
            LogPrint(BCLog::NET, "Reconciliation we initiated with peer=%d terminated due to %s \n", peer_id,
                remote_sketch_capacity == 0 ? "empty sketch" : "minisketch API failure");

            // Announce all transactions we have.
            txs_to_announce.assign(recon_state->second.m_local_set.begin(), recon_state->second.m_local_set.end());

            // Update local reconciliation state for the peer.
            recon_state->second.FinalizeInitByUs(true, DEFAULT_RECON_Q);
            recon_state->second.m_state_init_by_us.m_phase = RECON_NONE;

            result = false;
            return true;
        }

        assert(remote_sketch);
        assert(local_sketch);
        // Attempt to decode the set difference
        std::vector<uint64_t> differences(remote_sketch_capacity);
        if (local_sketch.Merge(remote_sketch).Decode(differences)) {
            // Initial reconciliation step succeeded.

            // Identify locally/remotely missing transactions.
            recon_state->second.GetRelevantIDsFromShortIDs(differences, txs_to_request, txs_to_announce);

            // Update local reconciliation state for the peer.
            size_t local_set_size = recon_state->second.m_local_set.size();
            recon_state->second.FinalizeInitByUs(true,
                RecomputeQ(local_set_size, txs_to_request.size(), txs_to_announce.size()));
            recon_state->second.m_state_init_by_us.m_phase = RECON_NONE;

            result = true;
            LogPrint(BCLog::NET, "Reconciliation we initiated with peer=%d has succeeded at initial step, "
                "request %i txs, announce %i txs \n", peer_id, txs_to_request.size(), txs_to_announce.size());
        } else {
            // Initial reconciliation step failed.
            // TODO handle failure.
            result = false;
        }
        return true;
    }

    void RemovePeer(NodeId peer_id)
    {
        LogPrint(BCLog::NET, "Stop tracking reconciliation state for peer=%d\n", peer_id);
        LOCK(m_mutex);
        m_local_salts.erase(peer_id);
        m_states.erase(peer_id);
        m_queue.erase(std::remove(m_queue.begin(), m_queue.end(), peer_id), m_queue.end());
    }

    bool IsPeerRegistered(NodeId peer_id) const
    {
        LOCK(m_mutex);
        return m_states.find(peer_id) != m_states.end();
    }

    std::optional<bool> IsPeerChosenForFlooding(NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return (*recon_state).second.m_flood_to;
    }

    std::optional<bool> IsPeerResponder(NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return (*recon_state).second.m_we_initiate;
    }

    std::optional<size_t> GetPeerSetSize(NodeId peer_id) const
    {
        LOCK(m_mutex);
        auto recon_state = m_states.find(peer_id);
        if (recon_state == m_states.end()) {
            return std::nullopt;
        }
        return (*recon_state).second.m_local_set.size();
    }

};

TxReconciliationTracker::TxReconciliationTracker() :
    m_impl{std::make_unique<TxReconciliationTracker::Impl>()} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

std::tuple<bool, bool, uint32_t, uint64_t> TxReconciliationTracker::SuggestReconciling(NodeId peer_id, bool inbound)
{
    return m_impl->SuggestReconciling(peer_id, inbound);
}

void TxReconciliationTracker::EnableReconciliationSupport(NodeId peer_id, bool inbound,
    bool recon_requestor, bool recon_responder, uint32_t recon_version, uint64_t remote_salt,
    size_t outbound_flooders)
{
    m_impl->EnableReconciliationSupport(peer_id, inbound, recon_requestor, recon_responder,
        recon_version, remote_salt, outbound_flooders);
}

void TxReconciliationTracker::StoreTxsToAnnounce(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
{
    m_impl->StoreTxsToAnnounce(peer_id, txs_to_reconcile);
}

std::optional<std::pair<uint16_t, uint16_t>> TxReconciliationTracker::MaybeRequestReconciliation(NodeId peer_id)
{
    return m_impl->MaybeRequestReconciliation(peer_id);
}

void TxReconciliationTracker::HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q)
{
    m_impl->HandleReconciliationRequest(peer_id, peer_recon_set_size, peer_q);
}

bool TxReconciliationTracker::RespondToReconciliationRequest(NodeId peer_id, std::vector<uint8_t>& skdata)
{
    return m_impl->RespondToReconciliationRequest(peer_id, skdata);
}

bool TxReconciliationTracker::HandleSketch(NodeId peer_id, const std::vector<uint8_t>& skdata,
    std::vector<uint32_t>& txs_to_request, std::vector<uint256>& txs_to_announce, bool& result)
{
    return m_impl->HandleSketch(peer_id, skdata, txs_to_request, txs_to_announce, result);
}

void TxReconciliationTracker::RemovePeer(NodeId peer_id)
{
    m_impl->RemovePeer(peer_id);
}

bool TxReconciliationTracker::IsPeerRegistered(NodeId peer_id) const
{
    return m_impl->IsPeerRegistered(peer_id);
}

std::optional<bool> TxReconciliationTracker::IsPeerChosenForFlooding(NodeId peer_id) const
{
    return m_impl->IsPeerChosenForFlooding(peer_id);
}

std::optional<bool> TxReconciliationTracker::IsPeerResponder(NodeId peer_id) const
{
    return m_impl->IsPeerResponder(peer_id);
}

std::optional<size_t> TxReconciliationTracker::GetPeerSetSize(NodeId peer_id) const
{
    return m_impl->GetPeerSetSize(peer_id);
}
