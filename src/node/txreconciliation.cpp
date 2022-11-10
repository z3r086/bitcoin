// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>

#include <util/check.h>
#include <util/hasher.h>
#include <util/system.h>

#include <cmath>
#include <unordered_map>
#include <variant>


namespace {

/** Static salt component used to compute short txids for sketch construction, see BIP-330. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";
const HashWriter RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);

/**
 * Announce transactions via full wtxid to a limited number of inbound and outbound peers.
 * Justification for these values are provided here:
 * https://github.com/naumenkogs/txrelaysim/issues/7#issuecomment-902165806 */
constexpr double INBOUND_FANOUT_DESTINATIONS_FRACTION = 0.1;
constexpr double OUTBOUND_FANOUT_DESTINATIONS = 1;
/**
 * If there's a chance a transaction is not streamlined along the first couple hops, it would take
 *  very long to relay.
 */
static_assert(OUTBOUND_FANOUT_DESTINATIONS >= 1);

/**
 * A floating point coefficient q for estimating reconciliation set difference, and
 * the value used to convert it to integer for transmission purposes, as specified in BIP-330.
 */
constexpr double Q = 0.25;
constexpr uint16_t Q_PRECISION{(2 << 14) - 1};
/**
 * Interval between initiating reconciliations with peers.
 * This value allows to reconcile ~(7 tx/s * 8s) transactions during normal operation.
 * More frequent reconciliations would cause significant constant bandwidth overhead
 * due to reconciliation metadata (sketch sizes etc.), which would nullify the efficiency.
 * Less frequent reconciliations would introduce high transaction relay latency.
 */
constexpr std::chrono::microseconds RECON_REQUEST_INTERVAL{8s};
/**
 * We should keep an interval between responding to reconciliation requests from the same peer,
 * to reduce potential DoS surface.
 */
constexpr std::chrono::microseconds RECON_RESPONSE_INTERVAL{1s};

/**
 * Represents phase of the current reconciliation round with a peer.
 */
enum class Phase {
    NONE,
    INIT_REQUESTED,
};

/**
 * Salt (specified by BIP-330) constructed from contributions from both peers. It is used
 * to compute transaction short IDs, which are then used to construct a sketch representing a set
 * of transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t salt1, uint64_t salt2)
{
    // According to BIP-330, salts should be combined in ascending order.
    return (HashWriter(RECON_SALT_HASHER) << std::min(salt1, salt2) << std::max(salt1, salt2)).GetSHA256();
}

/**
 * Keeps track of txreconciliation-related per-peer state.
 */
class TxReconciliationState
{
    /**
     * These values are used to salt short IDs, which is necessary for transaction reconciliations.
     */
    uint64_t m_k0, m_k1;

public:
    /**
     * TODO: This field is public to ignore -Wunused-private-field. Make private once used in
     * the following commits.
     *
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches). This defines our role,
     * based on the direction of the p2p connection.
     *
     */
    bool m_we_initiate;

    /**
     * Store all wtxids which we would announce to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute a compressed representation of this set ("sketch") and use it to efficiently
     * reconcile this set with a set on the peer's side.
     */
    std::set<uint256> m_local_set;

    /** Keep track of the reconciliation phase with the peer. */
    Phase m_phase{Phase::NONE};

    TxReconciliationState(bool we_initiate, uint64_t k0, uint64_t k1) : m_k0(k0), m_k1(k1), m_we_initiate(we_initiate) {}

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
     * The following fields are specific to only reconciliations initiated by the peer.
     */

    /**
     * The use of q coefficients is described above (see local_q comment).
     * The value transmitted from the peer with a reconciliation requests is stored here until
     * we respond to that request with a sketch.
     */
    double m_remote_q{Q};

    /**
     * A reconciliation request comes from a peer with a reconciliation set size from their side,
     * which is supposed to help us to estimate set difference size. The value is stored here until
     * we respond to that request with a sketch.
     */
    uint16_t m_remote_set_size;

    /**
     * We track when was the last time we responded to a reconciliation request by the peer,
     * so that we don't respond to them too often. This helps to reduce DoS surface.
     */
    std::chrono::microseconds m_last_init_recon_respond{0};
    /**
     * Returns whether at this time it's not too early to respond to a reconciliation request by
     * the peer, and, if so, bumps the time we last responded to allow further checks.
     */
    bool ConsiderInitResponseAndTrack()
    {
        auto current_time = GetTime<std::chrono::seconds>();
        if (m_last_init_recon_respond <= current_time - RECON_RESPONSE_INTERVAL) {
            m_last_init_recon_respond = current_time;
            return true;
        }
        return false;
    }
};

} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl
{
private:
    mutable Mutex m_txreconciliation_mutex;

    /**
     * We need a ReconciliationTracker-wide randomness to decide to which peers we should flood a
     * given transaction based on a (w)txid.
     */
    const SaltedTxidHasher txidHasher;

    // Local protocol version
    uint32_t m_recon_version;

    /**
     * Keeps track of txreconciliation states of eligible peers.
     * For pre-registered peers, the locally generated salt is stored.
     * For registered peers, the locally generated salt is forgotten, and the state (including
     * "full" salt) is stored instead.
     */
    std::unordered_map<NodeId, std::variant<uint64_t, TxReconciliationState>> m_states GUARDED_BY(m_txreconciliation_mutex);

    /**
     * Maintains a queue of reconciliations we should initiate. To achieve higher bandwidth
     * conservation and avoid overflows, we should reconcile in the same order, because then it’s
     * easier to estimate set difference size.
     */
    std::deque<NodeId> m_queue GUARDED_BY(m_txreconciliation_mutex);

    /**
     * Make reconciliation requests periodically to make reconciliations efficient.
     */
    std::chrono::microseconds m_next_recon_request GUARDED_BY(m_txreconciliation_mutex){0};
    void UpdateNextReconRequest(std::chrono::microseconds now) EXCLUSIVE_LOCKS_REQUIRED(m_txreconciliation_mutex)
    {
        // We have one timer for the entire queue. This is safe because we initiate reconciliations
        // with outbound connections, which are unlikely to game this timer in a serious way.
        size_t we_initiate_to_count = std::count_if(m_states.begin(), m_states.end(),
                                                    [](std::pair<NodeId, std::variant<uint64_t, TxReconciliationState>> indexed_state) {
                                                        const auto* cur_state = std::get_if<TxReconciliationState>(&indexed_state.second);
                                                        if (cur_state) return cur_state->m_we_initiate;
                                                        return false;
                                                    });

        Assert(we_initiate_to_count != 0);
        m_next_recon_request = now + (RECON_REQUEST_INTERVAL / we_initiate_to_count);
    }

public:
    explicit Impl(uint32_t recon_version) : m_recon_version(recon_version) {}

    uint64_t PreRegisterPeer(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Pre-register peer=%d\n", peer_id);
        const uint64_t local_salt{GetRand(UINT64_MAX)};

        // We do this exactly once per peer (which are unique by NodeId, see GetNewNodeId) so it's
        // safe to assume we don't have this record yet.
        Assume(m_states.emplace(peer_id, local_salt).second);
        return local_salt;
    }

    ReconciliationRegisterResult RegisterPeer(NodeId peer_id, bool is_peer_inbound, uint32_t peer_recon_version,
                                     uint64_t remote_salt) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);

        // A peer should be in the pre-registered state to proceed here.
        if (recon_state == m_states.end()) return ReconciliationRegisterResult::NOT_FOUND;
        uint64_t* local_salt = std::get_if<uint64_t>(&recon_state->second);
        // A peer is already registered. This should be checked by the caller.
        assert(local_salt);

        // If the peer supports the version which is lower than ours, we downgrade to the version
        // it supports. For now, this only guarantees that nodes with future reconciliation
        // versions have the choice of reconciling with this current version. However, they also
        // have the choice to refuse supporting reconciliations if the common version is not
        // satisfactory (e.g. too low).
        const uint32_t recon_version{std::min(peer_recon_version, m_recon_version)};
        // v1 is the lowest version, so suggesting something below must be a protocol violation.
        if (recon_version < 1) return ReconciliationRegisterResult::PROTOCOL_VIOLATION;

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Register peer=%d (inbound=%i)\n",
                      peer_id, is_peer_inbound);

        const uint256 full_salt{ComputeSalt(*local_salt, remote_salt)};
        recon_state->second = TxReconciliationState(!is_peer_inbound, full_salt.GetUint64(0), full_salt.GetUint64(1));
        m_queue.push_back(peer_id);
        return ReconciliationRegisterResult::SUCCESS;
    }

    void AddToSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        Assume(txs_to_reconcile.size() > 0);
        assert(IsPeerRegistered(peer_id));
        LOCK(m_txreconciliation_mutex);
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        size_t added = 0;
        for (auto& wtxid: txs_to_reconcile) {
            if (recon_state.m_local_set.insert(wtxid).second) {
                ++added;
            }
        }

        LogPrint(BCLog::NET, "Added %i new transactions to the reconciliation set for peer=%d. " /* Continued */
            "Now the set contains %i transactions.\n", added, peer_id, recon_state.m_local_set.size());
    }

    void TryRemovingFromSet(NodeId peer_id, const uint256& wtxid_to_remove) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        assert(IsPeerRegistered(peer_id));
        LOCK(m_txreconciliation_mutex);
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        recon_state.m_local_set.erase(wtxid_to_remove);
    }

    std::optional<std::pair<uint16_t, uint16_t>> MaybeRequestReconciliation(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        if (!IsPeerRegistered(peer_id)) return std::nullopt;
        LOCK(m_txreconciliation_mutex);
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        if (!recon_state.m_we_initiate) return std::nullopt;

        if (!m_queue.empty()) {
            // Request transaction reconciliation periodically to efficiently exchange transactions.
            // To make reconciliation predictable and efficient, we reconcile with peers in order
            // based on the queue, taking a delay between requests.
            auto current_time = GetTime<std::chrono::seconds>();
            if (m_next_recon_request <= current_time && m_queue.front() == peer_id) {
                m_queue.pop_front();
                m_queue.push_back(peer_id);
                UpdateNextReconRequest(current_time);
                if (recon_state.m_phase != Phase::NONE) return std::nullopt;
                recon_state.m_phase = Phase::INIT_REQUESTED;

                size_t local_set_size = recon_state.m_local_set.size();

                LogPrint(BCLog::NET, "Initiate reconciliation with peer=%d with the following params: " /* Continued */
                                     "local_set_size=%i\n",
                         peer_id, local_set_size);

                // In future, Q could be recomputed after every reconciliation based on the
                // set differences. For now, it provides good enough results without recompute
                // complexity, but we communicate it here to allow backward compatibility if
                // the value is changed or made dynamic.
                return std::make_pair(local_set_size, Q * Q_PRECISION);
            }
        }
        return std::nullopt;
    }

    void HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        if (!IsPeerRegistered(peer_id)) return;
        LOCK(m_txreconciliation_mutex);
        auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);
        if (recon_state.m_we_initiate) return;
        if (recon_state.m_phase != Phase::NONE) return;

        double peer_q_converted = peer_q * 1.0 / Q_PRECISION;
        recon_state.m_remote_q = peer_q_converted;
        recon_state.m_remote_set_size = peer_recon_set_size;
        recon_state.m_phase = Phase::INIT_REQUESTED;

        LogPrint(BCLog::NET, "Reconciliation initiated by peer=%d with the following params: " /* Continued */
            "remote_q=%d, remote_set_size=%i.\n", peer_id, peer_q_converted, peer_recon_set_size);
    }

    size_t GetPeerSetSize(NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        assert(IsPeerRegistered(peer_id));
        LOCK(m_txreconciliation_mutex);
        const auto& recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        return recon_state.m_local_set.size();
    }

    void ForgetPeer(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        if (m_states.erase(peer_id)) {
            m_queue.erase(std::remove(m_queue.begin(), m_queue.end(), peer_id), m_queue.end());
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Forget txreconciliation state of peer=%d\n", peer_id);
        }
    }

    bool IsPeerRegistered(NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);
        return (recon_state != m_states.end() &&
                std::holds_alternative<TxReconciliationState>(recon_state->second));
    }

    bool ShouldFloodTo(NodeId peer_id, const uint256& wtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        if (!IsPeerRegistered(peer_id)) return true;
        LOCK(m_txreconciliation_mutex);
        const auto recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);

        // We assume that reconciliation is always initiated from inbound to outbound to avoid
        // code complexity.
        std::vector<NodeId> eligible_peers;

        const bool we_initiate = recon_state.m_we_initiate;
        // Find all peers of the same reconciliation direction.
        std::for_each(m_states.begin(), m_states.end(),
                      [&eligible_peers, we_initiate](auto indexed_state) {
                          const auto& cur_state = std::get<TxReconciliationState>(indexed_state.second);
                          if (cur_state.m_we_initiate == we_initiate) eligible_peers.push_back(indexed_state.first);
                      });

        // We found the peer above, so it must be in this list.
        assert(eligible_peers.size() >= 1);

        // Flooding to a fraction (say, 10% of peers) is equivalent to taking the first 10% of
        // of the eligible peers. Sometimes it won't round to a "full peer", in that case we'll
        // roll the dice with the corresponding probability.
        double flood_targets;
        if (we_initiate) {
            flood_targets = OUTBOUND_FANOUT_DESTINATIONS;
        } else {
            flood_targets = eligible_peers.size() * INBOUND_FANOUT_DESTINATIONS_FRACTION;
            if (flood_targets == 0) return false;
        }

        const size_t round_down_flood_targets = floor(flood_targets);

        const auto it = std::find(eligible_peers.begin(), eligible_peers.end(), peer_id);
        Assume(it != eligible_peers.end());
        const size_t peer_position = it - eligible_peers.begin();
        // The requirements to this algorithm is the following:
        // 1. Every transaction should be assigned to *some* peer, at least assuming a static list
        // of peers. For this function that means no randomness.
        // 2. The choice doesn't leak the internal order of peers (m_states) to the external
        // observer. This is achieved by hashing the txid.
        //
        // Say, we have 2.4 targets out of 20 inbound peers, the wtixd hash is 217, and our peer_id
        // holds peer_position in the list of inbound peers.
        // We will compute 217 % 20 = 17, as if it was a "starting_point", from which we see if
        // the target is within a range of 2.4. It's impossible for the range to exceed
        // the bounds because of how we computed them in the first place.
        // For that, we need to check the following:
        // 1. If 17 <= peer_position < 19, return true.
        // 2. If peer_position = 19, roll the dice with the remaining probability (0.4).
        // 3. Otherwise, return false.
        const size_t starting_point = txidHasher(wtxid) % eligible_peers.size();
        if (starting_point <= peer_position && peer_position < starting_point + round_down_flood_targets) {
            return true;
        } else if (peer_position == starting_point + round_down_flood_targets) {
            return rand() < (flood_targets - round_down_flood_targets) * RAND_MAX;
        } else {
            return false;
        }
    }

    bool IsAlreadyInPeerSet(NodeId peer_id, const uint256& wtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        if (!IsPeerRegistered(peer_id)) return false;
        LOCK(m_txreconciliation_mutex);
        const auto recon_state = std::get<TxReconciliationState>(m_states.find(peer_id)->second);
        return recon_state.m_local_set.count(wtxid) > 0;
    }
};

TxReconciliationTracker::TxReconciliationTracker(uint32_t recon_version) : m_impl{std::make_unique<TxReconciliationTracker::Impl>(recon_version)} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

uint64_t TxReconciliationTracker::PreRegisterPeer(NodeId peer_id)
{
    return m_impl->PreRegisterPeer(peer_id);
}

ReconciliationRegisterResult TxReconciliationTracker::RegisterPeer(NodeId peer_id, bool is_peer_inbound,
                                                          uint32_t peer_recon_version, uint64_t remote_salt)
{
    return m_impl->RegisterPeer(peer_id, is_peer_inbound, peer_recon_version, remote_salt);
}

void TxReconciliationTracker::AddToSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
{
    m_impl->AddToSet(peer_id, txs_to_reconcile);
}

void TxReconciliationTracker::TryRemovingFromSet(NodeId peer_id, const uint256& wtxid_to_remove)
{
    m_impl->TryRemovingFromSet(peer_id, wtxid_to_remove);
}

std::optional<std::pair<uint16_t, uint16_t>> TxReconciliationTracker::MaybeRequestReconciliation(NodeId peer_id)
{
    return m_impl->MaybeRequestReconciliation(peer_id);
}

void TxReconciliationTracker::HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q)
{
    m_impl->HandleReconciliationRequest(peer_id, peer_recon_set_size, peer_q);
}

size_t TxReconciliationTracker::GetPeerSetSize(NodeId peer_id) const
{
    return m_impl->GetPeerSetSize(peer_id);
}

void TxReconciliationTracker::ForgetPeer(NodeId peer_id)
{
    m_impl->ForgetPeer(peer_id);
}

bool TxReconciliationTracker::IsPeerRegistered(NodeId peer_id) const
{
    return m_impl->IsPeerRegistered(peer_id);
}

bool TxReconciliationTracker::ShouldFloodTo(NodeId peer_id, const uint256& wtxid) const
{
    return m_impl->ShouldFloodTo(peer_id, wtxid);
}

bool TxReconciliationTracker::IsAlreadyInPeerSet(NodeId peer_id, const uint256& wtxid) const
{
    return m_impl->IsAlreadyInPeerSet(peer_id, wtxid);
}