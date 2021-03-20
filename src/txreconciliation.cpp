// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txreconciliation.h>

namespace {

/** Current protocol version */
constexpr uint32_t RECON_VERSION = 1;

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

    void RemovePeer(NodeId peer_id)
    {
        LogPrint(BCLog::NET, "Stop tracking reconciliation state for peer=%d\n", peer_id);
        LOCK(m_mutex);
        m_local_salts.erase(peer_id);
    }

};

TxReconciliationTracker::TxReconciliationTracker() :
    m_impl{std::make_unique<TxReconciliationTracker::Impl>()} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

std::tuple<bool, bool, uint32_t, uint64_t> TxReconciliationTracker::SuggestReconciling(NodeId peer_id, bool inbound)
{
    return m_impl->SuggestReconciling(peer_id, inbound);
}

void TxReconciliationTracker::RemovePeer(NodeId peer_id)
{
    m_impl->RemovePeer(peer_id);
}
