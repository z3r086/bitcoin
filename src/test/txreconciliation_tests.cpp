// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(txreconciliation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(RegisterPeerTest)
{
    TxReconciliationTracker tracker(TXRECONCILIATION_VERSION);
    const uint64_t salt = 0;

    // Prepare a peer for reconciliation.
    tracker.PreRegisterPeer(0);

    // Invalid version.
    BOOST_CHECK_EQUAL(tracker.RegisterPeer(/*peer_id=*/0, /*is_peer_inbound=*/true,
                                        /*peer_recon_version=*/0, salt), ReconciliationRegisterResult::PROTOCOL_VIOLATION);

    // Valid registration (inbound and outbound peers).
    BOOST_REQUIRE(!tracker.IsPeerRegistered(0));
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(0, true, 1, salt), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(tracker.IsPeerRegistered(0));
    BOOST_REQUIRE(!tracker.IsPeerRegistered(1));
    tracker.PreRegisterPeer(1);
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(1, false, 1, salt), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(tracker.IsPeerRegistered(1));

    // Reconciliation version is higher than ours, should be able to register.
    BOOST_REQUIRE(!tracker.IsPeerRegistered(2));
    tracker.PreRegisterPeer(2);
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(2, true, 2, salt), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(tracker.IsPeerRegistered(2));

    // Do not register if there were no pre-registration for the peer.
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(100, true, 1, salt), ReconciliationRegisterResult::NOT_FOUND);
    BOOST_CHECK(!tracker.IsPeerRegistered(100));
}

BOOST_AUTO_TEST_CASE(ForgetPeerTest)
{
    TxReconciliationTracker tracker(TXRECONCILIATION_VERSION);
    NodeId peer_id0 = 0;

    // Removing peer after pre-registring works and does not let to register the peer.
    tracker.PreRegisterPeer(peer_id0);
    tracker.ForgetPeer(peer_id0);
    BOOST_CHECK_EQUAL(tracker.RegisterPeer(peer_id0, true, 1, 1), ReconciliationRegisterResult::NOT_FOUND);

    // Removing peer after it is registered works.
    tracker.PreRegisterPeer(peer_id0);
    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, true, 1, 1), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(tracker.IsPeerRegistered(peer_id0));
    tracker.ForgetPeer(peer_id0);
    BOOST_CHECK(!tracker.IsPeerRegistered(peer_id0));
}

BOOST_AUTO_TEST_CASE(IsPeerRegisteredTest)
{
    TxReconciliationTracker tracker(TXRECONCILIATION_VERSION);
    NodeId peer_id0 = 0;

    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    tracker.PreRegisterPeer(peer_id0);
    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));

    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, true, 1, 1), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(tracker.IsPeerRegistered(peer_id0));

    tracker.ForgetPeer(peer_id0);
    BOOST_CHECK(!tracker.IsPeerRegistered(peer_id0));
}

BOOST_AUTO_TEST_CASE(ShouldFloodToTest)
{
    TxReconciliationTracker tracker(1);
    NodeId peer_id0 = 0;

    // If peer is not registered for reconciliation, it should be always chosen for flooding.
    // It's possible this peer is completely unknown to us, but that check is out of scope for
    // reconciliation tracker.
    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    for (int i = 0; i < 1000; ++i) {
        BOOST_CHECK(tracker.ShouldFloodTo(peer_id0, GetRandHash()));
    }
    tracker.PreRegisterPeer(peer_id0);
    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    // Same after pre-registering.
    for (int i = 0; i < 1000; ++i) {
        BOOST_CHECK(tracker.ShouldFloodTo(peer_id0, GetRandHash()));
    }

    // Once the peer is registered, it should be selected for flooding of some transactions.
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, true, 1, 1), ReconciliationRegisterResult::SUCCESS);
    size_t selected = 0;
    for (int i = 0; i < 1000; ++i) {
        selected += tracker.ShouldFloodTo(peer_id0, GetRandHash());
    }
    BOOST_CHECK(selected > 0);
}

// Also tests related AddToSet, TryRemovingFromSet and GetPeerSetSize.
BOOST_AUTO_TEST_CASE(IsAlreadyInPeerSet)
{
    TxReconciliationTracker tracker(1);
    NodeId peer_id0 = 0;
    uint256 wtxid = GetRandHash();

    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    BOOST_CHECK(!tracker.IsAlreadyInPeerSet(peer_id0, wtxid));

    tracker.PreRegisterPeer(peer_id0);
    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    BOOST_CHECK(!tracker.IsAlreadyInPeerSet(peer_id0, wtxid));

    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, true, 1, 1), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(!tracker.IsAlreadyInPeerSet(peer_id0, wtxid));
    BOOST_CHECK_EQUAL(tracker.GetPeerSetSize(peer_id0), 0);

    tracker.AddToSet(peer_id0, std::vector<uint256>{wtxid});
    BOOST_CHECK(tracker.IsAlreadyInPeerSet(peer_id0, wtxid));
    BOOST_CHECK_EQUAL(tracker.GetPeerSetSize(peer_id0), 1);

    tracker.TryRemovingFromSet(peer_id0, wtxid);
    BOOST_CHECK(!tracker.IsAlreadyInPeerSet(peer_id0, wtxid));
    BOOST_CHECK_EQUAL(tracker.GetPeerSetSize(peer_id0), 0);

    // Forgetting the peer
    tracker.AddToSet(peer_id0, std::vector<uint256>{wtxid});
    BOOST_REQUIRE(tracker.IsAlreadyInPeerSet(peer_id0, wtxid));
    BOOST_REQUIRE_EQUAL(tracker.GetPeerSetSize(peer_id0), 1);
    tracker.ForgetPeer(peer_id0);
    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    BOOST_CHECK(!tracker.IsAlreadyInPeerSet(peer_id0, wtxid));
}

BOOST_AUTO_TEST_CASE(MaybeRequestReconciliation)
{
    TxReconciliationTracker tracker(1);
    NodeId peer_id0 = 0;
    SetMockTime(1);

    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    BOOST_CHECK(tracker.MaybeRequestReconciliation(peer_id0) == std::nullopt);

    tracker.PreRegisterPeer(peer_id0);
    BOOST_REQUIRE(!tracker.IsPeerRegistered(peer_id0));
    BOOST_CHECK(tracker.MaybeRequestReconciliation(peer_id0) == std::nullopt);

    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, false, 1, 1), ReconciliationRegisterResult::SUCCESS);

    {
        const auto reconciliation_request_params = tracker.MaybeRequestReconciliation(peer_id0);
        BOOST_CHECK(reconciliation_request_params != std::nullopt);
        const auto [local_set_size, local_q_formatted] = (*reconciliation_request_params);
        BOOST_CHECK_EQUAL(local_set_size, 0);
        BOOST_CHECK_EQUAL(local_q_formatted, uint16_t(32767 * 0.25));
    }

    SetMockTime(1 + 7);
    // Even with non-empty set, the response is nullopt because not enough time has passed.
    {
        tracker.AddToSet(peer_id0, std::vector<uint256>{GetRandHash(), GetRandHash(), GetRandHash()});
        const auto reconciliation_request_params = tracker.MaybeRequestReconciliation(peer_id0);
        BOOST_CHECK(reconciliation_request_params == std::nullopt);
    }

    // Enough time passed, but the previous reconciliation is still pending.
    SetMockTime(1 + 9);
    {
        tracker.AddToSet(peer_id0, std::vector<uint256>{GetRandHash(), GetRandHash(), GetRandHash()});
        const auto reconciliation_request_params = tracker.MaybeRequestReconciliation(peer_id0);
        BOOST_CHECK(reconciliation_request_params == std::nullopt);
    }

    // TODO: expand these tests once there is a way to drop the pending reconciliation.

    // Start fresh
    SetMockTime(100);
    tracker.ForgetPeer(peer_id0);
    {
        tracker.PreRegisterPeer(peer_id0);
        BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, false, 1, 1), ReconciliationRegisterResult::SUCCESS);
        tracker.AddToSet(peer_id0, std::vector<uint256>{GetRandHash(), GetRandHash(), GetRandHash()});
        const auto reconciliation_request_params = tracker.MaybeRequestReconciliation(peer_id0);
        BOOST_CHECK(reconciliation_request_params != std::nullopt);
        const auto [local_set_size, local_q_formatted] = (*reconciliation_request_params);
        BOOST_CHECK_EQUAL(local_set_size, 3);
        BOOST_CHECK_EQUAL(local_q_formatted, uint16_t(32767 * 0.25));
    }

    // Two-peer setup
    tracker.ForgetPeer(peer_id0);
    NodeId peer_id1 = 1;
    NodeId peer_id2 = 2;
    SetMockTime(200);
    {
        tracker.PreRegisterPeer(peer_id1);
        tracker.PreRegisterPeer(peer_id2);
        BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id1, false, 1, 1), ReconciliationRegisterResult::SUCCESS);
        BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id2, false, 1, 1), ReconciliationRegisterResult::SUCCESS);

        // First, one of the peers is chosen.
        auto reconciliation_request_params1 = tracker.MaybeRequestReconciliation(peer_id1);
        auto reconciliation_request_params2 = tracker.MaybeRequestReconciliation(peer_id2);
        BOOST_CHECK(reconciliation_request_params1 != std::nullopt);
        BOOST_CHECK(reconciliation_request_params2 == std::nullopt);

        // Immediately after, neither should be chosen — not enough time passed.
        reconciliation_request_params1 = tracker.MaybeRequestReconciliation(peer_id1);
        reconciliation_request_params2 = tracker.MaybeRequestReconciliation(peer_id2);
        BOOST_CHECK(reconciliation_request_params1 == std::nullopt);
        BOOST_CHECK(reconciliation_request_params2 == std::nullopt);

        // After the delay, the other one should be chosen.
        SetMockTime(200 + 9);
        reconciliation_request_params1 = tracker.MaybeRequestReconciliation(peer_id1);
        reconciliation_request_params2 = tracker.MaybeRequestReconciliation(peer_id2);
        BOOST_CHECK(reconciliation_request_params1 == std::nullopt);
        BOOST_CHECK(reconciliation_request_params2 != std::nullopt);
    }
}

BOOST_AUTO_TEST_SUITE_END()
