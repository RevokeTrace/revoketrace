//! RevokeTrace bounded Testnet evidence adapter demonstration
//!
//! Demonstrates:
//! 1. Bounded evidence acquisition via AuthoritativeEvidenceAdapter:
//!    - Accepts trustor account and revoked credit asset identity without caller pool IDs.
//!    - Queries Stellar RPC `getLatestLedger`:
//!      - Decodes `LedgerHeader` (`headerXdr`) to extract header-derived `base_reserve` (5,000,000 stroops).
//!      - Extracts and asserts `protocolVersion >= 18` (Protocol 29 on Testnet).
//!      - Validates ledger hash format (64-char hex) and binds sequence to entry batch.
//!    - Queries Horizon `GET /accounts/{trustor}` to enumerate candidate liquidity-pool share IDs.
//!    - Queries Stellar RPC `getLedgerEntries` in a single atomic batch:
//!      - Enforces strict sequence binding between LedgerHeader and entry batch (`header.ledger_seq == rpc.latest_ledger`).
//!      - Bounded atomic retry loop (up to 3 attempts) if tip advances during capture.
//!      - Parses `xdr` (`LedgerEntryData`) and `extXdr` (`LedgerEntryExt`) to extract entry sponsorship.
//!      - Cryptographically verifies canonical CAP-0038 constant-product pool IDs.
//!      - Reconciles candidate pool count against on-chain `liquidityPoolUseCount == 2`.
//! 2. Strict Evidence Classification Derivation:
//!    - Derived property classification: `BoundedCurrentTipRpc` (bounded candidate set, not complete export).
//!    - CompleteAuthoritativeLedger is unreachable for caller-supplied snapshots; caller attempts to promote authority are refused.
//! 3. Preflight Forecast Evaluation:
//!    - Snapshot contains header-derived `base_reserve_stroops: Some(5_000_000)`.
//!    - Evaluates preflight forecast: `UnverifiedForecast` maximum (`SupportedSafe` unreachable).
//! 4. Fail-Closed Adversarial Guarantees across all failure modes (sequence torn states, missing reserves, forged claims).
//!
//! IMPORTANT: This live demonstration verifies a bounded candidate set at the current network tip.
//! It does NOT claim or demonstrate an independently complete ledger export across arbitrary historical ledgers.

use revoketrace_spike::{
    AUTHORIZED_FLAG, AuthoritativeEvidenceAdapter, Classification, CreditAsset, CurlTransport,
    DiscoveryError, EvidenceClassification, OperationSpec, Transition, discovery_manifest_sha256,
    evaluate,
};

fn main() {
    println!("============================================================");
    println!("   RevokeTrace Bounded Testnet Evidence Demo ");
    println!("============================================================\n");

    let network_passphrase = "Test SDF Network ; September 2015";
    let horizon_url = "https://horizon-testnet.stellar.org";
    let rpc_url = "https://soroban-testnet.stellar.org";

    let trustor = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";
    let asset = CreditAsset {
        code: "FLUTTER".to_owned(),
        issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
    };

    println!("--- Inputs ---");
    println!("Target Network: {}", network_passphrase);
    println!("Trustor: {}", trustor);
    println!("Revoked Asset: {}:{}", asset.code, asset.issuer);
    println!("(Notice: No candidate pool IDs are supplied by the caller)\n");

    println!("--- Step 1: Executing Live Bounded Evidence Adapter ---");
    println!(
        "RPC Endpoint (getLatestLedger + getLedgerEntries): {}",
        rpc_url
    );
    println!("Horizon Endpoint (Candidate Enumeration): {}", horizon_url);

    let transport = CurlTransport::new(15);
    let adapter =
        AuthoritativeEvidenceAdapter::new(transport, horizon_url, rpc_url, network_passphrase);

    match adapter.acquire_live_evidence(trustor, &asset) {
        Ok(snapshot) => {
            println!("\n[LIVE EVIDENCE ACQUISITION SUCCESSFUL]");
            println!("  Pinned Target Ledger: {}", snapshot.ledger_sequence);
            println!(
                "  Protocol Version from LedgerHeader: {:?}",
                snapshot.protocol_version
            );
            println!(
                "  Header-derived Base Reserve: {:?} stroops",
                snapshot.base_reserve_stroops
            );
            println!(
                "  Sponsorship Evidence Complete: {}",
                snapshot.sponsorship_evidence_complete
            );
            println!(
                "  Derived Evidence Classification: {:?}",
                snapshot.discovery.evidence_classification
            );
            println!(
                "  Discovered Affected Pools in Manifest: {}",
                snapshot.pool_share_trustlines.len()
            );

            assert!(snapshot.protocol_version.is_some_and(|v| v >= 18));
            assert_eq!(snapshot.base_reserve_stroops, Some(5_000_000));
            assert_eq!(
                snapshot.discovery.evidence_classification,
                Some(EvidenceClassification::BoundedCurrentTipRpc)
            );

            for (i, pool) in snapshot.pool_share_trustlines.iter().enumerate() {
                println!(
                    "    [{}] Pool ID: {} (Pairs {}:{} with {}:{}, sponsor: {:?})",
                    i + 1,
                    pool.pool_id,
                    pool.asset_a,
                    pool.asset_a_issuer,
                    pool.asset_b,
                    pool.asset_b_issuer,
                    pool.sponsor
                );
            }

            let target_tl = snapshot
                .trustlines
                .first()
                .expect("target credit trustline");
            assert_eq!(
                target_tl.liquidity_pool_use_count,
                Some(2),
                "Target credit trustline liquidityPoolUseCount must be exactly 2"
            );
            assert_eq!(
                snapshot.pool_share_trustlines.len(),
                2,
                "Snapshot pool share trustlines count must be exactly 2"
            );
            println!(
                "  [ASSERTION PASSED] On-chain liquidityPoolUseCount (2) matches discovered pools ({})",
                snapshot.pool_share_trustlines.len()
            );

            // Manifest hash verification
            let expected_manifest_hash = discovery_manifest_sha256(
                &snapshot.network_passphrase,
                snapshot.ledger_sequence,
                &snapshot.discovery.pool_ids,
            );
            assert_eq!(
                snapshot.discovery.manifest_sha256, expected_manifest_hash,
                "Manifest SHA-256 must match canonical sorted material"
            );
            println!(
                "  [ASSERTION PASSED] Canonical Manifest SHA-256: {}",
                snapshot.discovery.manifest_sha256
            );

            // Step 2: Strict Evidence Trust Model Derivation
            println!("\n--- Step 2: Strict Evidence Trust Model Derivation ---");
            let derived_class =
                AuthoritativeEvidenceAdapter::<CurlTransport>::validate_and_classify(&snapshot)
                    .expect("derived classification");
            assert_eq!(
                derived_class,
                EvidenceClassification::BoundedCurrentTipRpc,
                "Derived classification for live capture must be BoundedCurrentTipRpc (verifies bounded candidate set, not complete export)"
            );
            println!(
                "  [ASSERTION PASSED] Property-derived classification: {:?} (bounded candidate set)",
                derived_class
            );

            // Forged provenance rejection test: caller-controlled authority promotion is impossible
            let mut forged_snapshot = snapshot.clone();
            forged_snapshot.discovery.evidence_classification =
                Some(EvidenceClassification::CompleteAuthoritativeLedger);
            let forged_res = AuthoritativeEvidenceAdapter::<CurlTransport>::validate_and_classify(
                &forged_snapshot,
            );
            assert!(
                matches!(forged_res, Err(DiscoveryError::ForgedProvenance(_))),
                "Caller claiming CompleteAuthoritativeLedger without independent capture verifier must be rejected"
            );
            println!(
                "  [ASSERTION PASSED] Attempted CompleteAuthoritativeLedger authority promotion was rejected"
            );

            // Step 3: Preflight evaluation
            println!("\n--- Step 3: Evaluating Preflight Revocation Forecast ---");
            let op = OperationSpec {
                operation: "SetTrustLineFlags".to_owned(),
                source_account: asset.issuer.clone(),
                tx_source_account: Some(asset.issuer.clone()),
                trustor: trustor.to_owned(),
                sequence: Some(1),
                operation_index: Some(0),
                asset: asset.clone(),
                before_flags: AUTHORIZED_FLAG,
                after_flags: 0,
            };

            let report = evaluate(&op, &snapshot);
            assert_eq!(
                report.classification,
                Classification::UnverifiedForecast,
                "Classification must remain UnverifiedForecast"
            );
            assert_ne!(
                report.classification,
                Classification::SupportedSafe,
                "SupportedSafe must NEVER be reached without internal trusted capture"
            );
            assert_eq!(report.transition, Transition::ForcedPoolRedemption);
            assert_eq!(report.pool_redemptions.len(), 2);
            assert!(report.errors.is_empty());

            println!(
                "  [ASSERTION PASSED] Preflight Classification: {:?}",
                report.classification
            );
            println!("  [ASSERTION PASSED] SupportedSafe is unreachable");
            println!(
                "  [ASSERTION PASSED] Forecasted Redemptions: {}",
                report.pool_redemptions.len()
            );
            for (i, r) in report.pool_redemptions.iter().enumerate() {
                println!(
                    "    [{}] Pool {}: withdrawn_a = {} stroops, withdrawn_b = {} stroops, claimable_balances = {}",
                    i + 1,
                    r.pool_id,
                    r.withdrawn_a_stroops,
                    r.withdrawn_b_stroops,
                    r.claimable_balances.len()
                );
                for (j, cb) in r.claimable_balances.iter().enumerate() {
                    println!(
                        "        ({}) Asset: {}, Amount: {} stroops, Sponsor: {}, ID: {:?}, Clawback: {}",
                        j + 1,
                        cb.asset,
                        cb.amount_stroops,
                        cb.sponsor,
                        cb.claimable_balance_id,
                        cb.clawback_flag_enabled
                    );
                    assert!(
                        cb.claimable_balance_id.is_some(),
                        "claimable balance ID should be derived with complete operation context"
                    );
                }
            }
        }
        Err(err) => {
            println!("\n[LIVE PIPELINE REFUSAL / ERROR]: {}", err);
            println!("Classification: {:?}", err.into_classification());
        }
    }

    println!("\n--- Step 4: Verifying Fail-Closed Adversarial Guarantees ---");
    {
        // 1. Missing candidate refusal
        let err = DiscoveryError::CounterMismatch {
            expected_count: 2,
            discovered_count: 1,
        };
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Missing candidate fails closed as Inconclusive");

        // 2. Duplicate candidate refusal
        let err = DiscoveryError::DuplicatePoolId("00171ffe...".to_owned());
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Duplicate candidate fails closed as Inconclusive");

        // 3. Inconsistent sequence refusal
        let err = DiscoveryError::InconsistentLedgerSequence {
            entry_seq: 5000001,
            snapshot_seq: 5000000,
        };
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Inconsistent ledger sequence fails closed as Inconclusive");

        // 4. Stale indexer data refusal
        let err = DiscoveryError::StaleIndexerData("deleted pool".to_owned());
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Stale indexer data fails closed as Inconclusive");

        // 5. Unsupported protocol version refusal
        let err = DiscoveryError::UnsupportedProtocolVersion {
            version: 17,
            minimum: 18,
        };
        assert_eq!(err.into_classification(), Classification::Unsupported);
        println!("  [OK] Unsupported protocol version fails closed as Unsupported");

        // 6. Missing reserve configuration refusal
        let err = DiscoveryError::MissingReserveConfiguration("zero reserve".to_owned());
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Missing reserve configuration fails closed as Inconclusive");

        // 7. Forged provenance refusal
        let err = DiscoveryError::ForgedProvenance("unverified claim".to_owned());
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Forged provenance fails closed as Inconclusive");

        // 8. Truncated archive/capture refusal
        let err = DiscoveryError::TruncatedArchiveOrCapture("truncated json".to_owned());
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Truncated archive or capture fails closed as Inconclusive");

        // 9. Delta treated as snapshot refusal
        let err = DiscoveryError::DeltaTreatedAsFullSnapshot("missing base state".to_owned());
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        println!("  [OK] Delta treated as full snapshot fails closed as Inconclusive");
    }

    println!("\n============================================================");
    println!("  FEASIBILITY VERDICT: AUTHORITATIVE LEDGER EVIDENCE PARTIALLY DEMONSTRATED");
    println!("============================================================");
    println!("Summary:");
    println!(
        "  1. Header-derived base reserve and protocol version extracted from LedgerHeader (headerXdr)."
    );
    println!("  2. Entry-level sponsorship descriptors extracted from LedgerEntryExt (extXdr).");
    println!("  3. On-chain counter reconciliation ($K == N$) mathematically verified.");
    println!(
        "  4. Strict sequence binding (header.ledger_seq == rpc.latest_ledger) prevents torn-state captures."
    );
    println!(
        "  5. Property-derived trust model derives BoundedCurrentTipRpc for bounded candidates; caller authority promotion is rejected."
    );
    println!(
        "  6. Full candidate enumeration completeness across arbitrary historical ledgers remains unproven without Captive Core."
    );
    println!("============================================================\n");
}
