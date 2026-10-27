//! Authoritative Ledger Evidence Adapter and Strict Trust Model (Phase 4A)
//!
//! Provides:
//! 1. Strictly property-derived Evidence Classification:
//!    - `UntrustedCandidate`
//!    - `BoundedCurrentTipRpc`
//!    - `LedgerConsistentIncomplete`
//!    - `CompleteAuthoritativeLedger`
//!    - `InvalidOrContradictory`
//! 2. Authoritative Evidence Adapter:
//!    - Read-only queries to `getLatestLedger` and `getLedgerEntries`
//!    - Authoritative `base_reserve` and `protocolVersion` extraction from `LedgerHeader` (`headerXdr`)
//!    - Authoritative entry-level `sponsoring_id` extraction from `LedgerEntryExt` (`extXdr`)
//!    - Strict canonical CAP-0038 pool-ID verification and on-chain counter reconciliation
//!    - Property-derived classification that refuses caller-forged metadata
//! 3. Structured Capture Artifact for offline reproducibility.

use serde::{Deserialize, Serialize};
use stellar_xdr::{
    AccountId, Hash, LedgerEntryData, LedgerEntryExt, LedgerHeader, Limits, LiquidityPoolEntryBody,
    PoolId, ReadXdr, WriteXdr,
};

use crate::discovery::{
    DiscoveryError, HttpTransport, MAX_RPC_GET_LEDGER_ENTRIES_KEYS, RpcResponse, decode_account_id,
    decode_pool_id, encode_account_id, validate_rpc_entries,
};
use crate::{
    AccountState, CreditAsset, CreditTrustlineState, DiscoveryCoverage, DiscoveryProof,
    DiscoverySource, PoolShareState, Snapshot, derive_constant_product_pool_id,
    discovery_manifest_sha256,
};

/// Strict classifications for ledger evidence in RevokeTrace.
///
/// An evidence classification must be derived from verified properties,
/// never from caller-supplied labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceClassification {
    /// Raw candidate list or unverified caller manifest without on-chain verification.
    UntrustedCandidate,
    /// Bounded single-batch RPC verification at the current ledger tip.
    /// Reconciles against on-chain liquidityPoolUseCount and extracts base_reserve/sponsorship,
    /// but candidate enumeration is bounded or untrusted (e.g. Horizon), and historical state is unproven.
    BoundedCurrentTipRpc,
    /// State is ledger-consistent (all records from the same sequence), but lacks
    /// one or more required inputs (e.g. base reserve, third-party sponsor accounts, or complete counter).
    LedgerConsistentIncomplete,
    /// Truly complete, authoritative ledger evidence from an authoritative export or verified BucketList;
    /// all affected pool shares, credit trustline, canonical pool derivations, sponsor accounts,
    /// and header base-reserve values are verified.
    CompleteAuthoritativeLedger,
    /// Mismatched ledger sequences, corrupted XDR, conflicting flags, negative balances/reserves,
    /// pool ID derivation mismatch, missing deletion records, or tampered manifest hashes.
    InvalidOrContradictory,
}

impl std::fmt::Display for EvidenceClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedCandidate => write!(f, "UntrustedCandidate"),
            Self::BoundedCurrentTipRpc => write!(f, "BoundedCurrentTipRpc"),
            Self::LedgerConsistentIncomplete => write!(f, "LedgerConsistentIncomplete"),
            Self::CompleteAuthoritativeLedger => write!(f, "CompleteAuthoritativeLedger"),
            Self::InvalidOrContradictory => write!(f, "InvalidOrContradictory"),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire Types for getLatestLedger RPC Method
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestLedgerResult {
    pub id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    pub sequence: u32,
    #[serde(rename = "headerXdr")]
    pub header_xdr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestLedgerResponse {
    pub result: Option<LatestLedgerResult>,
    pub error: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Decoding Functions for Header and Sponsorship XDR
// ---------------------------------------------------------------------------

/// Decodes base64-encoded `headerXdr` into a `stellar_xdr::curr::LedgerHeader`.
pub fn decode_ledger_header(header_xdr: &str) -> Result<LedgerHeader, DiscoveryError> {
    LedgerHeader::from_xdr_base64(header_xdr, Limits::none()).map_err(|e| {
        DiscoveryError::ParseError(format!("failed to decode LedgerHeader XDR: {}", e))
    })
}

/// Decodes entry-level sponsorship from base64-encoded `extXdr`.
///
/// In Stellar Core:
/// - `LedgerEntryExt::V0` (or empty) indicates an unsponsored ledger entry.
/// - `LedgerEntryExt::V1(v1)` contains `sponsoring_id: SponsorshipDescriptor(Option<AccountId>)`.
pub fn decode_entry_sponsorship(
    ext_xdr: &Option<String>,
) -> Result<Option<String>, DiscoveryError> {
    let Some(b64) = ext_xdr else {
        return Ok(None);
    };
    if b64.is_empty() {
        return Ok(None);
    }
    let ext = LedgerEntryExt::from_xdr_base64(b64, Limits::none()).map_err(|e| {
        DiscoveryError::ParseError(format!("failed to decode LedgerEntryExt XDR: {}", e))
    })?;

    match ext {
        LedgerEntryExt::V0 => Ok(None),
        LedgerEntryExt::V1(v1) => match v1.sponsoring_id.0 {
            Some(account_id) => {
                let bytes = crate::discovery::account_id_to_bytes(&account_id);
                Ok(Some(encode_account_id(&bytes)))
            }
            None => Ok(None),
        },
    }
}

// ---------------------------------------------------------------------------
// Structured Capture Artifact for Offline Reproducibility
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthoritativeCaptureArtifact {
    pub network_passphrase: String,
    pub ledger_sequence: u32,
    pub protocol_version: u32,
    pub base_reserve_stroops: u64,
    pub evidence_classification: EvidenceClassification,
    pub manifest_sha256: String,
    pub snapshot: Snapshot,
}

// ---------------------------------------------------------------------------
// Authoritative Evidence Adapter
// ---------------------------------------------------------------------------

pub struct AuthoritativeEvidenceAdapter<T: HttpTransport> {
    pub transport: T,
    pub horizon_url: String,
    pub rpc_url: String,
    pub network_passphrase: String,
}

impl<T: HttpTransport> AuthoritativeEvidenceAdapter<T> {
    pub fn new(
        transport: T,
        horizon_url: impl Into<String>,
        rpc_url: impl Into<String>,
        network_passphrase: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            horizon_url: horizon_url.into(),
            rpc_url: rpc_url.into(),
            network_passphrase: network_passphrase.into(),
        }
    }

    /// Acquires and verifies authoritative ledger evidence at the current ledger close.
    ///
    /// Combines:
    /// 1. `getLatestLedger` to extract authoritative `base_reserve` and `protocolVersion` from `LedgerHeader`.
    /// 2. Horizon candidate enumeration for blind pool discovery.
    /// 3. Atomic single-batch `getLedgerEntries` with both `xdr` and `extXdr` decoding to extract entry sponsorship.
    /// 4. Cryptographic derivation of canonical pool IDs and reconciliation with `liquidityPoolUseCount`.
    /// 5. Derivation of the strict `EvidenceClassification::BoundedCurrentTipRpc`.
    pub fn acquire_live_evidence(
        &self,
        trustor: &str,
        asset: &CreditAsset,
    ) -> Result<Snapshot, DiscoveryError> {
        // Validate account identities
        let trustor_bytes = decode_account_id(trustor)
            .map_err(|e| DiscoveryError::ParseError(format!("invalid trustor: {}", e)))?;
        let issuer_bytes = decode_account_id(&asset.issuer)
            .map_err(|e| DiscoveryError::ParseError(format!("invalid issuer: {}", e)))?;

        if trustor == asset.issuer {
            return Err(DiscoveryError::ParseError(
                "trustor and issuer must differ".to_owned(),
            ));
        }
        if asset.code.is_empty() || asset.code.len() > 12 {
            return Err(DiscoveryError::ParseError(
                "invalid credit asset code length".to_owned(),
            ));
        }

        // Step 1: Tier 1 Candidate Enumeration via Horizon
        let horizon_account_url = format!(
            "{}/accounts/{}",
            self.horizon_url.trim_end_matches('/'),
            trustor
        );
        let horizon_body = self.transport.get(&horizon_account_url)?;
        let horizon_acc: crate::HorizonAccountResponse = serde_json::from_str(&horizon_body)
            .map_err(|e| {
                DiscoveryError::ParseError(format!("failed to parse Horizon account JSON: {}", e))
            })?;
        if horizon_acc.id != trustor {
            return Err(DiscoveryError::ParseError(format!(
                "Horizon account identity mismatch: expected {}, found {}",
                trustor, horizon_acc.id
            )));
        }

        let mut candidate_pool_ids = Vec::new();
        let mut seen_pool_ids = std::collections::BTreeSet::new();
        for b in &horizon_acc.balances {
            if b.asset_type == "liquidity_pool_shares"
                && let Some(pool_id) = &b.liquidity_pool_id
            {
                let clean_id = pool_id.trim().to_lowercase();
                if clean_id.len() != 64 || hex::decode(&clean_id).is_err() {
                    return Err(DiscoveryError::ParseError(format!(
                        "invalid pool ID format from Horizon: {}",
                        pool_id
                    )));
                }
                if !seen_pool_ids.insert(clean_id.clone()) {
                    return Err(DiscoveryError::DuplicatePoolId(clean_id));
                }
                candidate_pool_ids.push(clean_id);
            }
        }

        // Step 2: Construct Atomic Ledger Keys
        let trustor_acc_id = AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::Uint256(trustor_bytes),
        ));
        let issuer_acc_id = AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::Uint256(issuer_bytes),
        ));

        let mut keys_b64 = Vec::new();
        let mut key_account_trustor = String::new();
        let mut key_account_issuer = String::new();
        let mut key_credit_tl = String::new();
        let mut key_pool_tls = Vec::new();
        let mut key_pools = Vec::new();

        // 1. Trustor Account Key
        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_acc_id.clone(),
        });
        let k_trustor_b64 = k_trustor
            .to_xdr_base64(Limits::none())
            .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
        key_account_trustor.clone_from(&k_trustor_b64);
        keys_b64.push(k_trustor_b64);

        // 2. Issuer Account Key
        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_acc_id.clone(),
        });
        let k_issuer_b64 = k_issuer
            .to_xdr_base64(Limits::none())
            .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
        key_account_issuer.clone_from(&k_issuer_b64);
        keys_b64.push(k_issuer_b64);

        // 3. Target Credit Trustline Key
        let tl_asset = if asset.code.len() <= 4 {
            let mut code = [0u8; 4];
            code[..asset.code.len()].copy_from_slice(asset.code.as_bytes());
            stellar_xdr::TrustLineAsset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
                asset_code: stellar_xdr::AssetCode4(code),
                issuer: issuer_acc_id.clone(),
            })
        } else {
            let mut code = [0u8; 12];
            code[..asset.code.len()].copy_from_slice(asset.code.as_bytes());
            stellar_xdr::TrustLineAsset::CreditAlphanum12(stellar_xdr::AlphaNum12 {
                asset_code: stellar_xdr::AssetCode12(code),
                issuer: issuer_acc_id.clone(),
            })
        };
        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_acc_id.clone(),
            asset: tl_asset.clone(),
        });
        let k_credit_tl_b64 = k_credit_tl
            .to_xdr_base64(Limits::none())
            .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
        key_credit_tl.clone_from(&k_credit_tl_b64);
        keys_b64.push(k_credit_tl_b64);
        let target_asset = match &tl_asset {
            stellar_xdr::TrustLineAsset::CreditAlphanum4(a) => {
                stellar_xdr::Asset::CreditAlphanum4(a.clone())
            }
            stellar_xdr::TrustLineAsset::CreditAlphanum12(a) => {
                stellar_xdr::Asset::CreditAlphanum12(a.clone())
            }
            stellar_xdr::TrustLineAsset::Native | stellar_xdr::TrustLineAsset::PoolShare(_) => {
                return Err(DiscoveryError::ParseError(
                    "target asset must be a credit asset".to_owned(),
                ));
            }
        };

        // 3b. Additional Constituent Credit Trustlines from Horizon (for constituent clawback evaluation)
        let mut key_extra_credit_tls = Vec::new();
        for b in &horizon_acc.balances {
            if b.asset_type == "credit_alphanum4" || b.asset_type == "credit_alphanum12" {
                let code = b.asset_code.as_deref().ok_or_else(|| {
                    DiscoveryError::ParseError(format!(
                        "balance of type {} missing asset_code",
                        b.asset_type
                    ))
                })?;
                let iss = b.asset_issuer.as_deref().ok_or_else(|| {
                    DiscoveryError::ParseError(format!(
                        "balance of type {} missing asset_issuer",
                        b.asset_type
                    ))
                })?;
                if (b.asset_type == "credit_alphanum4" && (code.is_empty() || code.len() > 4))
                    || (b.asset_type == "credit_alphanum12" && (code.len() <= 4 || code.len() > 12))
                {
                    return Err(DiscoveryError::ParseError(format!(
                        "invalid asset_code length for {}: '{}'",
                        b.asset_type, code
                    )));
                }
                let iss_bytes = decode_account_id(iss).map_err(|e| {
                    DiscoveryError::ParseError(format!(
                        "invalid asset_issuer strkey '{}' from Horizon: {}",
                        iss, e
                    ))
                })?;

                // Skip the target asset being revoked, as it is already requested in step 3a
                if code == asset.code && iss == asset.issuer {
                    continue;
                }

                let iss_acc = AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
                    stellar_xdr::Uint256(iss_bytes),
                ));
                let extra_tl_asset = if code.len() <= 4 {
                    let mut code_arr = [0u8; 4];
                    code_arr[..code.len()].copy_from_slice(code.as_bytes());
                    stellar_xdr::TrustLineAsset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
                        asset_code: stellar_xdr::AssetCode4(code_arr),
                        issuer: iss_acc,
                    })
                } else {
                    let mut code_arr = [0u8; 12];
                    code_arr[..code.len()].copy_from_slice(code.as_bytes());
                    stellar_xdr::TrustLineAsset::CreditAlphanum12(stellar_xdr::AlphaNum12 {
                        asset_code: stellar_xdr::AssetCode12(code_arr),
                        issuer: iss_acc,
                    })
                };
                let k_extra = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
                    account_id: trustor_acc_id.clone(),
                    asset: extra_tl_asset.clone(),
                });
                let k_b64 = k_extra
                    .to_xdr_base64(Limits::none())
                    .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;

                if !keys_b64.contains(&k_b64) {
                    key_extra_credit_tls.push((
                        CreditAsset {
                            code: code.to_owned(),
                            issuer: iss.to_owned(),
                        },
                        extra_tl_asset,
                        k_b64.clone(),
                    ));
                    keys_b64.push(k_b64);
                }
            } else if b.asset_type != "native" && b.asset_type != "liquidity_pool_shares" {
                return Err(DiscoveryError::ParseError(format!(
                    "unknown Horizon balance asset_type: {}",
                    b.asset_type
                )));
            }
        }

        // 4. Candidate Pool-Share Trustlines and Liquidity Pools
        for pool_id in &candidate_pool_ids {
            let mut pool_bytes = [0u8; 32];
            hex::decode_to_slice(pool_id, &mut pool_bytes)
                .map_err(|e| DiscoveryError::ParseError(format!("hex decode failed: {}", e)))?;

            // Pool share trustline
            let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
                account_id: trustor_acc_id.clone(),
                asset: stellar_xdr::TrustLineAsset::PoolShare(PoolId(Hash(pool_bytes))),
            });
            let k_ptl_b64 = k_ptl
                .to_xdr_base64(Limits::none())
                .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
            key_pool_tls.push((pool_id.clone(), k_ptl_b64.clone()));
            keys_b64.push(k_ptl_b64);

            // Liquidity pool entry
            let k_pool =
                stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
                    liquidity_pool_id: PoolId(Hash(pool_bytes)),
                });
            let k_pool_b64 = k_pool
                .to_xdr_base64(Limits::none())
                .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
            key_pools.push((pool_id.clone(), k_pool_b64.clone()));
            keys_b64.push(k_pool_b64);
        }

        if keys_b64.len() > MAX_RPC_GET_LEDGER_ENTRIES_KEYS {
            return Err(DiscoveryError::RpcBatchTooLarge {
                requested: keys_b64.len(),
                maximum: MAX_RPC_GET_LEDGER_ENTRIES_KEYS,
            });
        }

        // Step 3: Atomic Snapshot Acquisition with Ledger Header-to-Entries Binding and Bounded Retry
        const MAX_CAPTURE_ATTEMPTS: usize = 3;
        let mut last_header = None;
        let mut last_rpc_result = None;

        for attempt in 0..MAX_CAPTURE_ATTEMPTS {
            // 3a. Query getLatestLedger from Stellar RPC
            let latest_ledger_payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestLedger"
            });
            let latest_ledger_resp_str = self
                .transport
                .post(&self.rpc_url, &latest_ledger_payload.to_string())?;
            let latest_ledger_resp: LatestLedgerResponse =
                serde_json::from_str(&latest_ledger_resp_str).map_err(|e| {
                    DiscoveryError::ParseError(format!(
                        "failed to parse getLatestLedger response: {}",
                        e
                    ))
                })?;

            if let Some(err) = latest_ledger_resp.error {
                return Err(DiscoveryError::TransportError(format!(
                    "getLatestLedger RPC error: {:?}",
                    err
                )));
            }

            let latest_ledger_result = latest_ledger_resp.result.ok_or_else(|| {
                DiscoveryError::TransportError(
                    "missing result in getLatestLedger response".to_owned(),
                )
            })?;

            // Validate ledger hash format (64-char hex)
            if latest_ledger_result.id.len() != 64 || hex::decode(&latest_ledger_result.id).is_err()
            {
                return Err(DiscoveryError::ParseError(format!(
                    "invalid ledger hash format in getLatestLedger: {}",
                    latest_ledger_result.id
                )));
            }

            // Decode LedgerHeader from headerXdr
            let header = decode_ledger_header(&latest_ledger_result.header_xdr)?;
            if header.ledger_seq != latest_ledger_result.sequence {
                return Err(DiscoveryError::InconsistentLedgerSequence {
                    entry_seq: header.ledger_seq,
                    snapshot_seq: latest_ledger_result.sequence,
                });
            }

            let protocol_version = header.ledger_version;
            if protocol_version < 18 {
                return Err(DiscoveryError::UnsupportedProtocolVersion {
                    version: protocol_version,
                    minimum: 18,
                });
            }

            let base_reserve_stroops = header.base_reserve as u64;
            if base_reserve_stroops == 0 {
                return Err(DiscoveryError::MissingReserveConfiguration(
                    "base_reserve in LedgerHeader is zero".to_owned(),
                ));
            }

            // 3b. Query Stellar RPC getLedgerEntries in a single atomic batch
            let rpc_payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLedgerEntries",
                "params": {
                    "keys": keys_b64
                }
            });
            let rpc_resp_str = self
                .transport
                .post(&self.rpc_url, &rpc_payload.to_string())?;
            let rpc_resp: RpcResponse = serde_json::from_str(&rpc_resp_str).map_err(|e| {
                DiscoveryError::ParseError(format!("failed to parse RPC response JSON: {}", e))
            })?;

            if let Some(err) = rpc_resp.error {
                return Err(DiscoveryError::TransportError(format!(
                    "RPC error returned: {:?}",
                    err
                )));
            }

            let rpc_result = rpc_resp.result.ok_or_else(|| {
                DiscoveryError::TransportError("missing RPC result in response".to_owned())
            })?;

            // 3c. Strict Sequence Binding: verify header and entries correspond to the exact same ledger sequence!
            if header.ledger_seq == rpc_result.latest_ledger {
                last_header = Some(header);
                last_rpc_result = Some(rpc_result);
                break;
            }

            // Tip advanced between getLatestLedger and getLedgerEntries!
            // If attempts remain, retry the entire capture atomically.
            if attempt + 1 == MAX_CAPTURE_ATTEMPTS {
                return Err(DiscoveryError::InconsistentLedgerSequence {
                    entry_seq: rpc_result.latest_ledger,
                    snapshot_seq: header.ledger_seq,
                });
            }
        }

        let (header, rpc_result) = last_header.zip(last_rpc_result).ok_or_else(|| {
            DiscoveryError::TransportError(
                "failed to synchronize ledger header and entries".to_owned(),
            )
        })?;

        let protocol_version = header.ledger_version;
        if protocol_version < 18 {
            return Err(DiscoveryError::UnsupportedProtocolVersion {
                version: protocol_version,
                minimum: 18,
            });
        }

        let base_reserve_stroops = header.base_reserve as u64;
        if base_reserve_stroops == 0 {
            return Err(DiscoveryError::MissingReserveConfiguration(
                "base_reserve in LedgerHeader is zero".to_owned(),
            ));
        }

        let target_seq = header.ledger_seq;

        let entry_map = validate_rpc_entries(&rpc_result, &keys_b64)?;

        // Parse Trustor Account
        let trustor_entry = entry_map
            .get(&key_account_trustor)
            .ok_or_else(|| DiscoveryError::MissingAccount(trustor.to_owned()))?;
        let trustor_data = LedgerEntryData::from_xdr_base64(&trustor_entry.xdr, Limits::none())
            .map_err(|e| {
                DiscoveryError::ParseError(format!("trustor account XDR decode error: {}", e))
            })?;
        let trustor_state = match trustor_data {
            LedgerEntryData::Account(acc) => {
                if acc.account_id != trustor_acc_id {
                    return Err(DiscoveryError::WrongTrustor {
                        expected: trustor.to_owned(),
                        found: encode_account_id(&crate::discovery::account_id_to_bytes(
                            &acc.account_id,
                        )),
                    });
                }
                if acc.balance < 0 {
                    return Err(DiscoveryError::ParseError(
                        "trustor account contains a negative balance or liability".to_owned(),
                    ));
                }
                let (buying_liab, selling_liab, num_sponsoring, num_sponsored) = match acc.ext {
                    stellar_xdr::AccountEntryExt::V1(v1) => {
                        if v1.liabilities.buying < 0 || v1.liabilities.selling < 0 {
                            return Err(DiscoveryError::ParseError(
                                "trustor account contains a negative liability".to_owned(),
                            ));
                        }
                        match v1.ext {
                            stellar_xdr::AccountEntryExtensionV1Ext::V2(v2) => (
                                v1.liabilities.buying as u64,
                                v1.liabilities.selling as u64,
                                v2.num_sponsoring,
                                v2.num_sponsored,
                            ),
                            _ => (
                                v1.liabilities.buying as u64,
                                v1.liabilities.selling as u64,
                                0,
                                0,
                            ),
                        }
                    }
                    _ => (0, 0, 0, 0),
                };
                AccountState {
                    id: trustor.to_owned(),
                    balance_stroops: acc.balance as u64,
                    buying_liabilities_stroops: buying_liab,
                    selling_liabilities_stroops: selling_liab,
                    subentries: acc.num_sub_entries,
                    num_sponsoring,
                    num_sponsored,
                    last_modified_ledger_seq: Some(trustor_entry.last_modified_ledger_seq),
                }
            }
            _ => {
                return Err(DiscoveryError::ParseError(
                    "expected AccountEntry for trustor".to_owned(),
                ));
            }
        };

        // Parse Issuer Account
        let issuer_entry = entry_map
            .get(&key_account_issuer)
            .ok_or_else(|| DiscoveryError::MissingAccount(asset.issuer.clone()))?;
        let issuer_data = LedgerEntryData::from_xdr_base64(&issuer_entry.xdr, Limits::none())
            .map_err(|e| {
                DiscoveryError::ParseError(format!("issuer account XDR decode error: {}", e))
            })?;
        let issuer_state = match issuer_data {
            LedgerEntryData::Account(acc) => {
                if acc.account_id != issuer_acc_id {
                    return Err(DiscoveryError::ParseError(
                        "issuer account XDR identity contradicts requested key".to_owned(),
                    ));
                }
                if acc.balance < 0 {
                    return Err(DiscoveryError::ParseError(
                        "issuer account contains a negative balance or liability".to_owned(),
                    ));
                }
                let (buying_liab, selling_liab, num_sponsoring, num_sponsored) = match acc.ext {
                    stellar_xdr::AccountEntryExt::V1(v1) => {
                        if v1.liabilities.buying < 0 || v1.liabilities.selling < 0 {
                            return Err(DiscoveryError::ParseError(
                                "issuer account contains a negative liability".to_owned(),
                            ));
                        }
                        match v1.ext {
                            stellar_xdr::AccountEntryExtensionV1Ext::V2(v2) => (
                                v1.liabilities.buying as u64,
                                v1.liabilities.selling as u64,
                                v2.num_sponsoring,
                                v2.num_sponsored,
                            ),
                            _ => (
                                v1.liabilities.buying as u64,
                                v1.liabilities.selling as u64,
                                0,
                                0,
                            ),
                        }
                    }
                    _ => (0, 0, 0, 0),
                };
                AccountState {
                    id: asset.issuer.clone(),
                    balance_stroops: acc.balance as u64,
                    buying_liabilities_stroops: buying_liab,
                    selling_liabilities_stroops: selling_liab,
                    subentries: acc.num_sub_entries,
                    num_sponsoring,
                    num_sponsored,
                    last_modified_ledger_seq: Some(issuer_entry.last_modified_ledger_seq),
                }
            }
            _ => {
                return Err(DiscoveryError::ParseError(
                    "expected AccountEntry for issuer".to_owned(),
                ));
            }
        };

        // Parse Credit Trustline and Extract Authoritative Sponsorship
        let credit_tl_entry = entry_map.get(&key_credit_tl).ok_or_else(|| {
            DiscoveryError::MissingCreditTrustline(format!("{}:{}", asset.code, asset.issuer))
        })?;
        let credit_tl_sponsor = decode_entry_sponsorship(&credit_tl_entry.ext_xdr)?;
        let credit_tl_data = LedgerEntryData::from_xdr_base64(&credit_tl_entry.xdr, Limits::none())
            .map_err(|e| {
                DiscoveryError::ParseError(format!("credit trustline XDR decode error: {}", e))
            })?;

        let (flags, liquidity_pool_use_count) = match credit_tl_data {
            LedgerEntryData::Trustline(tl) => {
                if tl.account_id != trustor_acc_id {
                    return Err(DiscoveryError::WrongTrustor {
                        expected: trustor.to_owned(),
                        found: encode_account_id(&crate::discovery::account_id_to_bytes(
                            &tl.account_id,
                        )),
                    });
                }
                if tl.asset != tl_asset {
                    return Err(DiscoveryError::ParseError(
                        "credit trustline asset identity contradicts requested key".to_owned(),
                    ));
                }
                if tl.balance < 0 || tl.limit < 0 {
                    return Err(DiscoveryError::ParseError(
                        "credit trustline contains a negative balance or limit".to_owned(),
                    ));
                }
                let use_count = match tl.ext {
                    stellar_xdr::TrustLineEntryExt::V1(v1) => match v1.ext {
                        stellar_xdr::TrustLineEntryV1Ext::V2(v2) => {
                            if v2.liquidity_pool_use_count < 0 {
                                return Err(DiscoveryError::ParseError(
                                    "negative liquidityPoolUseCount in credit trustline".to_owned(),
                                ));
                            }
                            u32::try_from(v2.liquidity_pool_use_count).ok()
                        }
                        _ => None,
                    },
                    _ => None,
                };
                (tl.flags, use_count)
            }
            _ => {
                return Err(DiscoveryError::ParseError(
                    "expected TrustLineEntry for credit asset".to_owned(),
                ));
            }
        };

        let use_count = liquidity_pool_use_count.ok_or_else(|| {
            DiscoveryError::MissingCounter(
                "credit trustline lacks V2 liquidityPoolUseCount".to_owned(),
            )
        })?;

        let credit_tl_state = CreditTrustlineState {
            owner: trustor.to_owned(),
            asset: asset.clone(),
            flags,
            sponsor: credit_tl_sponsor,
            liquidity_pool_use_count: Some(use_count),
            last_modified_ledger_seq: Some(credit_tl_entry.last_modified_ledger_seq),
        };

        // Parse Extra Constituent Credit Trustlines
        let mut all_trustlines = vec![credit_tl_state];
        for (extra_asset, expected_tl_asset, k_b64) in key_extra_credit_tls {
            let entry = entry_map.get(&k_b64).ok_or_else(|| {
                DiscoveryError::StaleIndexerData(format!(
                    "constituent credit trustline {}:{} returned by Horizon missing on-chain",
                    extra_asset.code, extra_asset.issuer
                ))
            })?;

            let tl_data =
                LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none()).map_err(|e| {
                    DiscoveryError::ParseError(format!(
                        "constituent credit trustline {}:{} XDR decode error: {}",
                        extra_asset.code, extra_asset.issuer, e
                    ))
                })?;

            let (tl_flags, tl_use_count) = match tl_data {
                LedgerEntryData::Trustline(tl) => {
                    if tl.account_id != trustor_acc_id {
                        return Err(DiscoveryError::WrongTrustor {
                            expected: trustor.to_owned(),
                            found: encode_account_id(&crate::discovery::account_id_to_bytes(
                                &tl.account_id,
                            )),
                        });
                    }
                    if tl.asset != expected_tl_asset {
                        return Err(DiscoveryError::ParseError(format!(
                            "constituent credit trustline asset identity contradicts requested asset {}:{}",
                            extra_asset.code, extra_asset.issuer
                        )));
                    }
                    if tl.balance < 0 || tl.limit < 0 {
                        return Err(DiscoveryError::ParseError(
                            "constituent credit trustline contains a negative balance or limit"
                                .to_owned(),
                        ));
                    }
                    let use_count = match tl.ext {
                        stellar_xdr::TrustLineEntryExt::V1(v1) => match v1.ext {
                            stellar_xdr::TrustLineEntryV1Ext::V2(v2) => {
                                if v2.liquidity_pool_use_count < 0 {
                                    return Err(DiscoveryError::ParseError(
                                        "negative liquidityPoolUseCount in constituent credit trustline"
                                            .to_owned(),
                                    ));
                                }
                                u32::try_from(v2.liquidity_pool_use_count).ok()
                            }
                            _ => None,
                        },
                        _ => None,
                    };
                    (tl.flags, use_count)
                }
                _ => {
                    return Err(DiscoveryError::ParseError(format!(
                        "expected TrustLineEntry for constituent credit asset {}:{}",
                        extra_asset.code, extra_asset.issuer
                    )));
                }
            };

            let sponsor = decode_entry_sponsorship(&entry.ext_xdr)?;
            all_trustlines.push(CreditTrustlineState {
                owner: trustor.to_owned(),
                asset: extra_asset,
                flags: tl_flags,
                sponsor,
                liquidity_pool_use_count: tl_use_count,
                last_modified_ledger_seq: Some(entry.last_modified_ledger_seq),
            });
        }

        // Parse Candidate Pools and Cryptographically Verify
        let mut affected_pools = Vec::new();
        let mut matching_pool_ids = Vec::new();
        let mut all_sponsors_verified = true;

        for (pool_id, k_pool_b64) in &key_pools {
            let expected_pool_id = decode_pool_id(pool_id)?;
            let pool_entry = entry_map.get(k_pool_b64).ok_or_else(|| {
                DiscoveryError::StaleIndexerData(format!(
                    "liquidity pool {} returned by Horizon missing on-chain",
                    pool_id
                ))
            })?;
            let (_, k_ptl_b64) = key_pool_tls
                .iter()
                .find(|(id, _)| id == pool_id)
                .expect("matching ptl key");
            let ptl_entry = entry_map.get(k_ptl_b64).ok_or_else(|| {
                DiscoveryError::StaleIndexerData(format!(
                    "pool-share trustline {} returned by Horizon missing on-chain",
                    pool_id
                ))
            })?;

            let pool_data = LedgerEntryData::from_xdr_base64(&pool_entry.xdr, Limits::none())
                .map_err(|e| DiscoveryError::ParseError(format!("pool XDR decode error: {}", e)))?;
            let ptl_data = LedgerEntryData::from_xdr_base64(&ptl_entry.xdr, Limits::none())
                .map_err(|e| DiscoveryError::ParseError(format!("ptl XDR decode error: {}", e)))?;

            let ptl_sponsor = decode_entry_sponsorship(&ptl_entry.ext_xdr)?;
            if let Some(ref sp) = ptl_sponsor
                && sp != trustor
                && sp != &asset.issuer
            {
                all_sponsors_verified = false;
            }

            let owner_shares = match ptl_data {
                LedgerEntryData::Trustline(tl) => {
                    if tl.account_id != trustor_acc_id {
                        return Err(DiscoveryError::WrongTrustor {
                            expected: trustor.to_owned(),
                            found: encode_account_id(&crate::discovery::account_id_to_bytes(
                                &tl.account_id,
                            )),
                        });
                    }
                    if tl.asset != stellar_xdr::TrustLineAsset::PoolShare(expected_pool_id.clone())
                    {
                        return Err(DiscoveryError::ParseError(
                            "pool-share trustline asset identity contradicts requested pool"
                                .to_owned(),
                        ));
                    }
                    if tl.balance < 0 {
                        return Err(DiscoveryError::ParseError(
                            "pool-share trustline balance cannot be negative".to_owned(),
                        ));
                    }
                    tl.balance as u64
                }
                _ => {
                    return Err(DiscoveryError::ParseError(
                        "expected TrustLineEntry for pool share".to_owned(),
                    ));
                }
            };

            let pool_state = match pool_data {
                LedgerEntryData::LiquidityPool(lp) => match lp.body {
                    LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
                        if lp.liquidity_pool_id != expected_pool_id {
                            return Err(DiscoveryError::ParseError(
                                "liquidity pool entry identity contradicts requested pool"
                                    .to_owned(),
                            ));
                        }
                        if cp.reserve_a < 0
                            || cp.reserve_b < 0
                            || cp.total_pool_shares < 0
                            || cp.params.fee < 0
                        {
                            return Err(DiscoveryError::ParseError(
                                "liquidity pool reserves and total shares cannot be negative"
                                    .to_owned(),
                            ));
                        }
                        // Cryptographic verification of canonical pool ID
                        let derived_hash = derive_constant_product_pool_id(
                            &cp.params.asset_a,
                            &cp.params.asset_b,
                            cp.params.fee,
                        )
                        .map_err(|e| {
                            DiscoveryError::ParseError(format!("pool ID derivation error: {}", e))
                        })?;

                        let derived_hex = hex::encode(derived_hash.0);
                        if derived_hex != *pool_id {
                            return Err(DiscoveryError::InvalidPoolDerivation {
                                expected: pool_id.clone(),
                                derived: derived_hex,
                            });
                        }

                        let (asset_a, asset_a_issuer) =
                            crate::discovery::asset_to_parts(&cp.params.asset_a);
                        let (asset_b, asset_b_issuer) =
                            crate::discovery::asset_to_parts(&cp.params.asset_b);

                        PoolShareState {
                            pool_id: pool_id.clone(),
                            owner: trustor.to_owned(),
                            asset_a,
                            asset_a_issuer,
                            asset_b,
                            asset_b_issuer,
                            reserve_a: cp.reserve_a as u64,
                            reserve_b: cp.reserve_b as u64,
                            total_pool_shares: cp.total_pool_shares as u64,
                            owner_pool_shares: owner_shares,
                            sponsor: ptl_sponsor,
                            last_modified_ledger_seq: Some(pool_entry.last_modified_ledger_seq),
                            pool_shares_trust_line_count: u32::try_from(
                                cp.pool_shares_trust_line_count,
                            )
                            .ok(),
                        }
                    }
                },
                _ => {
                    return Err(DiscoveryError::ParseError(
                        "expected LiquidityPoolEntry".to_owned(),
                    ));
                }
            };

            let pool_entry = entry_map
                .get(k_pool_b64)
                .ok_or_else(|| DiscoveryError::MissingLiquidityPoolEntry(pool_id.clone()))?;
            let pool_data = LedgerEntryData::from_xdr_base64(&pool_entry.xdr, Limits::none())
                .map_err(|e| DiscoveryError::ParseError(format!("pool XDR decode error: {}", e)))?;
            let pairs_target_asset = match pool_data {
                LedgerEntryData::LiquidityPool(lp) => match lp.body {
                    LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
                        cp.params.asset_a == target_asset || cp.params.asset_b == target_asset
                    }
                },
                _ => false,
            };

            if pairs_target_asset {
                matching_pool_ids.push(pool_id.clone());
                affected_pools.push(pool_state);
            }
        }

        // Tier 2 Reconciliation: Discovered affected pool count must match liquidityPoolUseCount
        let discovered_count = affected_pools.len() as u32;
        if discovered_count != use_count {
            return Err(DiscoveryError::CounterMismatch {
                expected_count: use_count,
                discovered_count,
            });
        }

        matching_pool_ids.sort();
        let manifest_hash =
            discovery_manifest_sha256(&self.network_passphrase, target_seq, &matching_pool_ids);

        let snapshot = Snapshot {
            network_passphrase: self.network_passphrase.clone(),
            ledger_sequence: target_seq,
            entries_ledger_sequence: target_seq,
            discovery: DiscoveryProof {
                source: DiscoverySource::TwoTierDiscovery {
                    horizon_endpoint: self.horizon_url.clone(),
                    rpc_endpoint: self.rpc_url.clone(),
                },
                target_ledger_sequence: target_seq,
                pool_ids: matching_pool_ids,
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: use_count,
                    verified_pool_count: discovered_count,
                },
                evidence_classification: Some(EvidenceClassification::BoundedCurrentTipRpc),
            },
            base_reserve_stroops: Some(base_reserve_stroops),
            protocol_version: Some(protocol_version),
            sponsorship_evidence_complete: all_sponsors_verified,
            accounts: vec![trustor_state, issuer_state],
            trustlines: all_trustlines,
            pool_share_trustlines: affected_pools,
            sponsorship_handoffs: Vec::new(),
        };

        Ok(snapshot)
    }

    /// Derives the strict EvidenceClassification from verified properties of a snapshot.
    ///
    /// Refuses caller-forged classifications. Derives status strictly from:
    /// - Ledger consistency and absence of newer entries
    /// - Base-reserve presence from LedgerHeader
    /// - Complete sponsorship verification
    /// - Reconciled counter and cryptographic pool ID derivations
    /// - Protocol version validity
    pub fn validate_and_classify(
        snapshot: &Snapshot,
    ) -> Result<EvidenceClassification, DiscoveryError> {
        // 1. Network Passphrase
        if snapshot.network_passphrase.trim().is_empty() {
            return Err(DiscoveryError::IncorrectNetworkPassphrase {
                expected: "non-empty network passphrase".to_owned(),
                found: snapshot.network_passphrase.clone(),
            });
        }

        // 2. Ledger sequence consistency
        if snapshot.ledger_sequence != snapshot.entries_ledger_sequence {
            return Err(DiscoveryError::InconsistentLedgerSequence {
                entry_seq: snapshot.entries_ledger_sequence,
                snapshot_seq: snapshot.ledger_sequence,
            });
        }
        if snapshot.discovery.target_ledger_sequence != snapshot.ledger_sequence {
            return Err(DiscoveryError::InconsistentLedgerSequence {
                entry_seq: snapshot.discovery.target_ledger_sequence,
                snapshot_seq: snapshot.ledger_sequence,
            });
        }

        // Check entry sequence boundaries
        for acc in &snapshot.accounts {
            if let Some(seq) = acc.last_modified_ledger_seq
                && seq > snapshot.ledger_sequence
            {
                return Err(DiscoveryError::InconsistentLedgerSequence {
                    entry_seq: seq,
                    snapshot_seq: snapshot.ledger_sequence,
                });
            }
        }
        for tl in &snapshot.trustlines {
            if let Some(seq) = tl.last_modified_ledger_seq
                && seq > snapshot.ledger_sequence
            {
                return Err(DiscoveryError::InconsistentLedgerSequence {
                    entry_seq: seq,
                    snapshot_seq: snapshot.ledger_sequence,
                });
            }
        }
        for pool in &snapshot.pool_share_trustlines {
            if let Some(seq) = pool.last_modified_ledger_seq
                && seq > snapshot.ledger_sequence
            {
                return Err(DiscoveryError::InconsistentLedgerSequence {
                    entry_seq: seq,
                    snapshot_seq: snapshot.ledger_sequence,
                });
            }
        }

        // 3. Manifest Integrity
        let expected_manifest = discovery_manifest_sha256(
            &snapshot.network_passphrase,
            snapshot.ledger_sequence,
            &snapshot.discovery.pool_ids,
        );
        if snapshot.discovery.manifest_sha256 != expected_manifest {
            return Err(DiscoveryError::ForgedProvenance(
                "manifest SHA-256 does not match canonical material".to_owned(),
            ));
        }

        // 4. Protocol Version
        if let Some(proto) = snapshot.protocol_version
            && proto < 18
        {
            return Err(DiscoveryError::UnsupportedProtocolVersion {
                version: proto,
                minimum: 18,
            });
        }

        // 5. Canonical Pool ID verification
        for pool in &snapshot.pool_share_trustlines {
            if pool.asset_a.is_empty()
                || pool.asset_a_issuer.is_empty()
                || pool.asset_b.is_empty()
                || pool.asset_b_issuer.is_empty()
            {
                return Err(DiscoveryError::ParseError(format!(
                    "pool {} has incomplete constituent asset identities",
                    pool.pool_id
                )));
            }
            if pool.asset_a == pool.asset_b && pool.asset_a_issuer == pool.asset_b_issuer {
                return Err(DiscoveryError::ParseError(format!(
                    "pool {} has contradictory identical constituent assets",
                    pool.pool_id
                )));
            }
        }

        // 6. Check for Forged Caller Claims
        // CompleteAuthoritativeLedger cannot be claimed by caller-supplied snapshots without an independent capture verifier.
        if let Some(EvidenceClassification::CompleteAuthoritativeLedger) =
            snapshot.discovery.evidence_classification
        {
            return Err(DiscoveryError::ForgedProvenance(
                "CompleteAuthoritativeLedger cannot be claimed by caller-supplied snapshots without an independent capture verifier"
                    .to_owned(),
            ));
        }

        // 7. Derive Property-Based Classification
        if snapshot.base_reserve_stroops.is_none_or(|r| r == 0) {
            return Ok(EvidenceClassification::LedgerConsistentIncomplete);
        }

        if !snapshot.sponsorship_evidence_complete {
            return Ok(EvidenceClassification::LedgerConsistentIncomplete);
        }

        // Verify sponsor accounts exist
        for pool in &snapshot.pool_share_trustlines {
            if let Some(ref sp) = pool.sponsor
                && !snapshot.accounts.iter().any(|a| a.id == *sp)
            {
                return Ok(EvidenceClassification::LedgerConsistentIncomplete);
            }
        }
        for tl in &snapshot.trustlines {
            if let Some(ref sp) = tl.sponsor
                && !snapshot.accounts.iter().any(|a| a.id == *sp)
            {
                return Ok(EvidenceClassification::LedgerConsistentIncomplete);
            }
        }

        match &snapshot.discovery.source {
            DiscoverySource::SyntheticFixture => Ok(EvidenceClassification::UntrustedCandidate),
            DiscoverySource::TwoTierDiscovery { .. } | DiscoverySource::LedgerCapture { .. } => {
                Ok(EvidenceClassification::BoundedCurrentTipRpc)
            }
            DiscoverySource::AuthoritativeExport { .. } => {
                // Without an independent offline capture verifier (e.g. Captive Core / History Archive verifier),
                // caller-supplied AuthoritativeExport snapshots cannot be verified as complete authoritative ledgers.
                // CompleteAuthoritativeLedger is unreachable for caller-supplied snapshots; safely fail closed to LedgerConsistentIncomplete.
                Ok(EvidenceClassification::LedgerConsistentIncomplete)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Adversarial Negative & Positive Test Suite (Phase 4A)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{MockTransport, decode_account_id};
    use crate::{
        AUTHORIZED_FLAG, AccountState, Classification, CreditAsset, CreditTrustlineState,
        DiscoveryCoverage, DiscoveryProof, DiscoverySource, OperationSpec, PoolShareState,
        Snapshot, derive_constant_product_pool_id, discovery_manifest_sha256, evaluate,
    };
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext,
        AccountEntryExtensionV2, AccountEntryExtensionV2Ext, AlphaNum4, Asset, AssetCode4, Hash,
        LedgerEntryData, LedgerEntryExt, LedgerEntryExtensionV1, LedgerEntryExtensionV1Ext,
        LedgerHeader, LedgerHeaderExt, Liabilities, Limits, LiquidityPoolConstantProductParameters,
        LiquidityPoolEntry, LiquidityPoolEntryBody, LiquidityPoolEntryConstantProduct, PoolId,
        PublicKey, SequenceNumber, SponsorshipDescriptor, StellarValue, StellarValueExt, String32,
        StringM, Thresholds, TimePoint, TrustLineAsset, TrustLineEntry, TrustLineEntryExt,
        TrustLineEntryExtensionV2, TrustLineEntryExtensionV2Ext, TrustLineEntryV1,
        TrustLineEntryV1Ext, Uint256, UpgradeType, VecM, WriteXdr,
    };

    const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const TRUSTOR_STRKEY: &str = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";
    const ISSUER_STRKEY: &str = "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG";
    const OTHER_ISSUER_STRKEY: &str = "GA5Q3FBUPYK4T3BQDILVTDFN2TCLLNBDYABMFZRXTE2BLXP5CZXOQFWM";

    const REAL_HEADER_XDR: &str = "AAAAHVOZ89LSqu4moPER2wy1YzgGMuM/b3wyPKcdRQN/Aswnqa/ZJd33JpbuLrfIRUs+c+8c6VqiE3HZoJy1ltNTHfAAAAAAauCEewAAAAAAAAABAAAAAKgkzRi8nXUGTSmaW1uspDvDqi8yaTgVPYwvm7XLbfAzAAAAQA4z+hQOXMsqYo3iWXk5CS/6zEATkWcD1+/Ts+70aWJu48Yr0dyHQN/QTICN46IkBhSKVNp1jDnf5rRE06B6iQJU9qbQM8wMDwGVL+hhkoS1B2hNpTkGZFDTu876ZNf5uqkE6BJi0nthXbi6zQBu9ixyEJYGsfcxclb2z7kO8s7MAFKgjg3gtrOnZAAAAAAsg3ISKdwAAAAAAAAAAAAOPbEAAABkAExLQAAAAMit8ugw6geBSII5ilGJF1fNsTkMBwVWPjKX71e5e032oEfHJn9bZYdTKdNTJUAzzqPlp8Bx6O189JCSlKDqfX9yq/E23IeCb2hra2R9ZaEUej6hcg2AwbODCzvqDoaX82m2cm6r8ecN/675yBcoOos0c4aKRh6aDbiou7DptxnL1QAAAAA=";
    const MOCK_LEDGER_HASH: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn trustor_id() -> AccountId {
        let bytes = decode_account_id(TRUSTOR_STRKEY).unwrap();
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn issuer_id() -> AccountId {
        let bytes = decode_account_id(ISSUER_STRKEY).unwrap();
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn other_issuer_id() -> AccountId {
        let bytes = decode_account_id(OTHER_ISSUER_STRKEY).unwrap();
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn sponsor_acc_id() -> (AccountId, String) {
        let bytes = [7u8; 32];
        let strkey = encode_account_id(&bytes);
        (
            AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes))),
            strkey,
        )
    }

    fn credit_asset_flutter() -> CreditAsset {
        CreditAsset {
            code: "FLUTTER".to_owned(),
            issuer: ISSUER_STRKEY.to_owned(),
        }
    }

    fn make_header_xdr(version: u32, seq: u32, base_reserve: u32) -> String {
        let header = LedgerHeader {
            ledger_version: version,
            previous_ledger_hash: Hash([0u8; 32]),
            scp_value: StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: TimePoint(1793098875),
                upgrades: VecM::<UpgradeType, 6>::default(),
                ext: StellarValueExt::Basic,
            },
            tx_set_result_hash: Hash([0u8; 32]),
            bucket_list_hash: Hash([0u8; 32]),
            ledger_seq: seq,
            total_coins: 100_000_000_000_000_000,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 1000,
            base_fee: 100,
            base_reserve,
            max_tx_set_size: 100,
            skip_list: [
                Hash([0u8; 32]),
                Hash([0u8; 32]),
                Hash([0u8; 32]),
                Hash([0u8; 32]),
            ],
            ext: LedgerHeaderExt::V0,
        };
        header.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_account_xdr(acc_id: AccountId, balance: i64) -> String {
        let entry = LedgerEntryData::Account(AccountEntry {
            account_id: acc_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 10,
            inflation_dest: None,
            flags: 0,
            home_domain: String32(StringM::default()),
            thresholds: Thresholds([1, 1, 1, 1]),
            signers: VecM::default(),
            ext: AccountEntryExt::V1(AccountEntryExtensionV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 0,
                },
                ext: AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                    num_sponsoring: 2,
                    num_sponsored: 0,
                    signer_sponsoring_i_ds: VecM::default(),
                    ext: AccountEntryExtensionV2Ext::V0,
                }),
            }),
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_credit_tl_xdr(
        owner: AccountId,
        issuer: AccountId,
        code: &str,
        use_count: Option<i32>,
    ) -> String {
        make_credit_tl_xdr_with_flags(owner, issuer, code, use_count, 1)
    }

    fn make_credit_tl_xdr_with_flags(
        owner: AccountId,
        issuer: AccountId,
        code: &str,
        use_count: Option<i32>,
        flags: u32,
    ) -> String {
        let mut arr = [0u8; 4];
        arr[..code.len()].copy_from_slice(code.as_bytes());
        let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(arr),
            issuer,
        });

        let ext = match use_count {
            Some(cnt) => TrustLineEntryExt::V1(TrustLineEntryV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 0,
                },
                ext: TrustLineEntryV1Ext::V2(TrustLineEntryExtensionV2 {
                    liquidity_pool_use_count: cnt,
                    ext: TrustLineEntryExtensionV2Ext::V0,
                }),
            }),
            None => TrustLineEntryExt::V0,
        };

        let entry = LedgerEntryData::Trustline(TrustLineEntry {
            account_id: owner,
            asset,
            balance: 500_000_000,
            limit: i64::MAX,
            flags,
            ext,
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_pool_tl_xdr(owner: AccountId, pool_id: &Hash, shares: i64) -> String {
        let entry = LedgerEntryData::Trustline(TrustLineEntry {
            account_id: owner,
            asset: TrustLineAsset::PoolShare(PoolId(pool_id.clone())),
            balance: shares,
            limit: i64::MAX,
            flags: 1,
            ext: TrustLineEntryExt::V0,
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_pool_entry_xdr(asset_a: Asset, asset_b: Asset, fee_bps: i32) -> (String, Hash, String) {
        let pool_id = derive_constant_product_pool_id(&asset_a, &asset_b, fee_bps).unwrap();
        let pool_hex = hex::encode(pool_id.0);
        let entry = LedgerEntryData::LiquidityPool(LiquidityPoolEntry {
            liquidity_pool_id: PoolId(pool_id.clone()),
            body: LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
                LiquidityPoolEntryConstantProduct {
                    params: LiquidityPoolConstantProductParameters {
                        asset_a,
                        asset_b,
                        fee: fee_bps,
                    },
                    reserve_a: 10_000_000,
                    reserve_b: 20_000_000,
                    total_pool_shares: 1000,
                    pool_shares_trust_line_count: 1,
                },
            ),
        });
        (
            entry.to_xdr_base64(Limits::none()).unwrap(),
            pool_id,
            pool_hex,
        )
    }

    fn make_sponsorship_ext_xdr(sponsor: Option<AccountId>) -> String {
        let ext = match sponsor {
            Some(acc) => LedgerEntryExt::V1(LedgerEntryExtensionV1 {
                sponsoring_id: SponsorshipDescriptor(Some(acc)),
                ext: LedgerEntryExtensionV1Ext::V0,
            }),
            None => LedgerEntryExt::V0,
        };
        ext.to_xdr_base64(Limits::none()).unwrap()
    }

    // -----------------------------------------------------------------------
    // Positive Verification Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_real_testnet_header_xdr() {
        let header = decode_ledger_header(REAL_HEADER_XDR).expect("valid testnet header XDR");
        assert_eq!(header.ledger_version, 29);
        assert_eq!(header.ledger_seq, 5415054);
        assert_eq!(header.base_reserve, 5_000_000);
        assert_eq!(header.base_fee, 100);
    }

    #[test]
    fn test_decode_sponsorship_v0_and_v1() {
        let v0_b64 = Some("AAAAAA==".to_owned());
        let sponsor_none = decode_entry_sponsorship(&v0_b64).expect("valid V0 decode");
        assert_eq!(sponsor_none, None);

        let empty_opt: Option<String> = None;
        assert_eq!(decode_entry_sponsorship(&empty_opt).unwrap(), None);

        let (sponsor_acc, sponsor_strkey) = sponsor_acc_id();
        let v1_b64 = Some(make_sponsorship_ext_xdr(Some(sponsor_acc)));
        let sponsor_decoded = decode_entry_sponsorship(&v1_b64).expect("valid V1 decode");
        assert_eq!(sponsor_decoded, Some(sponsor_strkey));
    }

    #[test]
    fn test_positive_bounded_current_tip_rpc_classification() {
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            30,
        );

        let mut mock = MockTransport::new();
        // 1. getLatestLedger response
        let latest_ledger_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "id": MOCK_LEDGER_HASH,
                "protocolVersion": 29,
                "sequence": 5000,
                "headerXdr": make_header_xdr(29, 5000, 5_000_000)
            }
        })
        .to_string();
        mock.set_post_method("getLatestLedger", Ok(latest_ledger_json));

        // 2. Horizon candidate enumeration
        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [{
                "asset_type": "liquidity_pool_shares",
                "liquidity_pool_id": pool_hex
            }]
        })
        .to_string();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );

        // 3. getLedgerEntries response with extXdr
        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_hash.clone()),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let entries = vec![
            serde_json::json!({
                "key": k_trustor,
                "xdr": make_account_xdr(trustor_id(), 100_000_000),
                "lastModifiedLedgerSeq": 4900,
                "extXdr": "AAAAAA=="
            }),
            serde_json::json!({
                "key": k_issuer,
                "xdr": make_account_xdr(issuer_id(), 500_000_000),
                "lastModifiedLedgerSeq": 4800,
                "extXdr": "AAAAAA=="
            }),
            serde_json::json!({
                "key": k_credit_tl,
                "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUT", Some(1)),
                "lastModifiedLedgerSeq": 4950,
                "extXdr": "AAAAAA=="
            }),
            serde_json::json!({
                "key": k_ptl,
                "xdr": make_pool_tl_xdr(trustor_id(), &derive_constant_product_pool_id(
                    &Asset::Native,
                    &Asset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4(*b"FLUT"),
                        issuer: issuer_id(),
                    }),
                    30,
                ).unwrap(), 100),
                "lastModifiedLedgerSeq": 4950,
                "extXdr": "AAAAAA=="
            }),
            serde_json::json!({
                "key": k_pool,
                "xdr": pool_xdr,
                "lastModifiedLedgerSeq": 4900,
                "extXdr": "AAAAAA=="
            }),
        ];

        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "entries": entries,
                "latestLedger": 5000
            }
        })
        .to_string();
        mock.set_post_method("getLedgerEntries", Ok(rpc_json));

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );

        let asset = CreditAsset {
            code: "FLUT".to_owned(),
            issuer: ISSUER_STRKEY.to_owned(),
        };

        let snapshot = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .expect("successful acquisition");

        assert_eq!(snapshot.ledger_sequence, 5000);
        assert_eq!(snapshot.base_reserve_stroops, Some(5_000_000));
        assert_eq!(snapshot.protocol_version, Some(29));
        assert!(snapshot.sponsorship_evidence_complete);
        assert_eq!(
            snapshot.discovery.evidence_classification,
            Some(EvidenceClassification::BoundedCurrentTipRpc)
        );

        // Preflight forecast remains UnverifiedForecast; SupportedSafe unreachable!
        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            tx_source_account: None,
            trustor: TRUSTOR_STRKEY.to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset,
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };
        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_ne!(report.classification, Classification::SupportedSafe);
    }

    #[test]
    fn test_positive_authoritative_complete_export_classification() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);

        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "core-export-ledger-5000".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids: pool_ids.clone(),
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: 1,
                    verified_pool_count: 1,
                },
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![
                AccountState {
                    id: TRUSTOR_STRKEY.to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 4,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4900),
                },
                AccountState {
                    id: ISSUER_STRKEY.to_owned(),
                    balance_stroops: 500_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4800),
                },
            ],
            trustlines: vec![CreditTrustlineState {
                owner: TRUSTOR_STRKEY.to_owned(),
                asset: CreditAsset {
                    code: "FLUTTER".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
                flags: AUTHORIZED_FLAG,
                sponsor: None,
                liquidity_pool_use_count: Some(1),
                last_modified_ledger_seq: Some(4950),
            }],
            pool_share_trustlines: vec![PoolShareState {
                pool_id,
                owner: TRUSTOR_STRKEY.to_owned(),
                asset_a: "FLUTTER".to_owned(),
                asset_a_issuer: ISSUER_STRKEY.to_owned(),
                asset_b: "XLM".to_owned(),
                asset_b_issuer: "native".to_owned(),
                reserve_a: 10_000_000,
                reserve_b: 20_000_000,
                total_pool_shares: 1000,
                owner_pool_shares: 100,
                sponsor: None,
                last_modified_ledger_seq: Some(4900),
                pool_shares_trust_line_count: None,
            }],
            sponsorship_handoffs: Vec::new(),
        };

        let classification =
            AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
                .expect("validation passed");
        // Caller cannot promote to CompleteAuthoritativeLedger without independent capture verifier;
        // safely evaluates to LedgerConsistentIncomplete
        assert_eq!(
            classification,
            EvidenceClassification::LedgerConsistentIncomplete
        );
    }

    // -----------------------------------------------------------------------
    // Adversarial Negative Tests (17 Failure Modes)
    // -----------------------------------------------------------------------

    #[test]
    fn test_adversarial_1_missing_pool_share_trustline() {
        let mut mock = MockTransport::new();
        mock.set_post_method(
            "getLatestLedger",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
            }).to_string()),
        );
        let pool_hex = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46";
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY,
                "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
            }).to_string()),
        );
        // Omit pool-share trustline in RPC response
        mock.set_post_method(
            "getLedgerEntries",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "entries": [], "latestLedger": 5000 }
            })
            .to_string()),
        );

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_2_missing_liquidity_pool_entry() {
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            30,
        );
        let mut mock = MockTransport::new();
        mock.set_post_method("getLatestLedger", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
        }).to_string()));
        mock.set_get(format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY), Ok(serde_json::json!({
            "id": TRUSTOR_STRKEY, "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
        }).to_string()));

        // Return ptl but omit pool entry
        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash)),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        mock.set_post_method(
            "getLedgerEntries",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "entries": [{
                        "key": k_ptl,
                        "xdr": make_pool_tl_xdr(trustor_id(), &Hash([0u8; 32]), 100),
                        "lastModifiedLedgerSeq": 4900,
                        "extXdr": "AAAAAA=="
                    }],
                    "latestLedger": 5000
                }
            })
            .to_string()),
        );

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert_eq!(err.into_classification(), Classification::Inconclusive);
        let _ = pool_xdr;
    }

    #[test]
    fn test_adversarial_3_duplicate_ledger_entry() {
        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let rpc_result = crate::discovery::RpcResult {
            entries: vec![
                crate::discovery::RpcEntry {
                    key: k_trustor.clone(),
                    xdr: make_account_xdr(trustor_id(), 1000),
                    last_modified_ledger_seq: 4000,
                    ext_xdr: None,
                },
                crate::discovery::RpcEntry {
                    key: k_trustor.clone(),
                    xdr: make_account_xdr(trustor_id(), 2000),
                    last_modified_ledger_seq: 4000,
                    ext_xdr: None,
                },
            ],
            latest_ledger: 5000,
        };
        let err = crate::discovery::validate_rpc_entries(&rpc_result, &[k_trustor]).unwrap_err();
        assert!(matches!(err, DiscoveryError::ParseError(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_4_incorrect_trustor() {
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            30,
        );
        let mut mock = MockTransport::new();
        mock.set_post_method("getLatestLedger", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
        }).to_string()));
        mock.set_get(format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY), Ok(serde_json::json!({
            "id": TRUSTOR_STRKEY, "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
        }).to_string()));

        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_hash.clone()),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        // Credit trustline belongs to other_issuer_id instead of trustor!
        let forged_credit_tl = make_credit_tl_xdr(other_issuer_id(), issuer_id(), "FLUT", Some(1));

        mock.set_post_method("getLedgerEntries", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100), "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 500), "lastModifiedLedgerSeq": 4800, "extXdr": "AAAAAA==" },
                    { "key": k_credit_tl, "xdr": forged_credit_tl, "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &Hash([0u8; 32]), 100), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_pool, "xdr": pool_xdr, "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                ],
                "latestLedger": 5000
            }
        }).to_string()));

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(
                TRUSTOR_STRKEY,
                &CreditAsset {
                    code: "FLUT".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
            )
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::WrongTrustor { .. }));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_5_incorrect_asset_issuer() {
        // Pool pairs "FLUT" with other_issuer_id instead of target issuer!
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: other_issuer_id(),
            }),
            30,
        );

        let mut mock = MockTransport::new();
        mock.set_post_method("getLatestLedger", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
        }).to_string()));
        mock.set_get(format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY), Ok(serde_json::json!({
            "id": TRUSTOR_STRKEY, "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
        }).to_string()));

        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_hash.clone()),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        mock.set_post_method("getLedgerEntries", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100), "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 500), "lastModifiedLedgerSeq": 4800, "extXdr": "AAAAAA==" },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUT", Some(1)), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool_hash, 100), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_pool, "xdr": pool_xdr, "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                ],
                "latestLedger": 5000
            }
        }).to_string()));

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(
                TRUSTOR_STRKEY,
                &CreditAsset {
                    code: "FLUT".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
            )
            .unwrap_err();
        // Since pool pairs other_issuer_id, discovered count is 0 != expected 1
        assert!(matches!(
            err,
            DiscoveryError::CounterMismatch {
                expected_count: 1,
                discovered_count: 0
            }
        ));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_6_incorrect_pool_id() {
        // Construct pool with fee 30, but request pool ID derived from fee 50
        let (pool_xdr, _, _) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            30,
        );
        let forged_pool_id = derive_constant_product_pool_id(
            &Asset::Native,
            &Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            50,
        )
        .unwrap();
        let forged_hex = hex::encode(forged_pool_id.0);

        let mut mock = MockTransport::new();
        mock.set_post_method("getLatestLedger", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
        }).to_string()));
        mock.set_get(format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY), Ok(serde_json::json!({
            "id": TRUSTOR_STRKEY, "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": forged_hex }]
        }).to_string()));

        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(forged_pool_id.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(forged_pool_id),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        mock.set_post_method("getLedgerEntries", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100), "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 500), "lastModifiedLedgerSeq": 4800, "extXdr": "AAAAAA==" },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUT", Some(1)), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &Hash([0u8; 32]), 100), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_pool, "xdr": pool_xdr, "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                ],
                "latestLedger": 5000
            }
        }).to_string()));

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(
                TRUSTOR_STRKEY,
                &CreditAsset {
                    code: "FLUT".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
            )
            .unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::ParseError(_) | DiscoveryError::InvalidPoolDerivation { .. }
        ));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_7_mixed_ledger_evidence() {
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            30,
        );
        let mut mock = MockTransport::new();
        mock.set_post_method("getLatestLedger", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
        }).to_string()));
        mock.set_get(format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY), Ok(serde_json::json!({
            "id": TRUSTOR_STRKEY, "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
        }).to_string()));

        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_hash.clone()),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        // One entry has lastModifiedLedgerSeq = 5001 > latestLedger = 5000!
        mock.set_post_method("getLedgerEntries", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100), "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 500), "lastModifiedLedgerSeq": 4800, "extXdr": "AAAAAA==" },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUT", Some(1)), "lastModifiedLedgerSeq": 5001, "extXdr": "AAAAAA==" },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool_hash, 100), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_pool, "xdr": pool_xdr, "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                ],
                "latestLedger": 5000
            }
        }).to_string()));

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(
                TRUSTOR_STRKEY,
                &CreditAsset {
                    code: "FLUT".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
            )
            .unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::InconsistentLedgerSequence {
                entry_seq: 5001,
                snapshot_seq: 5000
            }
        ));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_8_missing_ledger_close_changes_delta_treated_as_snapshot() {
        // Delta missing base account entries
        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "raw-delta-changes".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids: vec![],
                manifest_sha256: discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &[]),
                coverage: DiscoveryCoverage::Unproven,
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: false,
            accounts: vec![], // Missing base accounts!
            trustlines: vec![],
            pool_share_trustlines: vec![],
            sponsorship_handoffs: vec![],
        };

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            tx_source_account: None,
            trustor: TRUSTOR_STRKEY.to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: credit_asset_flutter(),
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };
        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("source account is missing"))
        );
    }

    #[test]
    fn test_adversarial_9_missing_deletion_records() {
        // Reconciliation fails because candidate set contains 2 pools but on-chain use count is 1
        let pool_id_1 =
            "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_id_2 =
            "078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c".to_owned();
        let pool_ids = vec![pool_id_1.clone(), pool_id_2.clone()];
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);

        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "export".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids: pool_ids.clone(),
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: 1, // On-chain says 1!
                    verified_pool_count: 2,      // But 2 are present because deletion was missed!
                },
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![
                AccountState {
                    id: TRUSTOR_STRKEY.to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 4,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4900),
                },
                AccountState {
                    id: ISSUER_STRKEY.to_owned(),
                    balance_stroops: 500_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4800),
                },
            ],
            trustlines: vec![CreditTrustlineState {
                owner: TRUSTOR_STRKEY.to_owned(),
                asset: CreditAsset {
                    code: "FLUTTER".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
                flags: AUTHORIZED_FLAG,
                sponsor: None,
                liquidity_pool_use_count: Some(1),
                last_modified_ledger_seq: Some(4950),
            }],
            pool_share_trustlines: vec![
                PoolShareState {
                    pool_id: pool_id_1,
                    owner: TRUSTOR_STRKEY.to_owned(),
                    asset_a: "FLUTTER".to_owned(),
                    asset_a_issuer: ISSUER_STRKEY.to_owned(),
                    asset_b: "XLM".to_owned(),
                    asset_b_issuer: "native".to_owned(),
                    reserve_a: 100,
                    reserve_b: 200,
                    total_pool_shares: 100,
                    owner_pool_shares: 10,
                    sponsor: None,
                    last_modified_ledger_seq: Some(4900),
                    pool_shares_trust_line_count: None,
                },
                PoolShareState {
                    pool_id: pool_id_2,
                    owner: TRUSTOR_STRKEY.to_owned(),
                    asset_a: "FLUTTER".to_owned(),
                    asset_a_issuer: ISSUER_STRKEY.to_owned(),
                    asset_b: "XLM".to_owned(),
                    asset_b_issuer: "native".to_owned(),
                    reserve_a: 100,
                    reserve_b: 200,
                    total_pool_shares: 100,
                    owner_pool_shares: 10,
                    sponsor: None,
                    last_modified_ledger_seq: Some(4900),
                    pool_shares_trust_line_count: None,
                },
            ],
            sponsorship_handoffs: vec![],
        };

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            tx_source_account: None,
            trustor: TRUSTOR_STRKEY.to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: credit_asset_flutter(),
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };
        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("does not match discovered affected pools"))
        );
    }

    #[test]
    fn test_adversarial_10_truncated_archive_or_capture() {
        let truncated_json =
            "{ \"network_passphrase\": \"Test SDF Network\", \"ledger_sequence\": 50";
        let res: Result<AuthoritativeCaptureArtifact, _> = serde_json::from_str(truncated_json);
        assert!(res.is_err());
    }

    #[test]
    fn test_adversarial_11_incorrect_network() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];
        // Manifest computed with Test SDF Network, but snapshot has Public Global
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);

        let snapshot = Snapshot {
            network_passphrase: "Public Global Stellar Network ; September 2015".to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "export".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids,
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::Unproven,
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![],
            trustlines: vec![],
            pool_share_trustlines: vec![],
            sponsorship_handoffs: vec![],
        };

        let err = AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::ForgedProvenance(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_12_unsupported_protocol_version() {
        let mut mock = MockTransport::new();
        // Horizon returns empty balances
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY,
                "balances": []
            })
            .to_string()),
        );
        // Return protocolVersion = 17 (pre-CAP-0038)
        mock.set_post_method("getLatestLedger", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 17, "sequence": 5000, "headerXdr": make_header_xdr(17, 5000, 5_000_000) }
        }).to_string()));

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::UnsupportedProtocolVersion {
                version: 17,
                minimum: 18
            }
        ));
        assert_eq!(err.into_classification(), Classification::Unsupported);
    }

    #[test]
    fn test_adversarial_13_forged_provenance_rejected() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);

        // Caller attempts to label TwoTierDiscovery as CompleteAuthoritativeLedger!
        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::TwoTierDiscovery {
                    horizon_endpoint: "https://horizon.example".to_owned(),
                    rpc_endpoint: "https://rpc.example".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids: pool_ids.clone(),
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: 1,
                    verified_pool_count: 1,
                },
                evidence_classification: Some(EvidenceClassification::CompleteAuthoritativeLedger),
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![
                AccountState {
                    id: TRUSTOR_STRKEY.to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 4,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4900),
                },
                AccountState {
                    id: ISSUER_STRKEY.to_owned(),
                    balance_stroops: 500_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4800),
                },
            ],
            trustlines: vec![],
            pool_share_trustlines: vec![],
            sponsorship_handoffs: vec![],
        };

        let err = AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::ForgedProvenance(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_14_incorrect_sponsorship_identity() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);
        let (_, sponsor_strkey) = sponsor_acc_id();

        // Pool has sponsor sponsor_strkey, but sponsor_strkey is missing from snapshot accounts!
        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "export".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids: pool_ids.clone(),
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: 1,
                    verified_pool_count: 1,
                },
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![
                AccountState {
                    id: TRUSTOR_STRKEY.to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 4,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4900),
                },
                AccountState {
                    id: ISSUER_STRKEY.to_owned(),
                    balance_stroops: 500_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4800),
                },
            ], // sponsor_strkey missing!
            trustlines: vec![],
            pool_share_trustlines: vec![PoolShareState {
                pool_id,
                owner: TRUSTOR_STRKEY.to_owned(),
                asset_a: "FLUTTER".to_owned(),
                asset_a_issuer: ISSUER_STRKEY.to_owned(),
                asset_b: "XLM".to_owned(),
                asset_b_issuer: "native".to_owned(),
                reserve_a: 100,
                reserve_b: 200,
                total_pool_shares: 100,
                owner_pool_shares: 10,
                sponsor: Some(sponsor_strkey),
                last_modified_ledger_seq: Some(4900),
                pool_shares_trust_line_count: None,
            }],
            sponsorship_handoffs: vec![],
        };

        let classification =
            AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
                .unwrap();
        // Degrades to LedgerConsistentIncomplete because sponsor account is unverified!
        assert_eq!(
            classification,
            EvidenceClassification::LedgerConsistentIncomplete
        );
    }

    #[test]
    fn test_adversarial_15_missing_reserve_configuration() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);

        // base_reserve_stroops is None
        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "export".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids,
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::Unproven,
                evidence_classification: None,
            },
            base_reserve_stroops: None,
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![],
            trustlines: vec![],
            pool_share_trustlines: vec![],
            sponsorship_handoffs: vec![],
        };

        let classification =
            AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
                .unwrap();
        assert_eq!(
            classification,
            EvidenceClassification::LedgerConsistentIncomplete
        );
    }

    #[test]
    fn test_adversarial_16_interrupted_capture() {
        let mut mock = MockTransport::new();
        // Network timeout / transport error on getLatestLedger
        mock.set_post_method(
            "getLatestLedger",
            Err("connection timeout after 15s".to_owned()),
        );

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::TransportError(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_17_stale_indexer_data() {
        let pool_hex = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46";
        let mut mock = MockTransport::new();
        mock.set_post_method("getLatestLedger", Ok(serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
        }).to_string()));
        // Horizon returns closed pool
        mock.set_get(format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY), Ok(serde_json::json!({
            "id": TRUSTOR_STRKEY, "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
        }).to_string()));

        // RPC returns empty (key was deleted on-chain)
        mock.set_post_method(
            "getLedgerEntries",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "entries": [], "latestLedger": 5000 }
            })
            .to_string()),
        );

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(
            err,
            DiscoveryError::StaleIndexerData(_) | DiscoveryError::ParseError(_)
        ));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_18_deliberate_mismatched_ledger_sequences_fails_closed() {
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            30,
        );
        let mut mock = MockTransport::new();
        // getLatestLedger returns ledger 5000
        mock.set_post_method(
            "getLatestLedger",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "id": MOCK_LEDGER_HASH, "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
            })
            .to_string()),
        );
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY, "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
            })
            .to_string()),
        );

        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_hash.clone()),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        // Deliberate sequence mismatch: getLedgerEntries returns latestLedger = 5001 != 5000!
        mock.set_post_method(
            "getLedgerEntries",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "entries": [
                        { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100), "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                        { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 500), "lastModifiedLedgerSeq": 4800, "extXdr": "AAAAAA==" },
                        { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUT", Some(1)), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                        { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool_hash, 100), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                        { "key": k_pool, "xdr": pool_xdr, "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                    ],
                    "latestLedger": 5001
                }
            })
            .to_string()),
        );

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(
                TRUSTOR_STRKEY,
                &CreditAsset {
                    code: "FLUT".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
            )
            .unwrap_err();
        // Strict sequence binding fails closed when tip advances during capture and retry fails
        assert!(matches!(
            err,
            DiscoveryError::InconsistentLedgerSequence {
                entry_seq: 5001,
                snapshot_seq: 5000
            }
        ));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[derive(Default)]
    struct SequentialMockTransport {
        ledger_call_count: std::sync::atomic::AtomicUsize,
        horizon_response: String,
        entries_response_5001: String,
    }

    impl HttpTransport for SequentialMockTransport {
        fn post(&self, _url: &str, body: &str) -> Result<String, DiscoveryError> {
            if body.contains("getLatestLedger") {
                let count = self
                    .ledger_call_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if count == 0 {
                    // Attempt 0: header is at sequence 5000
                    Ok(serde_json::json!({
                        "jsonrpc": "2.0", "id": 1,
                        "result": {
                            "id": MOCK_LEDGER_HASH,
                            "protocolVersion": 29,
                            "sequence": 5000,
                            "headerXdr": make_header_xdr(29, 5000, 5_000_000)
                        }
                    })
                    .to_string())
                } else {
                    // Attempt 1: retry captures tip at sequence 5001 matching entries!
                    Ok(serde_json::json!({
                        "jsonrpc": "2.0", "id": 1,
                        "result": {
                            "id": MOCK_LEDGER_HASH,
                            "protocolVersion": 29,
                            "sequence": 5001,
                            "headerXdr": make_header_xdr(29, 5001, 5_000_000)
                        }
                    })
                    .to_string())
                }
            } else if body.contains("getLedgerEntries") {
                Ok(self.entries_response_5001.clone())
            } else {
                Err(DiscoveryError::TransportError("unexpected post".to_owned()))
            }
        }

        fn get(&self, _url: &str) -> Result<String, DiscoveryError> {
            Ok(self.horizon_response.clone())
        }
    }

    #[test]
    fn test_adversarial_19_bounded_retry_succeeds_when_tip_advances_transiently() {
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::Native,
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            30,
        );

        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_hash.clone()),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let entries_response_5001 = serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100), "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 500), "lastModifiedLedgerSeq": 4800, "extXdr": "AAAAAA==" },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUT", Some(1)), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool_hash, 100), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" },
                    { "key": k_pool, "xdr": pool_xdr, "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" },
                ],
                "latestLedger": 5001
            }
        })
        .to_string();

        let transport = SequentialMockTransport {
            ledger_call_count: std::sync::atomic::AtomicUsize::new(0),
            horizon_response: serde_json::json!({
                "id": TRUSTOR_STRKEY,
                "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
            })
            .to_string(),
            entries_response_5001,
        };

        let adapter = AuthoritativeEvidenceAdapter::new(
            transport,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );

        let snapshot = adapter
            .acquire_live_evidence(
                TRUSTOR_STRKEY,
                &CreditAsset {
                    code: "FLUT".to_owned(),
                    issuer: ISSUER_STRKEY.to_owned(),
                },
            )
            .expect("retry captures synchronized ledger state");

        // Verified sequence is synchronized at 5001 without torn state
        assert_eq!(snapshot.ledger_sequence, 5001);
        assert_eq!(snapshot.entries_ledger_sequence, 5001);
        assert_eq!(snapshot.discovery.target_ledger_sequence, 5001);
    }

    #[test]
    fn test_adversarial_20_invalid_ledger_hash_format_rejected() {
        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY, "balances": []
            })
            .to_string()),
        );
        // id is not 64 hex characters
        mock.set_post_method(
            "getLatestLedger",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "id": "invalid-hash", "protocolVersion": 29, "sequence": 5000, "headerXdr": make_header_xdr(29, 5000, 5_000_000) }
            })
            .to_string()),
        );

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::ParseError(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_21_attempted_authority_promotion_rejected() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);

        // Caller crafts an AuthoritativeExport snapshot and sets evidence_classification = CompleteAuthoritativeLedger
        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "core-export-ledger-5000".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids: pool_ids.clone(),
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: 1,
                    verified_pool_count: 1,
                },
                evidence_classification: Some(EvidenceClassification::CompleteAuthoritativeLedger),
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![
                AccountState {
                    id: TRUSTOR_STRKEY.to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 4,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4900),
                },
                AccountState {
                    id: ISSUER_STRKEY.to_owned(),
                    balance_stroops: 500_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4800),
                },
            ],
            trustlines: vec![],
            pool_share_trustlines: vec![],
            sponsorship_handoffs: vec![],
        };

        // CompleteAuthoritativeLedger MUST be unreachable for caller-supplied snapshots; must fail closed with ForgedProvenance
        let err = AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::ForgedProvenance(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_22_forged_source_label_cannot_promote_to_complete() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];
        let manifest_hash = discovery_manifest_sha256(NETWORK_PASSPHRASE, 5000, &pool_ids);

        // Caller labels source as AuthoritativeExport without evidence_classification
        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "forged_export_id".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids: pool_ids.clone(),
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: 1,
                    verified_pool_count: 1,
                },
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![
                AccountState {
                    id: TRUSTOR_STRKEY.to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 4,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4900),
                },
                AccountState {
                    id: ISSUER_STRKEY.to_owned(),
                    balance_stroops: 500_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: Some(4800),
                },
            ],
            trustlines: vec![],
            pool_share_trustlines: vec![],
            sponsorship_handoffs: vec![],
        };

        // Without an independent offline capture verifier, caller-supplied exports safely degrade to LedgerConsistentIncomplete
        let classification =
            AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
                .expect("validation passes but cannot promote");
        assert_eq!(
            classification,
            EvidenceClassification::LedgerConsistentIncomplete
        );
        assert_ne!(
            classification,
            EvidenceClassification::CompleteAuthoritativeLedger
        );
    }

    #[test]
    fn test_adversarial_23_forged_manifest_digest_rejected() {
        let pool_id = "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned();
        let pool_ids = vec![pool_id.clone()];

        // Forged manifest hash
        let snapshot = Snapshot {
            network_passphrase: NETWORK_PASSPHRASE.to_owned(),
            ledger_sequence: 5000,
            entries_ledger_sequence: 5000,
            discovery: DiscoveryProof {
                source: DiscoverySource::AuthoritativeExport {
                    export_id: "export".to_owned(),
                },
                target_ledger_sequence: 5000,
                pool_ids,
                manifest_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
                coverage: DiscoveryCoverage::Unproven,
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(29),
            sponsorship_evidence_complete: true,
            accounts: vec![],
            trustlines: vec![],
            pool_share_trustlines: vec![],
            sponsorship_handoffs: vec![],
        };

        let err = AuthoritativeEvidenceAdapter::<MockTransport>::validate_and_classify(&snapshot)
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::ForgedProvenance(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    fn setup_mock_with_constituent_sdk(
        constituent_entry_xdr: String,
        constituent_key_override: Option<String>,
        constituent_ext_xdr: Option<&str>,
        omit_constituent_entry: bool,
    ) -> (AuthoritativeEvidenceAdapter<MockTransport>, CreditAsset) {
        let (pool_xdr, pool_hash, pool_hex) = make_pool_entry_xdr(
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
            Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"SDK\0"),
                issuer: other_issuer_id(),
            }),
            30,
        );
        let mut mock = MockTransport::new();
        mock.set_post_method(
            "getLatestLedger",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "id": MOCK_LEDGER_HASH,
                    "protocolVersion": 29,
                    "sequence": 5000,
                    "headerXdr": make_header_xdr(29, 5000, 5_000_000)
                }
            })
            .to_string()),
        );

        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY,
                "balances": [
                    { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex },
                    { "asset_type": "credit_alphanum4", "asset_code": "SDK", "asset_issuer": OTHER_ISSUER_STRKEY }
                ]
            }).to_string()),
        );

        let k_trustor = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: trustor_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_issuer = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
            account_id: issuer_id(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_credit_tl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"FLUT"),
                issuer: issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_ptl = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_hash.clone())),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let k_pool = stellar_xdr::LedgerKey::LiquidityPool(stellar_xdr::LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_hash.clone()),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let mut sdk_arr = [0u8; 4];
        sdk_arr[..3].copy_from_slice(b"SDK");
        let k_extra_sdk = stellar_xdr::LedgerKey::Trustline(stellar_xdr::LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(sdk_arr),
                issuer: other_issuer_id(),
            }),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();

        let ext_xdr = constituent_ext_xdr.unwrap_or("AAAAAA==");
        let actual_sdk_key = constituent_key_override.unwrap_or_else(|| k_extra_sdk.clone());

        let mut entries = vec![
            serde_json::json!({ "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100), "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" }),
            serde_json::json!({ "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 500), "lastModifiedLedgerSeq": 4800, "extXdr": "AAAAAA==" }),
            serde_json::json!({ "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUT", Some(1)), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" }),
            serde_json::json!({ "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool_hash, 100), "lastModifiedLedgerSeq": 4950, "extXdr": "AAAAAA==" }),
            serde_json::json!({ "key": k_pool, "xdr": pool_xdr, "lastModifiedLedgerSeq": 4900, "extXdr": "AAAAAA==" }),
        ];

        if !omit_constituent_entry {
            entries.push(serde_json::json!({
                "key": actual_sdk_key,
                "xdr": constituent_entry_xdr,
                "lastModifiedLedgerSeq": 4950,
                "extXdr": ext_xdr
            }));
        }

        mock.set_post_method(
            "getLedgerEntries",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "entries": entries, "latestLedger": 5000 }
            })
            .to_string()),
        );

        let adapter = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let asset = CreditAsset {
            code: "FLUT".to_owned(),
            issuer: ISSUER_STRKEY.to_owned(),
        };
        (adapter, asset)
    }

    #[test]
    fn test_adversarial_24_constituent_trustline_incorrect_asset_code() {
        // Returned constituent trustline has code "EUR" instead of requested "SDK"
        let wrong_code_xdr = make_credit_tl_xdr(trustor_id(), other_issuer_id(), "EUR", Some(1));
        let (adapter, asset) = setup_mock_with_constituent_sdk(wrong_code_xdr, None, None, false);
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .unwrap_err();
        match err {
            DiscoveryError::ParseError(ref msg) => {
                assert!(
                    msg.contains(
                        "constituent credit trustline asset identity contradicts requested asset"
                    ),
                    "unexpected error message: {}",
                    msg
                );
            }
            other => panic!("expected ParseError for wrong asset code, got: {:?}", other),
        }
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_25_constituent_trustline_incorrect_issuer() {
        // Returned constituent trustline has issuer_id() instead of other_issuer_id()
        let wrong_issuer_xdr = make_credit_tl_xdr(trustor_id(), issuer_id(), "SDK", Some(1));
        let (adapter, asset) = setup_mock_with_constituent_sdk(wrong_issuer_xdr, None, None, false);
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .unwrap_err();
        match err {
            DiscoveryError::ParseError(ref msg) => {
                assert!(
                    msg.contains(
                        "constituent credit trustline asset identity contradicts requested asset"
                    ),
                    "unexpected error message: {}",
                    msg
                );
            }
            other => panic!(
                "expected ParseError for wrong asset issuer, got: {:?}",
                other
            ),
        }
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_26_constituent_trustline_malformed_xdr() {
        let malformed_xdr = "AAAAA_NOT_VALID_BASE64_XDR_DATA@@@@".to_owned();
        let (adapter, asset) = setup_mock_with_constituent_sdk(malformed_xdr, None, None, false);
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .unwrap_err();
        match err {
            DiscoveryError::ParseError(ref msg) => {
                assert!(
                    msg.contains("XDR decode error"),
                    "unexpected error message: {}",
                    msg
                );
            }
            other => panic!("expected ParseError for malformed XDR, got: {:?}", other),
        }
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_27_constituent_trustline_incorrect_owner() {
        // Returned constituent trustline is owned by other_issuer_id() instead of trustor_id()
        let wrong_owner_xdr =
            make_credit_tl_xdr(other_issuer_id(), other_issuer_id(), "SDK", Some(1));
        let (adapter, asset) = setup_mock_with_constituent_sdk(wrong_owner_xdr, None, None, false);
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .unwrap_err();
        match err {
            DiscoveryError::WrongTrustor {
                ref expected,
                ref found,
            } => {
                assert_eq!(expected, TRUSTOR_STRKEY);
                assert_eq!(found, OTHER_ISSUER_STRKEY);
            }
            other => panic!(
                "expected WrongTrustor for wrong trustline owner, got: {:?}",
                other
            ),
        }
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_28_constituent_trustline_missing_entry() {
        // RPC response omits constituent trustline entry entirely
        let (adapter, asset) = setup_mock_with_constituent_sdk(String::new(), None, None, true);
        let err = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .unwrap_err();
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_adversarial_29_constituent_trustline_valid_clawback_flag() {
        // Case A: Valid constituent trustline with clawback enabled (flags: 9 = AUTHORIZED | CLAWBACK_ENABLED)
        let valid_clawback_xdr = make_credit_tl_xdr_with_flags(
            trustor_id(),
            other_issuer_id(),
            "SDK",
            Some(1),
            crate::AUTHORIZED_FLAG | crate::TRUSTLINE_CLAWBACK_ENABLED_FLAG,
        );
        let (adapter_cb, asset) =
            setup_mock_with_constituent_sdk(valid_clawback_xdr, None, None, false);
        let snapshot_cb = adapter_cb
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .expect("should acquire valid evidence with constituent trustline");

        // Verify constituent trustline was successfully parsed into snapshot
        let sdk_tl = snapshot_cb
            .trustlines
            .iter()
            .find(|tl| tl.asset.code == "SDK" && tl.asset.issuer == OTHER_ISSUER_STRKEY)
            .expect("SDK constituent trustline should be in snapshot");
        assert_eq!(
            sdk_tl.flags,
            crate::AUTHORIZED_FLAG | crate::TRUSTLINE_CLAWBACK_ENABLED_FLAG
        );

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            tx_source_account: None,
            sequence: None,
            operation_index: None,
            trustor: TRUSTOR_STRKEY.to_owned(),
            asset: asset.clone(),
            before_flags: crate::AUTHORIZED_FLAG,
            after_flags: 0,
        };
        let report_cb = crate::evaluate(&op, &snapshot_cb);
        assert_eq!(report_cb.classification, Classification::UnverifiedForecast);
        assert_eq!(report_cb.pool_redemptions.len(), 1);
        let sdk_cb_forecast = report_cb.pool_redemptions[0]
            .claimable_balances
            .iter()
            .find(|cb| cb.asset == "SDK")
            .expect("SDK claimable balance forecast must exist");
        assert!(
            sdk_cb_forecast.clawback_flag_enabled,
            "SDK claimable balance must have clawback enabled"
        );

        // Case B: Valid constituent trustline with clawback disabled (flags: 1 = AUTHORIZED only)
        let valid_no_cb_xdr = make_credit_tl_xdr_with_flags(
            trustor_id(),
            other_issuer_id(),
            "SDK",
            Some(1),
            crate::AUTHORIZED_FLAG,
        );
        let (adapter_no_cb, _) =
            setup_mock_with_constituent_sdk(valid_no_cb_xdr, None, None, false);
        let snapshot_no_cb = adapter_no_cb
            .acquire_live_evidence(TRUSTOR_STRKEY, &asset)
            .expect("should acquire valid evidence with constituent trustline");
        let report_no_cb = crate::evaluate(&op, &snapshot_no_cb);
        assert_eq!(
            report_no_cb.classification,
            Classification::UnverifiedForecast
        );
        let sdk_no_cb_forecast = report_no_cb.pool_redemptions[0]
            .claimable_balances
            .iter()
            .find(|cb| cb.asset == "SDK")
            .expect("SDK claimable balance forecast must exist");
        assert!(
            !sdk_no_cb_forecast.clawback_flag_enabled,
            "SDK claimable balance must have clawback disabled"
        );
    }

    #[test]
    fn test_adversarial_30_invalid_horizon_balance_identity_rejected() {
        let mut mock = MockTransport::new();
        mock.set_post_method(
            "getLatestLedger",
            Ok(serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "id": MOCK_LEDGER_HASH,
                    "protocolVersion": 29,
                    "sequence": 5000,
                    "headerXdr": make_header_xdr(29, 5000, 5_000_000)
                }
            })
            .to_string()),
        );

        // Case A: Missing asset_code on credit balance
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY,
                "balances": [
                    { "asset_type": "credit_alphanum4", "asset_issuer": OTHER_ISSUER_STRKEY }
                ]
            })
            .to_string()),
        );
        let adapter = AuthoritativeEvidenceAdapter::new(
            mock.clone(),
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err_missing_code = adapter
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err_missing_code, DiscoveryError::ParseError(_)));
        assert_eq!(
            err_missing_code.into_classification(),
            Classification::Inconclusive
        );

        // Case B: Invalid issuer StrKey on credit balance
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY,
                "balances": [
                    { "asset_type": "credit_alphanum4", "asset_code": "SDK", "asset_issuer": "INVALID_STRKEY_BOGUS" }
                ]
            }).to_string()),
        );
        let adapter_bad_key = AuthoritativeEvidenceAdapter::new(
            mock.clone(),
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err_bad_key = adapter_bad_key
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err_bad_key, DiscoveryError::ParseError(_)));
        assert_eq!(
            err_bad_key.into_classification(),
            Classification::Inconclusive
        );

        // Case C: Unknown balance asset_type
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(serde_json::json!({
                "id": TRUSTOR_STRKEY,
                "balances": [
                    { "asset_type": "unknown_soroban_sac_v3" }
                ]
            })
            .to_string()),
        );
        let adapter_unknown_type = AuthoritativeEvidenceAdapter::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            NETWORK_PASSPHRASE,
        );
        let err_unknown_type = adapter_unknown_type
            .acquire_live_evidence(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err_unknown_type, DiscoveryError::ParseError(_)));
        assert_eq!(
            err_unknown_type.into_classification(),
            Classification::Inconclusive
        );
    }
}
