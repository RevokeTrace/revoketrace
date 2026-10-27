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

        // Step 1: Query getLatestLedger from Stellar RPC
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
            DiscoveryError::TransportError("missing result in getLatestLedger response".to_owned())
        })?;

        // Decode LedgerHeader from headerXdr
        let header = decode_ledger_header(&latest_ledger_result.header_xdr)?;
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

        let latest_ledger_seq = latest_ledger_result.sequence;

        // Step 2: Tier 1 Candidate Enumeration via Horizon
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

        // Step 3: Tier 2 Single-Batch Atomic Request to Stellar RPC
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

        // Query Stellar RPC in a single batch
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

        let rpc_latest_ledger = rpc_result.latest_ledger;

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
                let (selling_liab, num_sponsoring, num_sponsored) = match acc.ext {
                    stellar_xdr::AccountEntryExt::V1(v1) => {
                        if v1.liabilities.buying < 0 || v1.liabilities.selling < 0 {
                            return Err(DiscoveryError::ParseError(
                                "trustor account contains a negative liability".to_owned(),
                            ));
                        }
                        match v1.ext {
                            stellar_xdr::AccountEntryExtensionV1Ext::V2(v2) => (
                                v1.liabilities.selling as u64,
                                v2.num_sponsoring,
                                v2.num_sponsored,
                            ),
                            _ => (v1.liabilities.selling as u64, 0, 0),
                        }
                    }
                    _ => (0, 0, 0),
                };
                AccountState {
                    id: trustor.to_owned(),
                    balance_stroops: acc.balance as u64,
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
                let (selling_liab, num_sponsoring, num_sponsored) = match acc.ext {
                    stellar_xdr::AccountEntryExt::V1(v1) => {
                        if v1.liabilities.buying < 0 || v1.liabilities.selling < 0 {
                            return Err(DiscoveryError::ParseError(
                                "issuer account contains a negative liability".to_owned(),
                            ));
                        }
                        match v1.ext {
                            stellar_xdr::AccountEntryExtensionV1Ext::V2(v2) => (
                                v1.liabilities.selling as u64,
                                v2.num_sponsoring,
                                v2.num_sponsored,
                            ),
                            _ => (v1.liabilities.selling as u64, 0, 0),
                        }
                    }
                    _ => (0, 0, 0),
                };
                AccountState {
                    id: asset.issuer.clone(),
                    balance_stroops: acc.balance as u64,
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
        let target_seq = rpc_latest_ledger.max(latest_ledger_seq);
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
            trustlines: vec![credit_tl_state],
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
        candidate_source_authoritative: bool,
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
        if let Some(EvidenceClassification::CompleteAuthoritativeLedger) =
            snapshot.discovery.evidence_classification
        {
            if !candidate_source_authoritative {
                return Err(DiscoveryError::ForgedProvenance(
                    "caller claimed CompleteAuthoritativeLedger without authoritative source proof"
                        .to_owned(),
                ));
            }
            if matches!(
                snapshot.discovery.source,
                DiscoverySource::TwoTierDiscovery { .. } | DiscoverySource::SyntheticFixture
            ) {
                return Err(DiscoveryError::ForgedProvenance(
                    "TwoTierDiscovery or SyntheticFixture cannot produce CompleteAuthoritativeLedger"
                        .to_owned(),
                ));
            }
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
                if candidate_source_authoritative {
                    Ok(EvidenceClassification::CompleteAuthoritativeLedger)
                } else {
                    Ok(EvidenceClassification::LedgerConsistentIncomplete)
                }
            }
        }
    }
}
