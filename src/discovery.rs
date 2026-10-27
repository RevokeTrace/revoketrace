//! Trusted Discovery Prototype for Phase 1C: Two-Tier Candidate Enumeration and Atomic Core Verification.
//!
//! Tier 1: Blind candidate enumeration via Horizon account balance views.
//! Tier 2: Atomic single-batch verification via Stellar RPC `getLedgerEntries` at the current tip.
//! Reconciles candidate pools pairing the target credit asset against on-chain `liquidityPoolUseCount`.
//! All failures fail closed as `Inconclusive`.

use serde::{Deserialize, Serialize};
use stellar_xdr::{
    AccountEntryExt, AccountEntryExtensionV1Ext, AccountId, AlphaNum4, AlphaNum12, Asset,
    AssetCode4, AssetCode12, Hash, LedgerEntryData, LedgerKey, LedgerKeyAccount,
    LedgerKeyLiquidityPool, LedgerKeyTrustLine, Limits, LiquidityPoolEntryBody, PoolId, PublicKey,
    ReadXdr, TrustLineAsset, TrustLineEntryExt, TrustLineEntryV1Ext, Uint256, WriteXdr,
};

use crate::{
    AccountState, CreditAsset, CreditTrustlineState, DiscoveryCoverage, DiscoveryProof,
    DiscoverySource, PoolShareState, Snapshot, derive_constant_product_pool_id,
    discovery_manifest_sha256,
};

// ---------------------------------------------------------------------------
// StrKey RFC 4648 Base32 Encoding / Decoding
// ---------------------------------------------------------------------------

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode_account_id(bytes: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(35);
    payload.push(0x30); // 'G' version byte (0x30 = 6 << 3)
    payload.extend_from_slice(bytes);
    let crc = crc16_xmodem(&payload);
    payload.push((crc & 0xFF) as u8);
    payload.push(((crc >> 8) & 0xFF) as u8);

    let mut out = String::with_capacity(56);
    let mut buffer = 0u64;
    let mut bits_left = 0;
    for &b in &payload {
        buffer = (buffer << 8) | (b as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }
    out
}

pub fn decode_account_id(strkey: &str) -> Result<[u8; 32], String> {
    if strkey.len() != 56 || !strkey.starts_with('G') {
        return Err("invalid account strkey format".to_owned());
    }
    let mut buffer = 0u64;
    let mut bits_left = 0;
    let mut decoded = Vec::with_capacity(35);
    for c in strkey.chars() {
        let val = match c {
            'A'..='Z' => (c as u8 - b'A') as u64,
            '2'..='7' => (c as u8 - b'2' + 26) as u64,
            _ => return Err("invalid base32 character".to_owned()),
        };
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            decoded.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }
    if decoded.len() != 35 || decoded[0] != 0x30 {
        return Err("invalid version byte in strkey".to_owned());
    }
    let expected_crc = ((decoded[34] as u16) << 8) | (decoded[33] as u16);
    let computed_crc = crc16_xmodem(&decoded[..33]);
    if computed_crc != expected_crc {
        return Err("checksum mismatch in strkey".to_owned());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[1..33]);
    Ok(out)
}

fn account_id_to_bytes(acc: &AccountId) -> [u8; 32] {
    match &acc.0 {
        PublicKey::PublicKeyTypeEd25519(u) => u.0,
    }
}

fn asset_to_parts(asset: &Asset) -> (String, String) {
    match asset {
        Asset::Native => ("XLM".to_owned(), "native".to_owned()),
        Asset::CreditAlphanum4(a) => {
            let code = String::from_utf8_lossy(&a.asset_code.0)
                .trim_matches('\0')
                .to_owned();
            let issuer = encode_account_id(&account_id_to_bytes(&a.issuer));
            (code, issuer)
        }
        Asset::CreditAlphanum12(a) => {
            let code = String::from_utf8_lossy(&a.asset_code.0)
                .trim_matches('\0')
                .to_owned();
            let issuer = encode_account_id(&account_id_to_bytes(&a.issuer));
            (code, issuer)
        }
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryError {
    TransportError(String),
    ParseError(String),
    MissingAccount(String),
    MissingCreditTrustline(String),
    MissingPoolShareTrustline(String),
    MissingLiquidityPoolEntry(String),
    MissingCounter(String),
    InvalidPoolDerivation {
        expected: String,
        derived: String,
    },
    DuplicatePoolId(String),
    WrongTrustor {
        expected: String,
        found: String,
    },
    InconsistentLedgerSequence {
        entry_seq: u32,
        snapshot_seq: u32,
    },
    CounterMismatch {
        expected_count: u32,
        discovered_count: u32,
    },
    StaleIndexerData(String),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransportError(e) => write!(f, "transport error: {}", e),
            Self::ParseError(e) => write!(f, "parse error: {}", e),
            Self::MissingAccount(a) => write!(f, "missing account entry: {}", a),
            Self::MissingCreditTrustline(t) => write!(f, "missing credit trustline: {}", t),
            Self::MissingPoolShareTrustline(p) => write!(f, "missing pool share trustline: {}", p),
            Self::MissingLiquidityPoolEntry(p) => write!(f, "missing liquidity pool entry: {}", p),
            Self::MissingCounter(m) => write!(f, "missing counter: {}", m),
            Self::InvalidPoolDerivation { expected, derived } => {
                write!(
                    f,
                    "pool ID derivation mismatch: expected {}, derived {}",
                    expected, derived
                )
            }
            Self::DuplicatePoolId(p) => write!(f, "duplicate pool ID: {}", p),
            Self::WrongTrustor { expected, found } => {
                write!(f, "wrong trustor: expected {}, found {}", expected, found)
            }
            Self::InconsistentLedgerSequence {
                entry_seq,
                snapshot_seq,
            } => {
                write!(
                    f,
                    "inconsistent ledger sequence: entry {} > snapshot {}",
                    entry_seq, snapshot_seq
                )
            }
            Self::CounterMismatch {
                expected_count,
                discovered_count,
            } => {
                write!(
                    f,
                    "liquidityPoolUseCount mismatch: expected {}, discovered {}",
                    expected_count, discovered_count
                )
            }
            Self::StaleIndexerData(s) => write!(f, "stale indexer data: {}", s),
        }
    }
}

impl std::error::Error for DiscoveryError {}

// ---------------------------------------------------------------------------
// HTTP Transport Trait & Implementations
// ---------------------------------------------------------------------------

pub trait HttpTransport {
    fn post(&self, url: &str, body: &str) -> Result<String, DiscoveryError>;
    fn get(&self, url: &str) -> Result<String, DiscoveryError>;
}

#[derive(Debug, Default, Clone)]
pub struct CurlTransport {
    pub timeout_secs: u32,
}

impl CurlTransport {
    pub fn new(timeout_secs: u32) -> Self {
        Self { timeout_secs }
    }
}

impl HttpTransport for CurlTransport {
    fn post(&self, url: &str, body: &str) -> Result<String, DiscoveryError> {
        let timeout_str = self.timeout_secs.to_string();
        let output = std::process::Command::new("curl")
            .arg("-s")
            .arg("-X")
            .arg("POST")
            .arg(url)
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-H")
            .arg("User-Agent: RevokeTrace-Discovery/0.1.0")
            .arg("--max-time")
            .arg(&timeout_str)
            .arg("-d")
            .arg(body)
            .output()
            .map_err(|e| DiscoveryError::TransportError(format!("curl post failed: {}", e)))?;

        if !output.status.success() {
            return Err(DiscoveryError::TransportError(format!(
                "curl post exited with status {}",
                output.status
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|e| DiscoveryError::ParseError(format!("invalid UTF-8 in response: {}", e)))
    }

    fn get(&self, url: &str) -> Result<String, DiscoveryError> {
        let timeout_str = self.timeout_secs.to_string();
        let output = std::process::Command::new("curl")
            .arg("-s")
            .arg("-X")
            .arg("GET")
            .arg(url)
            .arg("-H")
            .arg("User-Agent: RevokeTrace-Discovery/0.1.0")
            .arg("--max-time")
            .arg(&timeout_str)
            .output()
            .map_err(|e| DiscoveryError::TransportError(format!("curl get failed: {}", e)))?;

        if !output.status.success() {
            return Err(DiscoveryError::TransportError(format!(
                "curl get exited with status {}",
                output.status
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|e| DiscoveryError::ParseError(format!("invalid UTF-8 in response: {}", e)))
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockTransport {
    pub get_responses: std::collections::BTreeMap<String, Result<String, String>>,
    pub post_responses: std::collections::BTreeMap<String, Result<String, String>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_get(&mut self, url: impl Into<String>, resp: Result<String, String>) {
        self.get_responses.insert(url.into(), resp);
    }

    pub fn set_post(&mut self, url: impl Into<String>, resp: Result<String, String>) {
        self.post_responses.insert(url.into(), resp);
    }
}

impl HttpTransport for MockTransport {
    fn post(&self, url: &str, _body: &str) -> Result<String, DiscoveryError> {
        if let Some(resp) = self.post_responses.get(url) {
            resp.clone().map_err(DiscoveryError::TransportError)
        } else {
            Err(DiscoveryError::TransportError(format!(
                "unhandled mock POST for {}",
                url
            )))
        }
    }

    fn get(&self, url: &str) -> Result<String, DiscoveryError> {
        if let Some(resp) = self.get_responses.get(url) {
            resp.clone().map_err(DiscoveryError::TransportError)
        } else {
            Err(DiscoveryError::TransportError(format!(
                "unhandled mock GET for {}",
                url
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Horizon & RPC Response Wire Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HorizonBalance {
    pub asset_type: String,
    #[serde(default)]
    pub liquidity_pool_id: Option<String>,
    #[serde(default)]
    pub asset_code: Option<String>,
    #[serde(default)]
    pub asset_issuer: Option<String>,
    #[serde(default)]
    pub balance: Option<String>,
    #[serde(default)]
    pub last_modified_ledger: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HorizonAccountResponse {
    pub id: String,
    #[serde(default)]
    pub subentry_count: u32,
    #[serde(default)]
    pub balances: Vec<HorizonBalance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEntry {
    pub key: String,
    pub xdr: String,
    #[serde(rename = "lastModifiedLedgerSeq")]
    pub last_modified_ledger_seq: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResult {
    pub entries: Vec<RpcEntry>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub result: Option<RpcResult>,
    pub error: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Discovery Pipeline
// ---------------------------------------------------------------------------

pub struct DiscoveryPipeline<T: HttpTransport> {
    pub transport: T,
    pub horizon_url: String,
    pub rpc_url: String,
    pub network_passphrase: String,
}

impl<T: HttpTransport> DiscoveryPipeline<T> {
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

    /// Discovers candidate pool IDs from Horizon and verifies the complete state
    /// atomically against Stellar RPC in a single batch.
    pub fn discover_and_verify(
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

        // Tier 1: Candidate Enumeration via Horizon
        let horizon_account_url = format!(
            "{}/accounts/{}",
            self.horizon_url.trim_end_matches('/'),
            trustor
        );
        let horizon_body = self.transport.get(&horizon_account_url)?;
        let horizon_acc: HorizonAccountResponse =
            serde_json::from_str(&horizon_body).map_err(|e| {
                DiscoveryError::ParseError(format!("failed to parse Horizon account JSON: {}", e))
            })?;

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

        // Tier 2: Single-Batch Atomic Request to Stellar RPC
        let trustor_acc_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(trustor_bytes)));
        let issuer_acc_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes)));

        let mut keys_b64 = Vec::new();
        let mut key_account_trustor = String::new();
        let mut key_account_issuer = String::new();
        let mut key_credit_tl = String::new();
        let mut key_pool_tls = Vec::new();
        let mut key_pools = Vec::new();

        // 1. Trustor Account Key
        let k_trustor = LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_acc_id.clone(),
        });
        let k_trustor_b64 = k_trustor
            .to_xdr_base64(Limits::none())
            .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
        key_account_trustor.clone_from(&k_trustor_b64);
        keys_b64.push(k_trustor_b64);

        // 2. Issuer Account Key
        let k_issuer = LedgerKey::Account(LedgerKeyAccount {
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
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(code),
                issuer: issuer_acc_id.clone(),
            })
        } else {
            let mut code = [0u8; 12];
            code[..asset.code.len()].copy_from_slice(asset.code.as_bytes());
            TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(code),
                issuer: issuer_acc_id.clone(),
            })
        };
        let k_credit_tl = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_acc_id.clone(),
            asset: tl_asset,
        });
        let k_credit_tl_b64 = k_credit_tl
            .to_xdr_base64(Limits::none())
            .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
        key_credit_tl.clone_from(&k_credit_tl_b64);
        keys_b64.push(k_credit_tl_b64);

        // 4. Candidate Pool-Share Trustlines and Liquidity Pools
        for pool_id in &candidate_pool_ids {
            let mut pool_bytes = [0u8; 32];
            hex::decode_to_slice(pool_id, &mut pool_bytes)
                .map_err(|e| DiscoveryError::ParseError(format!("hex decode failed: {}", e)))?;

            // Pool share trustline
            let k_ptl = LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: trustor_acc_id.clone(),
                asset: TrustLineAsset::PoolShare(PoolId(Hash(pool_bytes))),
            });
            let k_ptl_b64 = k_ptl
                .to_xdr_base64(Limits::none())
                .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
            key_pool_tls.push((pool_id.clone(), k_ptl_b64.clone()));
            keys_b64.push(k_ptl_b64);

            // Liquidity pool entry
            let k_pool = LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
                liquidity_pool_id: PoolId(Hash(pool_bytes)),
            });
            let k_pool_b64 = k_pool
                .to_xdr_base64(Limits::none())
                .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
            key_pools.push((pool_id.clone(), k_pool_b64.clone()));
            keys_b64.push(k_pool_b64);
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

        let latest_ledger = rpc_result.latest_ledger;

        // Map entries by key
        let mut entry_map = std::collections::BTreeMap::new();
        for entry in &rpc_result.entries {
            // Check sequence consistency
            if entry.last_modified_ledger_seq > latest_ledger {
                return Err(DiscoveryError::InconsistentLedgerSequence {
                    entry_seq: entry.last_modified_ledger_seq,
                    snapshot_seq: latest_ledger,
                });
            }
            entry_map.insert(entry.key.clone(), entry);
        }

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
                let (selling_liab, num_sponsoring, num_sponsored) = match acc.ext {
                    AccountEntryExt::V1(v1) => match v1.ext {
                        AccountEntryExtensionV1Ext::V2(v2) => (
                            v1.liabilities.selling as u64,
                            v2.num_sponsoring,
                            v2.num_sponsored,
                        ),
                        _ => (v1.liabilities.selling as u64, 0, 0),
                    },
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
                let (selling_liab, num_sponsoring, num_sponsored) = match acc.ext {
                    AccountEntryExt::V1(v1) => match v1.ext {
                        AccountEntryExtensionV1Ext::V2(v2) => (
                            v1.liabilities.selling as u64,
                            v2.num_sponsoring,
                            v2.num_sponsored,
                        ),
                        _ => (v1.liabilities.selling as u64, 0, 0),
                    },
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

        // Parse Credit Trustline
        let credit_tl_entry = entry_map.get(&key_credit_tl).ok_or_else(|| {
            DiscoveryError::MissingCreditTrustline(format!("{}:{}", asset.code, asset.issuer))
        })?;
        let credit_tl_data = LedgerEntryData::from_xdr_base64(&credit_tl_entry.xdr, Limits::none())
            .map_err(|e| {
                DiscoveryError::ParseError(format!("credit trustline XDR decode error: {}", e))
            })?;

        let (flags, liquidity_pool_use_count) = match credit_tl_data {
            LedgerEntryData::Trustline(tl) => {
                let use_count = match tl.ext {
                    TrustLineEntryExt::V1(v1) => match v1.ext {
                        TrustLineEntryV1Ext::V2(v2) => {
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
            sponsor: None,
            liquidity_pool_use_count: Some(use_count),
            last_modified_ledger_seq: Some(credit_tl_entry.last_modified_ledger_seq),
        };

        // Parse Candidate Pools and Cryptographically Verify
        let mut affected_pools = Vec::new();
        let mut matching_pool_ids = Vec::new();

        for (pool_id, k_pool_b64) in &key_pools {
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

            let owner_shares = match ptl_data {
                LedgerEntryData::Trustline(tl) => {
                    if tl.account_id != trustor_acc_id {
                        return Err(DiscoveryError::WrongTrustor {
                            expected: trustor.to_owned(),
                            found: encode_account_id(&account_id_to_bytes(&tl.account_id)),
                        });
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

                        let (asset_a, asset_a_issuer) = asset_to_parts(&cp.params.asset_a);
                        let (asset_b, asset_b_issuer) = asset_to_parts(&cp.params.asset_b);

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
                            sponsor: None,
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

            // Check if this pool pairs the target credit asset
            let pairs_target_asset = (pool_state.asset_a == asset.code
                && pool_state.asset_a_issuer == asset.issuer)
                || (pool_state.asset_b == asset.code && pool_state.asset_b_issuer == asset.issuer);

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
            discovery_manifest_sha256(&self.network_passphrase, latest_ledger, &matching_pool_ids);

        let snapshot = Snapshot {
            network_passphrase: self.network_passphrase.clone(),
            ledger_sequence: latest_ledger,
            entries_ledger_sequence: latest_ledger,
            discovery: DiscoveryProof {
                source: DiscoverySource::TwoTierDiscovery {
                    horizon_endpoint: self.horizon_url.clone(),
                    rpc_endpoint: self.rpc_url.clone(),
                },
                target_ledger_sequence: latest_ledger,
                pool_ids: matching_pool_ids,
                manifest_sha256: manifest_hash,
                coverage: DiscoveryCoverage::AuthoritativeReconciled {
                    liquidity_pool_use_count: use_count,
                    verified_pool_count: discovered_count,
                },
            },
            base_reserve_stroops: 5_000_000,
            accounts: vec![trustor_state, issuer_state],
            trustlines: vec![credit_tl_state],
            pool_share_trustlines: affected_pools,
            sponsorship_handoffs: Vec::new(),
        };

        Ok(snapshot)
    }
}

impl DiscoveryError {
    /// Maps any discovery refusal into the engine's conservative outcome (`Inconclusive`).
    pub fn into_classification(&self) -> crate::Classification {
        crate::Classification::Inconclusive
    }
}

// ---------------------------------------------------------------------------
// Adversarial Negative & Positive Test Suite (Phase 1C)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AUTHORIZED_FLAG, Classification, OperationSpec, Transition, evaluate};
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext,
        AccountEntryExtensionV2, AccountEntryExtensionV2Ext, AlphaNum4, AlphaNum12, Asset,
        AssetCode4, AssetCode12, Hash, LedgerEntryData, LedgerKey, LedgerKeyAccount,
        LedgerKeyLiquidityPool, LedgerKeyTrustLine, Liabilities, Limits,
        LiquidityPoolConstantProductParameters, LiquidityPoolEntry, LiquidityPoolEntryBody,
        LiquidityPoolEntryConstantProduct, PoolId, PublicKey, SequenceNumber, String32, StringM,
        Thresholds, TrustLineAsset, TrustLineEntry, TrustLineEntryExt, TrustLineEntryExtensionV2,
        TrustLineEntryExtensionV2Ext, TrustLineEntryV1, TrustLineEntryV1Ext, Uint256, VecM,
        WriteXdr,
    };

    const TRUSTOR_STRKEY: &str = "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB";
    const ISSUER_STRKEY: &str = "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG";
    const OTHER_ISSUER_STRKEY: &str = "GA5Q3FBUPYK4T3BQDILVTDFN2TCLLNBDYABMFZRXTE2BLXP5CZXOQFWM";

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

    fn credit_asset_flutter() -> CreditAsset {
        CreditAsset {
            code: "FLUTTER".to_owned(),
            issuer: ISSUER_STRKEY.to_owned(),
        }
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
                    num_sponsoring: 0,
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
        let asset = if code.len() <= 4 {
            let mut arr = [0u8; 4];
            arr[..code.len()].copy_from_slice(code.as_bytes());
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(arr),
                issuer,
            })
        } else {
            let mut arr = [0u8; 12];
            arr[..code.len()].copy_from_slice(code.as_bytes());
            TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(arr),
                issuer,
            })
        };

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
            flags: 1, // AUTHORIZED
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
            flags: 0,
            ext: TrustLineEntryExt::V0,
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_lp_entry_xdr(pool_id: &Hash, asset_a: &Asset, asset_b: &Asset, fee: i32) -> String {
        let entry = LedgerEntryData::LiquidityPool(LiquidityPoolEntry {
            liquidity_pool_id: PoolId(pool_id.clone()),
            body: LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
                LiquidityPoolEntryConstantProduct {
                    params: LiquidityPoolConstantProductParameters {
                        asset_a: asset_a.clone(),
                        asset_b: asset_b.clone(),
                        fee,
                    },
                    reserve_a: 1_000_000_000,
                    reserve_b: 2_000_000_000,
                    total_pool_shares: 500_000_000,
                    pool_shares_trust_line_count: 1,
                },
            ),
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    fn get_canonical_pool1() -> (String, Hash, Asset, Asset) {
        let mut sdk_code = [0u8; 4];
        sdk_code[..3].copy_from_slice(b"SDK");
        let sdk = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(sdk_code),
            issuer: other_issuer_id(),
        });
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let flutter = Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(flutter_code),
            issuer: issuer_id(),
        });
        let pool_id = derive_constant_product_pool_id(&sdk, &flutter, 30).unwrap();
        (hex::encode(pool_id.0), pool_id, sdk, flutter)
    }

    fn get_canonical_pool2() -> (String, Hash, Asset, Asset) {
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let flutter = Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(flutter_code),
            issuer: issuer_id(),
        });
        let pool_id = derive_constant_product_pool_id(&Asset::Native, &flutter, 30).unwrap();
        (hex::encode(pool_id.0), pool_id, Asset::Native, flutter)
    }

    fn key_to_b64(key: &LedgerKey) -> String {
        key.to_xdr_base64(Limits::none()).unwrap()
    }

    // -----------------------------------------------------------------------
    // Test 1: Single affected pool
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_single_affected_pool() {
        let (pool1_hex, pool1_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                {
                    "asset_type": "liquidity_pool_shares",
                    "liquidity_pool_id": pool1_hex,
                    "balance": "100.0"
                }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));

        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool1_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool1_id.clone()),
        }));

        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool1_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&pool1_id, &asset_a, &asset_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let snapshot = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .expect("discovery should succeed");

        assert_eq!(snapshot.pool_share_trustlines.len(), 1);
        assert_eq!(snapshot.pool_share_trustlines[0].pool_id, pool1_hex);

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            trustor: TRUSTOR_STRKEY.to_owned(),
            sequence: 1,
            operation_index: 0,
            asset: credit_asset_flutter(),
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_eq!(report.pool_redemptions.len(), 1);
        assert!(report.errors.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 2: Multiple affected pools
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_multiple_affected_pools() {
        let (pool1_hex, pool1_id, asset1_a, asset1_b) = get_canonical_pool1();
        let (pool2_hex, pool2_id, asset2_a, asset2_b) = get_canonical_pool2();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex },
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool2_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));

        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl1 = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool1_id.clone())),
        }));
        let k_lp1 = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool1_id.clone()),
        }));
        let k_ptl2 = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool2_id.clone())),
        }));
        let k_lp2 = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool2_id.clone()),
        }));

        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(2)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl1, "xdr": make_pool_tl_xdr(trustor_id(), &pool1_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp1, "xdr": make_lp_entry_xdr(&pool1_id, &asset1_a, &asset1_b, 30), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl2, "xdr": make_pool_tl_xdr(trustor_id(), &pool2_id, 200_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp2, "xdr": make_lp_entry_xdr(&pool2_id, &asset2_a, &asset2_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let snapshot = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .expect("discovery should succeed");

        assert_eq!(snapshot.pool_share_trustlines.len(), 2);

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            trustor: TRUSTOR_STRKEY.to_owned(),
            sequence: 1,
            operation_index: 0,
            asset: credit_asset_flutter(),
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_eq!(report.pool_redemptions.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Test 3: No affected pools (zero pools)
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_zero_affected_pools() {
        let target_ledger = 5000000;
        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "native", "balance": "100.0" }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));

        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(0)), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let snapshot = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .expect("discovery should succeed");

        assert_eq!(snapshot.pool_share_trustlines.len(), 0);

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            trustor: TRUSTOR_STRKEY.to_owned(),
            sequence: 1,
            operation_index: 0,
            asset: credit_asset_flutter(),
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_eq!(report.transition, Transition::ForcedPoolRedemption);
        assert!(report.pool_redemptions.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 4: Missing candidate (Horizon dropped/lagged a pool)
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_missing_candidate() {
        let (pool1_hex, pool1_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        // Horizon only returned 1 pool
        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool1_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool1_id.clone()),
        }));

        // But on-chain credit trustline says liquidityPoolUseCount is 2!
        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(2)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool1_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&pool1_id, &asset_a, &asset_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert_eq!(
            err,
            DiscoveryError::CounterMismatch {
                expected_count: 2,
                discovered_count: 1
            }
        );
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 5: Duplicate candidate returned by Horizon
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_duplicate_candidate() {
        let (pool1_hex, _, _, _) = get_canonical_pool1();
        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex },
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert_eq!(err, DiscoveryError::DuplicatePoolId(pool1_hex));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 6: Wrong issuer with matching asset code
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_wrong_issuer_matching_code() {
        // Pool pairs FLUTTER:other_issuer instead of FLUTTER:issuer
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let wrong_flutter = Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(flutter_code),
            issuer: other_issuer_id(), // Wrong issuer!
        });
        let pool_id = derive_constant_product_pool_id(&Asset::Native, &wrong_flutter, 30).unwrap();
        let pool_hex = hex::encode(pool_id.0);
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_id.clone()),
        }));

        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&pool_id, &Asset::Native, &wrong_flutter, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        // Spurious pool pairing wrong issuer is ignored; count mismatch occurs (expected 1, discovered 0)
        assert_eq!(
            err,
            DiscoveryError::CounterMismatch {
                expected_count: 1,
                discovered_count: 0
            }
        );
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 7: Wrong trustor on pool share
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_wrong_trustor() {
        let (pool1_hex, pool1_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool1_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool1_id.clone()),
        }));

        // The pool share trustline on-chain has wrong owner (other_issuer_id instead of trustor_id)
        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(other_issuer_id(), &pool1_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&pool1_id, &asset_a, &asset_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert_eq!(
            err,
            DiscoveryError::WrongTrustor {
                expected: TRUSTOR_STRKEY.to_owned(),
                found: OTHER_ISSUER_STRKEY.to_owned(),
            }
        );
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 8: Incorrect pool ID (does not match canonical constant product hash)
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_incorrect_pool_id() {
        let (pool1_hex, _, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let mut pool_bytes = [0u8; 32];
        hex::decode_to_slice(&pool1_hex, &mut pool_bytes).unwrap();
        let fake_pool_id = Hash(pool_bytes);

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(fake_pool_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(fake_pool_id.clone()),
        }));

        // The pool body has fee = 50 instead of 30, so its canonical ID is different!
        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &fake_pool_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&fake_pool_id, &asset_a, &asset_b, 50), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::InvalidPoolDerivation { .. }));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 9: Mixed ledger states (entry has lastModifiedLedgerSeq > latestLedger)
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_mixed_ledger_states() {
        let (pool1_hex, pool1_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool1_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool1_id.clone()),
        }));

        // One entry has lastModifiedLedgerSeq = 5000001 > latestLedger 5000000!
        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger + 1 },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool1_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&pool1_id, &asset_a, &asset_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert_eq!(
            err,
            DiscoveryError::InconsistentLedgerSequence {
                entry_seq: target_ledger + 1,
                snapshot_seq: target_ledger
            }
        );
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 10: Missing counter (credit trustline lacks V2 extension)
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_missing_counter() {
        let (pool1_hex, pool1_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool1_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool1_id.clone()),
        }));

        // Credit trustline has None for use_count (no V2 extension)
        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", None), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool1_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&pool1_id, &asset_a, &asset_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::MissingCounter(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 11: Incomplete pagination / truncated JSON response
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_incomplete_pagination() {
        let truncated_json = "{\"id\": \"GAPOZN3...\", \"balances\": ["; // Truncated mid-stream
        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(truncated_json.to_owned()),
        );

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::ParseError(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 12: Provider error or timeout
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_provider_error_or_timeout() {
        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Err("connection timeout after 10000ms".to_owned()),
        );

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::TransportError(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 13: Stale indexer data (deleted pool on-chain)
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_stale_indexer_data() {
        let (pool1_hex, _pool1_id, _, _) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        // Pool was deleted on-chain, so RPC entries does NOT contain k_ptl or k_lp!
        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let err = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert!(matches!(err, DiscoveryError::StaleIndexerData(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    // -----------------------------------------------------------------------
    // Test 14: Forged manifest metadata fails closed in preflight engine
    // -----------------------------------------------------------------------
    #[test]
    fn test_discovery_forged_manifest_metadata() {
        let (pool1_hex, pool1_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex }
            ]
        })
        .to_string();

        let k_trustor = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: trustor_id(),
        }));
        let k_issuer = key_to_b64(&LedgerKey::Account(LedgerKeyAccount {
            account_id: issuer_id(),
        }));
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let k_credit_tl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(flutter_code),
                issuer: issuer_id(),
            }),
        }));
        let k_ptl = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool1_id.clone())),
        }));
        let k_lp = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool1_id.clone()),
        }));

        let rpc_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": k_trustor, "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_issuer, "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_credit_tl, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_ptl, "xdr": make_pool_tl_xdr(trustor_id(), &pool1_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": k_lp, "xdr": make_lp_entry_xdr(&pool1_id, &asset_a, &asset_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        }).to_string();

        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_json));

        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );

        let mut snapshot = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap();

        // Adversary forges the manifest hash or target ledger
        snapshot.discovery.manifest_sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: ISSUER_STRKEY.to_owned(),
            trustor: TRUSTOR_STRKEY.to_owned(),
            sequence: 1,
            operation_index: 0,
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
                .any(|e| e.contains("discovery manifest hash is invalid"))
        );
    }
}
