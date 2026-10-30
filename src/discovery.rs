//! Bounded two-tier candidate enumeration and RPC verification.
//!
//! Tier 1: Blind candidate enumeration via Horizon account balance views.
//! Tier 2: Atomic single-batch verification via Stellar RPC `getLedgerEntries` at the current tip.
//! Reconciles supplied candidate pools pairing the target credit asset against on-chain
//! `liquidityPoolUseCount`.
//! This adapter is used by the CLI's read-only live path. It verifies the
//! returned candidate set and current-tip ledger entries, but cannot prove
//! exhaustive or historical ledger coverage. All failures fail closed as
//! `Inconclusive`.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Stdio};
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

pub(crate) fn account_id_to_bytes(acc: &AccountId) -> [u8; 32] {
    match &acc.0 {
        PublicKey::PublicKeyTypeEd25519(u) => u.0,
    }
}

pub(crate) fn decode_pool_id(pool_id: &str) -> Result<PoolId, DiscoveryError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(pool_id, &mut bytes)
        .map_err(|e| DiscoveryError::ParseError(format!("invalid pool ID: {}", e)))?;
    Ok(PoolId(Hash(bytes)))
}

pub(crate) fn asset_to_parts(asset: &Asset) -> (String, String) {
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
    RpcBatchTooLarge {
        requested: usize,
        maximum: usize,
    },
    UnsupportedProtocolVersion {
        version: u32,
        minimum: u32,
    },
    MissingReserveConfiguration(String),
    IncorrectNetworkPassphrase {
        expected: String,
        found: String,
    },
    IncorrectSponsorshipIdentity {
        expected: String,
        found: String,
    },
    MissingDeletionRecord(String),
    DeltaTreatedAsFullSnapshot(String),
    TruncatedArchiveOrCapture(String),
    ForgedProvenance(String),
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
            Self::RpcBatchTooLarge { requested, maximum } => write!(
                f,
                "RPC batch contains {} keys, exceeding the single-request maximum of {}",
                requested, maximum
            ),
            Self::UnsupportedProtocolVersion { version, minimum } => write!(
                f,
                "unsupported protocol version: {} < minimum required {}",
                version, minimum
            ),
            Self::MissingReserveConfiguration(s) => {
                write!(f, "missing reserve configuration: {}", s)
            }
            Self::IncorrectNetworkPassphrase { expected, found } => write!(
                f,
                "incorrect network passphrase: expected {}, found {}",
                expected, found
            ),
            Self::IncorrectSponsorshipIdentity { expected, found } => write!(
                f,
                "incorrect sponsorship identity: expected {}, found {}",
                expected, found
            ),
            Self::MissingDeletionRecord(s) => write!(f, "missing deletion record: {}", s),
            Self::DeltaTreatedAsFullSnapshot(s) => {
                write!(f, "delta treated as full snapshot: {}", s)
            }
            Self::TruncatedArchiveOrCapture(s) => {
                write!(f, "truncated archive or capture: {}", s)
            }
            Self::ForgedProvenance(s) => write!(f, "forged provenance: {}", s),
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

const MAX_HTTP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

impl CurlTransport {
    pub fn new(timeout_secs: u32) -> Self {
        Self { timeout_secs }
    }
}

fn collect_curl_output(mut command: Command, action: &str) -> Result<String, DiscoveryError> {
    command.stdout(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        DiscoveryError::TransportError(format!("curl {} failed to start: {}", action, error))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        DiscoveryError::TransportError(format!("curl {} did not provide stdout", action))
    })?;
    let mut bytes = Vec::new();
    let read_result = stdout
        .take((MAX_HTTP_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    if let Err(error) = read_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(DiscoveryError::TransportError(format!(
            "curl {} response read failed: {}",
            action, error
        )));
    }
    if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(DiscoveryError::TransportError(format!(
            "curl {} response exceeds the {}-byte limit",
            action, MAX_HTTP_RESPONSE_BYTES
        )));
    }
    let status = child.wait().map_err(|error| {
        DiscoveryError::TransportError(format!("curl {} wait failed: {}", action, error))
    })?;
    if !status.success() {
        return Err(DiscoveryError::TransportError(format!(
            "curl {} exited with status {}",
            action, status
        )));
    }
    String::from_utf8(bytes).map_err(|error| {
        DiscoveryError::ParseError(format!("invalid UTF-8 in response: {}", error))
    })
}

impl HttpTransport for CurlTransport {
    fn post(&self, url: &str, body: &str) -> Result<String, DiscoveryError> {
        let timeout_str = self.timeout_secs.to_string();
        let mut command = Command::new("curl");
        command
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
            .arg(body);
        collect_curl_output(command, "post")
    }

    fn get(&self, url: &str) -> Result<String, DiscoveryError> {
        let timeout_str = self.timeout_secs.to_string();
        let mut command = Command::new("curl");
        command
            .arg("-s")
            .arg("-X")
            .arg("GET")
            .arg(url)
            .arg("-H")
            .arg("User-Agent: RevokeTrace-Discovery/0.1.0")
            .arg("--max-time")
            .arg(&timeout_str);
        collect_curl_output(command, "get")
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockTransport {
    pub get_responses: std::collections::BTreeMap<String, Result<String, String>>,
    pub post_responses: std::collections::BTreeMap<String, Result<String, String>>,
    pub post_method_responses: std::collections::BTreeMap<String, Result<String, String>>,
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

    pub fn set_post_method(&mut self, method: impl Into<String>, resp: Result<String, String>) {
        self.post_method_responses.insert(method.into(), resp);
    }
}

impl HttpTransport for MockTransport {
    fn post(&self, url: &str, body: &str) -> Result<String, DiscoveryError> {
        for (method, resp) in &self.post_method_responses {
            if body.contains(method) {
                return resp.clone().map_err(DiscoveryError::TransportError);
            }
        }
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
    #[serde(default, rename = "extXdr")]
    pub ext_xdr: Option<String>,
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

pub const MAX_RPC_GET_LEDGER_ENTRIES_KEYS: usize = 200;

pub(crate) fn validate_rpc_entries<'a>(
    result: &'a RpcResult,
    requested_keys: &[String],
) -> Result<std::collections::BTreeMap<String, &'a RpcEntry>, DiscoveryError> {
    let mut requested = std::collections::BTreeSet::new();
    for key in requested_keys {
        if !requested.insert(key) {
            return Err(DiscoveryError::ParseError(format!(
                "duplicate requested ledger key: {}",
                key
            )));
        }
    }

    let mut entries = std::collections::BTreeMap::new();
    for entry in &result.entries {
        if !requested.contains(&entry.key) {
            return Err(DiscoveryError::ParseError(format!(
                "unexpected returned ledger key: {}",
                entry.key
            )));
        }
        if entries.insert(entry.key.clone(), entry).is_some() {
            return Err(DiscoveryError::ParseError(format!(
                "duplicate returned ledger key: {}",
                entry.key
            )));
        }
        if entry.last_modified_ledger_seq > result.latest_ledger {
            return Err(DiscoveryError::InconsistentLedgerSequence {
                entry_seq: entry.last_modified_ledger_seq,
                snapshot_seq: result.latest_ledger,
            });
        }
    }
    for key in requested_keys {
        if !entries.contains_key(key) {
            return Err(DiscoveryError::ParseError(format!(
                "missing required ledger key: {}",
                key
            )));
        }
    }
    Ok(entries)
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
            asset: tl_asset.clone(),
        });
        let k_credit_tl_b64 = k_credit_tl
            .to_xdr_base64(Limits::none())
            .map_err(|e| DiscoveryError::ParseError(e.to_string()))?;
        key_credit_tl.clone_from(&k_credit_tl_b64);
        keys_b64.push(k_credit_tl_b64);
        let target_asset = match &tl_asset {
            TrustLineAsset::CreditAlphanum4(a) => Asset::CreditAlphanum4(a.clone()),
            TrustLineAsset::CreditAlphanum12(a) => Asset::CreditAlphanum12(a.clone()),
            TrustLineAsset::Native | TrustLineAsset::PoolShare(_) => {
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

        let latest_ledger = rpc_result.latest_ledger;

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
                        found: encode_account_id(&account_id_to_bytes(&acc.account_id)),
                    });
                }
                if acc.balance < 0 {
                    return Err(DiscoveryError::ParseError(
                        "trustor account contains a negative balance or liability".to_owned(),
                    ));
                }
                let (buying_liab, selling_liab, num_sponsoring, num_sponsored) = match acc.ext {
                    AccountEntryExt::V1(v1) => {
                        if v1.liabilities.buying < 0 || v1.liabilities.selling < 0 {
                            return Err(DiscoveryError::ParseError(
                                "trustor account contains a negative liability".to_owned(),
                            ));
                        }
                        match v1.ext {
                            AccountEntryExtensionV1Ext::V2(v2) => (
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
                    AccountEntryExt::V1(v1) => {
                        if v1.liabilities.buying < 0 || v1.liabilities.selling < 0 {
                            return Err(DiscoveryError::ParseError(
                                "issuer account contains a negative liability".to_owned(),
                            ));
                        }
                        match v1.ext {
                            AccountEntryExtensionV1Ext::V2(v2) => (
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
                if tl.account_id != trustor_acc_id {
                    return Err(DiscoveryError::WrongTrustor {
                        expected: trustor.to_owned(),
                        found: encode_account_id(&account_id_to_bytes(&tl.account_id)),
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

            let owner_shares = match ptl_data {
                LedgerEntryData::Trustline(tl) => {
                    if tl.account_id != trustor_acc_id {
                        return Err(DiscoveryError::WrongTrustor {
                            expected: trustor.to_owned(),
                            found: encode_account_id(&account_id_to_bytes(&tl.account_id)),
                        });
                    }
                    if tl.asset != TrustLineAsset::PoolShare(expected_pool_id.clone()) {
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
                        let pool_shares_trust_line_count =
                            u32::try_from(cp.pool_shares_trust_line_count).map_err(|_| {
                                DiscoveryError::ParseError(format!(
                                    "liquidity pool shares trust line count is negative or unrepresentable: {}",
                                    cp.pool_shares_trust_line_count
                                ))
                            })?;
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
                            pool_shares_trust_line_count: Some(pool_shares_trust_line_count),
                        }
                    }
                },
                _ => {
                    return Err(DiscoveryError::ParseError(
                        "expected LiquidityPoolEntry".to_owned(),
                    ));
                }
            };

            // Check the decoded XDR asset identity, not display strings alone.
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
                evidence_classification: None,
            },
            // The public RPC response does not establish the network's base-reserve
            // configuration or ledger-entry sponsorship identities. Keep this result
            // as discovery evidence only; do not promote it to a complete preflight.
            base_reserve_stroops: None,
            protocol_version: None,
            sponsorship_evidence_complete: false,
            accounts: vec![trustor_state, issuer_state],
            trustlines: vec![credit_tl_state],
            pool_share_trustlines: affected_pools,
            sponsorship_handoffs: Vec::new(),
        };

        Ok(snapshot)
    }
}

impl DiscoveryError {
    /// Maps any discovery refusal into the engine's conservative outcome.
    pub fn into_classification(&self) -> crate::Classification {
        match self {
            Self::UnsupportedProtocolVersion { .. } => crate::Classification::Unsupported,
            _ => crate::Classification::Inconclusive,
        }
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

    fn make_lp_entry_xdr_with_values(
        pool_id: &Hash,
        asset_a: &Asset,
        asset_b: &Asset,
        fee: i32,
        reserve_a: i64,
        reserve_b: i64,
        total_pool_shares: i64,
    ) -> String {
        let entry = LedgerEntryData::LiquidityPool(LiquidityPoolEntry {
            liquidity_pool_id: PoolId(pool_id.clone()),
            body: LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
                LiquidityPoolEntryConstantProduct {
                    params: LiquidityPoolConstantProductParameters {
                        asset_a: asset_a.clone(),
                        asset_b: asset_b.clone(),
                        fee,
                    },
                    reserve_a,
                    reserve_b,
                    total_pool_shares,
                    pool_shares_trust_line_count: 1,
                },
            ),
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_lp_entry_xdr_with_count(
        pool_id: &Hash,
        asset_a: &Asset,
        asset_b: &Asset,
        fee: i32,
        pool_shares_trust_line_count: i64,
    ) -> String {
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
                    pool_shares_trust_line_count,
                },
            ),
        });
        entry.to_xdr_base64(Limits::none()).unwrap()
    }

    fn make_lp_entry_xdr(pool_id: &Hash, asset_a: &Asset, asset_b: &Asset, fee: i32) -> String {
        make_lp_entry_xdr_with_values(
            pool_id,
            asset_a,
            asset_b,
            fee,
            1_000_000_000,
            2_000_000_000,
            500_000_000,
        )
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

    fn single_pool_rpc_value() -> serde_json::Value {
        let (_, pool_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5_000_000;
        let credit_key = key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(*b"FLUTTER\0\0\0\0\0"),
                issuer: issuer_id(),
            }),
        }));
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": target_ledger,
                "entries": [
                    { "key": key_to_b64(&LedgerKey::Account(LedgerKeyAccount { account_id: trustor_id() })), "xdr": make_account_xdr(trustor_id(), 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": key_to_b64(&LedgerKey::Account(LedgerKeyAccount { account_id: issuer_id() })), "xdr": make_account_xdr(issuer_id(), 50_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": credit_key, "xdr": make_credit_tl_xdr(trustor_id(), issuer_id(), "FLUTTER", Some(1)), "lastModifiedLedgerSeq": target_ledger },
                    { "key": key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine { account_id: trustor_id(), asset: TrustLineAsset::PoolShare(PoolId(pool_id.clone())) })), "xdr": make_pool_tl_xdr(trustor_id(), &pool_id, 100_000_000), "lastModifiedLedgerSeq": target_ledger },
                    { "key": key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool { liquidity_pool_id: PoolId(pool_id.clone()) })), "xdr": make_lp_entry_xdr(&pool_id, &asset_a, &asset_b, 30), "lastModifiedLedgerSeq": target_ledger }
                ]
            }
        })
    }

    fn run_single_pool_rpc(rpc_value: serde_json::Value) -> Result<Snapshot, DiscoveryError> {
        let (pool_hex, _, _, _) = get_canonical_pool1();
        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [{ "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool_hex }]
        })
        .to_string();
        let mut mock = MockTransport::new();
        mock.set_get(
            format!("https://horizon.example/accounts/{}", TRUSTOR_STRKEY),
            Ok(horizon_json),
        );
        mock.set_post("https://rpc.example", Ok(rpc_value.to_string()));
        let pipeline = DiscoveryPipeline::new(
            mock,
            "https://horizon.example",
            "https://rpc.example",
            "Test SDF Network ; September 2015",
        );
        pipeline.discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
    }

    fn rpc_entry_by_key<'a>(
        value: &'a mut serde_json::Value,
        key: &str,
    ) -> &'a mut serde_json::Value {
        value["result"]["entries"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["key"] == key)
            .unwrap()
    }

    fn single_pool_credit_key() -> String {
        key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(*b"FLUTTER\0\0\0\0\0"),
                issuer: issuer_id(),
            }),
        }))
    }

    fn single_pool_share_key(pool_id: Hash) -> String {
        key_to_b64(&LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: trustor_id(),
            asset: TrustLineAsset::PoolShare(PoolId(pool_id)),
        }))
    }

    #[test]
    fn rpc_duplicate_returned_key_is_rejected_without_overwrite() {
        let mut value = single_pool_rpc_value();
        let duplicate = value["result"]["entries"][0].clone();
        value["result"]["entries"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        let error = run_single_pool_rpc(value).unwrap_err();
        assert!(error.to_string().contains("duplicate returned ledger key"));
    }

    #[test]
    fn duplicate_requested_key_is_rejected() {
        let result = RpcResult {
            entries: Vec::new(),
            latest_ledger: 1,
        };
        let requested = vec!["same".to_owned(), "same".to_owned()];
        let error = validate_rpc_entries(&result, &requested).unwrap_err();
        assert!(error.to_string().contains("duplicate requested ledger key"));
    }

    #[test]
    fn rpc_unexpected_returned_key_is_rejected() {
        let mut value = single_pool_rpc_value();
        value["result"]["entries"][0]["key"] = serde_json::Value::String("unexpected".to_owned());
        let error = run_single_pool_rpc(value).unwrap_err();
        assert!(error.to_string().contains("unexpected returned ledger key"));
    }

    #[test]
    fn rpc_missing_required_key_is_rejected() {
        let mut value = single_pool_rpc_value();
        value["result"]["entries"].as_array_mut().unwrap().pop();
        let error = run_single_pool_rpc(value).unwrap_err();
        assert!(error.to_string().contains("missing required ledger key"));
    }

    #[test]
    fn wrong_credit_trustline_owner_is_rejected() {
        let mut value = single_pool_rpc_value();
        let key = single_pool_credit_key();
        rpc_entry_by_key(&mut value, &key)["xdr"] = serde_json::Value::String(make_credit_tl_xdr(
            other_issuer_id(),
            issuer_id(),
            "FLUTTER",
            Some(1),
        ));
        let error = run_single_pool_rpc(value).unwrap_err();
        assert!(error.to_string().contains("wrong trustor"));
    }

    #[test]
    fn wrong_credit_trustline_asset_is_rejected() {
        let mut value = single_pool_rpc_value();
        let key = single_pool_credit_key();
        rpc_entry_by_key(&mut value, &key)["xdr"] = serde_json::Value::String(make_credit_tl_xdr(
            trustor_id(),
            other_issuer_id(),
            "FLUTTER",
            Some(1),
        ));
        let error = run_single_pool_rpc(value).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("credit trustline asset identity")
        );
    }

    #[test]
    fn wrong_pool_share_identity_is_rejected() {
        let mut value = single_pool_rpc_value();
        let (_, pool_id, _, _) = get_canonical_pool1();
        let key = single_pool_share_key(pool_id.clone());
        let (_, other_pool_id, _, _) = get_canonical_pool2();
        rpc_entry_by_key(&mut value, &key)["xdr"] =
            serde_json::Value::String(make_pool_tl_xdr(trustor_id(), &other_pool_id, 100_000_000));
        let error = run_single_pool_rpc(value).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("pool-share trustline asset identity")
        );
    }

    #[test]
    fn wrong_pool_entry_identity_is_rejected() {
        let mut value = single_pool_rpc_value();
        let (_, pool_id, asset_a, asset_b) = get_canonical_pool1();
        let pool_key = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_id.clone()),
        }));
        let (_, other_pool_id, _, _) = get_canonical_pool2();
        rpc_entry_by_key(&mut value, &pool_key)["xdr"] =
            serde_json::Value::String(make_lp_entry_xdr(&other_pool_id, &asset_a, &asset_b, 30));
        let error = run_single_pool_rpc(value).unwrap_err();
        assert!(error.to_string().contains("liquidity pool entry identity"));
    }

    #[test]
    fn negative_pool_balance_and_reserve_are_rejected() {
        let mut negative_balance = single_pool_rpc_value();
        let (_, pool_id, _, _) = get_canonical_pool1();
        let key = single_pool_share_key(pool_id.clone());
        rpc_entry_by_key(&mut negative_balance, &key)["xdr"] =
            serde_json::Value::String(make_pool_tl_xdr(trustor_id(), &pool_id, -1));
        let error = run_single_pool_rpc(negative_balance).unwrap_err();
        assert!(error.to_string().contains("balance cannot be negative"));

        let mut negative_reserve = single_pool_rpc_value();
        let pool_key = key_to_b64(&LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: PoolId(pool_id.clone()),
        }));
        let (_, _, asset_a, asset_b) = get_canonical_pool1();
        rpc_entry_by_key(&mut negative_reserve, &pool_key)["xdr"] =
            serde_json::Value::String(make_lp_entry_xdr_with_values(
                &pool_id,
                &asset_a,
                &asset_b,
                30,
                -1,
                2_000_000_000,
                500_000_000,
            ));
        let error = run_single_pool_rpc(negative_reserve).unwrap_err();
        assert!(error.to_string().contains("cannot be negative"));
    }

    #[test]
    fn discovery_marks_sponsorship_and_reserve_preflight_as_incomplete() {
        let snapshot = run_single_pool_rpc(single_pool_rpc_value()).expect("bounded discovery");
        assert_eq!(snapshot.base_reserve_stroops, None);
        assert!(!snapshot.sponsorship_evidence_complete);
    }

    #[test]
    fn rpc_batch_over_limit_fails_before_transport() {
        let balances: Vec<_> = (0..99)
            .map(|index| {
                serde_json::json!({
                    "asset_type": "liquidity_pool_shares",
                    "liquidity_pool_id": format!("{:064x}", index + 1)
                })
            })
            .collect();
        let horizon_json =
            serde_json::json!({ "id": TRUSTOR_STRKEY, "balances": balances }).to_string();
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
        let error = pipeline
            .discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
            .unwrap_err();
        assert_eq!(
            error,
            DiscoveryError::RpcBatchTooLarge {
                requested: 201,
                maximum: MAX_RPC_GET_LEDGER_ENTRIES_KEYS
            }
        );
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
        assert!(report.pool_redemptions.is_empty());
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("base reserve is unavailable"))
        );
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
        assert!(report.pool_redemptions.is_empty());
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
    // Pool-shares-trust-line-count evidence integrity
    // -----------------------------------------------------------------------

    fn discover_with_pool_shares_trust_line_count(count: i64) -> Result<Snapshot, DiscoveryError> {
        let (pool1_hex, pool1_id, asset_a, asset_b) = get_canonical_pool1();
        let target_ledger = 5000000;

        let horizon_json = serde_json::json!({
            "id": TRUSTOR_STRKEY,
            "balances": [
                { "asset_type": "liquidity_pool_shares", "liquidity_pool_id": pool1_hex, "balance": "100.0" }
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
                    { "key": k_lp, "xdr": make_lp_entry_xdr_with_count(&pool1_id, &asset_a, &asset_b, 30, count), "lastModifiedLedgerSeq": target_ledger }
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

        pipeline.discover_and_verify(TRUSTOR_STRKEY, &credit_asset_flutter())
    }

    #[test]
    fn test_discovery_negative_pool_shares_trust_line_count_fails_closed() {
        let err = discover_with_pool_shares_trust_line_count(-1).unwrap_err();
        assert!(matches!(err, DiscoveryError::ParseError(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_discovery_unrepresentable_pool_shares_trust_line_count_fails_closed() {
        let err = discover_with_pool_shares_trust_line_count(i64::from(u32::MAX) + 1).unwrap_err();
        assert!(matches!(err, DiscoveryError::ParseError(_)));
        assert_eq!(err.into_classification(), Classification::Inconclusive);
    }

    #[test]
    fn test_discovery_positive_pool_shares_trust_line_count_is_retained_exactly() {
        let snapshot = discover_with_pool_shares_trust_line_count(3)
            .expect("a valid nonnegative counter must not be rejected");
        assert_eq!(
            snapshot.pool_share_trustlines[0].pool_shares_trust_line_count,
            Some(3)
        );
    }

    #[test]
    fn test_discovery_zero_pool_shares_trust_line_count_with_existing_trustline_is_not_silently_dropped()
     {
        // The owner's own pool-share trustline is present in this fixture (balance 100_000_000),
        // so a reported counter of zero is contradictory, not missing evidence: discovery must
        // retain it exactly as `Some(0)` rather than collapsing it into `None` (which the
        // evaluator would otherwise treat as merely unforecastable instead of contradictory).
        // `evaluate`'s own fail-closed handling of this contradiction is already covered by
        // `contradictory_zero_pool_shares_trust_line_count_fails_closed` in lib.rs; this test
        // only verifies the extraction layer does not silently downgrade it first.
        let snapshot = discover_with_pool_shares_trust_line_count(0)
            .expect("zero is representable as u32 and must be decoded, not rejected");
        assert_eq!(
            snapshot.pool_share_trustlines[0].pool_shares_trust_line_count,
            Some(0)
        );
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
        assert!(err.to_string().contains("missing required ledger key"));
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
                .any(|e| e.contains("discovery manifest hash is invalid"))
        );
    }
}
