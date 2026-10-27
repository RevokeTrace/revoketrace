//! Deterministic offline engine for the first RevokeTrace implementation slice.
//!
//! Network capture, discovery, signing, and submission are intentionally not
//! part of this crate yet. The engine only evaluates a complete immutable
//! snapshot supplied by its caller and fails closed when completeness cannot
//! be established.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, AllowTrustResultCode, AlphaNum4, AlphaNum12, Asset, AssetCode4, AssetCode12, Hash,
    HashIdPreimageRevokeId, Limits, LiquidityPoolConstantProductParameters,
    LiquidityPoolParameters, OperationResultCode, PoolId, PublicKey, ReadXdr, SequenceNumber,
    SetTrustLineFlagsOp, SetTrustLineFlagsResultCode, Uint256, WriteXdr,
};

pub mod discovery;
pub mod evidence;
pub use discovery::{
    CurlTransport, DiscoveryError, DiscoveryPipeline, HorizonAccountResponse, HorizonBalance,
    HttpTransport, MockTransport, decode_account_id, encode_account_id,
};
pub use evidence::{
    AuthoritativeCaptureArtifact, AuthoritativeEvidenceAdapter, EvidenceClassification,
};

pub const AUTHORIZED_FLAG: u32 = 1;
pub const AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG: u32 = 2;
pub const TRUSTLINE_CLAWBACK_ENABLED_FLAG: u32 = 4;
pub const CLAIMABLE_BALANCE_FLAG_CLAWBACK_ENABLED: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transition {
    NoEffect,
    MaintainLiabilitiesOnly,
    ForcedPoolRedemption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    /// Reserved for a future trusted capture/verifier implementation.
    SupportedSafe,
    SupportedBlocked,
    /// The supplied snapshot is internally coherent, but discovery is not
    /// independently verified as ledger-complete.
    UnverifiedForecast,
    Inconclusive,
    Unsupported,
}

/// Maps an observed protocol result into the evaluator's conservative outcome.
/// These are protocol result mappings, not a claim that a forecast will succeed.
pub fn map_allow_trust_result(code: AllowTrustResultCode) -> Classification {
    match code {
        AllowTrustResultCode::Success => Classification::UnverifiedForecast,
        AllowTrustResultCode::LowReserve
        | AllowTrustResultCode::Malformed
        | AllowTrustResultCode::NoTrustLine
        | AllowTrustResultCode::TrustNotRequired
        | AllowTrustResultCode::CantRevoke
        | AllowTrustResultCode::SelfNotAllowed => Classification::SupportedBlocked,
    }
}

pub fn map_set_trust_line_flags_result(code: SetTrustLineFlagsResultCode) -> Classification {
    match code {
        SetTrustLineFlagsResultCode::Success => Classification::UnverifiedForecast,
        SetTrustLineFlagsResultCode::Malformed
        | SetTrustLineFlagsResultCode::NoTrustLine
        | SetTrustLineFlagsResultCode::CantRevoke
        | SetTrustLineFlagsResultCode::InvalidState
        | SetTrustLineFlagsResultCode::LowReserve => Classification::SupportedBlocked,
    }
}

pub fn map_operation_result(code: OperationResultCode) -> Classification {
    match code {
        OperationResultCode::OpNotSupported => Classification::Unsupported,
        // opINNER is only a wrapper; without the nested AllowTrust or
        // SetTrustLineFlags result, the evaluator must not claim success.
        OperationResultCode::OpInner => Classification::Inconclusive,
        OperationResultCode::OpBadAuth
        | OperationResultCode::OpNoAccount
        | OperationResultCode::OpTooManySubentries
        | OperationResultCode::OpExceededWorkLimit
        | OperationResultCode::OpTooManySponsoring => Classification::SupportedBlocked,
    }
}

/// Derives the CAP-0038 pool-revocation claimable-balance ID.
///
/// The preimage is the XDR encoding of HashIDPreimageRevokeId, which is then
/// SHA-256 hashed. The operation source, transaction sequence, operation index,
/// pool ID, and output asset are all identity-bearing inputs.
pub fn derive_pool_revoke_claimable_balance_id(
    source_account: stellar_xdr::AccountId,
    sequence: SequenceNumber,
    operation_index: u32,
    pool_id: Hash,
    asset: Asset,
) -> Result<Hash, stellar_xdr::Error> {
    let preimage = HashIdPreimageRevokeId {
        source_account,
        seq_num: sequence,
        op_num: operation_index,
        liquidity_pool_id: PoolId(pool_id),
        asset,
    };
    let encoded = preimage.to_xdr(Limits::none())?;
    Ok(Hash(Sha256::digest(encoded).into()))
}

/// Derives the canonical CAP-0038 constant-product pool ID from constituent assets and fee.
pub fn derive_constant_product_pool_id(
    asset_a: &Asset,
    asset_b: &Asset,
    fee_bps: i32,
) -> Result<Hash, stellar_xdr::Error> {
    let params = LiquidityPoolParameters::LiquidityPoolConstantProduct(
        LiquidityPoolConstantProductParameters {
            asset_a: asset_a.clone(),
            asset_b: asset_b.clone(),
            fee: fee_bps,
        },
    );
    let encoded = params.to_xdr(Limits::none())?;
    Ok(Hash(Sha256::digest(encoded).into()))
}

/// Constructs an authoritative Stellar XDR Asset from code and issuer strkey.
pub fn make_xdr_asset(code: &str, issuer_strkey: &str) -> Result<stellar_xdr::Asset, String> {
    if code == "XLM" && (issuer_strkey == "native" || issuer_strkey.is_empty()) {
        return Ok(stellar_xdr::Asset::Native);
    }
    let issuer_bytes = decode_account_id(issuer_strkey)?;
    let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes)));
    let bytes = code.as_bytes();
    if bytes.is_empty() {
        return Err("asset code cannot be empty".to_owned());
    }
    if bytes.len() <= 4 {
        let mut code_arr = [0u8; 4];
        code_arr[..bytes.len()].copy_from_slice(bytes);
        Ok(stellar_xdr::Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code_arr),
            issuer,
        }))
    } else if bytes.len() <= 12 {
        let mut code_arr = [0u8; 12];
        code_arr[..bytes.len()].copy_from_slice(bytes);
        Ok(stellar_xdr::Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(code_arr),
            issuer,
        }))
    } else {
        Err(format!("asset code exceeds 12 characters: {}", code))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSpec {
    pub operation: String,
    pub source_account: String,
    #[serde(default)]
    pub tx_source_account: Option<String>,
    pub trustor: String,
    #[serde(default)]
    pub sequence: Option<u64>,
    #[serde(default)]
    pub operation_index: Option<u32>,
    pub asset: CreditAsset,
    pub before_flags: u32,
    pub after_flags: u32,
}

impl OperationSpec {
    pub fn new(
        operation: impl Into<String>,
        source_account: impl Into<String>,
        trustor: impl Into<String>,
        asset: CreditAsset,
        before_flags: u32,
        after_flags: u32,
    ) -> Self {
        Self {
            operation: operation.into(),
            source_account: source_account.into(),
            tx_source_account: None,
            trustor: trustor.into(),
            sequence: None,
            operation_index: None,
            asset,
            before_flags,
            after_flags,
        }
    }

    pub fn with_context(
        mut self,
        tx_source_account: Option<String>,
        sequence: Option<u64>,
        operation_index: Option<u32>,
    ) -> Self {
        self.tx_source_account = tx_source_account;
        self.sequence = sequence;
        self.operation_index = operation_index;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditAsset {
    pub code: String,
    pub issuer: String,
}

fn same_asset(left: &CreditAsset, right: &CreditAsset) -> bool {
    left.code == right.code && left.issuer == right.issuer
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditTrustlineState {
    pub owner: String,
    pub asset: CreditAsset,
    pub flags: u32,
    pub sponsor: Option<String>,
    #[serde(default)]
    pub liquidity_pool_use_count: Option<u32>,
    #[serde(default)]
    pub last_modified_ledger_seq: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub id: String,
    pub balance_stroops: u64,
    #[serde(default)]
    pub buying_liabilities_stroops: u64,
    pub selling_liabilities_stroops: u64,
    pub subentries: u32,
    pub num_sponsoring: u32,
    pub num_sponsored: u32,
    #[serde(default)]
    pub last_modified_ledger_seq: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolShareState {
    pub pool_id: String,
    pub owner: String,
    pub asset_a: String,
    pub asset_a_issuer: String,
    pub asset_b: String,
    pub asset_b_issuer: String,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub total_pool_shares: u64,
    pub owner_pool_shares: u64,
    pub sponsor: Option<String>,
    #[serde(default)]
    pub last_modified_ledger_seq: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorshipHandoff {
    pub sponsored_account: String,
    pub replacement_sponsor: String,
    pub begin_operation_index: u32,
    pub revoke_operation_index: u32,
    pub end_operation_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoverySource {
    SyntheticFixture,
    LedgerCapture {
        endpoint: String,
    },
    TwoTierDiscovery {
        horizon_endpoint: String,
        rpc_endpoint: String,
    },
    AuthoritativeExport {
        export_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DiscoveryCoverage {
    #[default]
    Unproven,
    AuthoritativeReconciled {
        liquidity_pool_use_count: u32,
        verified_pool_count: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryProof {
    pub source: DiscoverySource,
    pub target_ledger_sequence: u32,
    pub pool_ids: Vec<String>,
    pub manifest_sha256: String,
    #[serde(default)]
    pub coverage: DiscoveryCoverage,
    #[serde(default)]
    pub evidence_classification: Option<EvidenceClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub network_passphrase: String,
    pub ledger_sequence: u32,
    pub entries_ledger_sequence: u32,
    pub discovery: DiscoveryProof,
    #[serde(default)]
    pub base_reserve_stroops: Option<u64>,
    #[serde(default)]
    pub protocol_version: Option<u32>,
    /// False when the source cannot prove sponsorship identities and counters.
    #[serde(default)]
    pub sponsorship_evidence_complete: bool,
    pub accounts: Vec<AccountState>,
    pub trustlines: Vec<CreditTrustlineState>,
    pub pool_share_trustlines: Vec<PoolShareState>,
    pub sponsorship_handoffs: Vec<SponsorshipHandoff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimableBalanceForecast {
    pub pool_id: String,
    pub asset: String,
    pub amount_stroops: u64,
    pub sponsor: String,
    #[serde(default)]
    pub claimable_balance_id: Option<String>,
    #[serde(default)]
    pub clawback_flag_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolRedemptionForecast {
    pub pool_id: String,
    pub owner: String,
    pub withdrawn_a_stroops: u64,
    pub withdrawn_b_stroops: u64,
    pub claimable_balances: Vec<ClaimableBalanceForecast>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDelta {
    pub id: String,
    pub balance_stroops: i128,
    pub subentries: i64,
    pub num_sponsoring: i64,
    pub num_sponsored: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub classification: Classification,
    pub transition: Transition,
    pub pool_redemptions: Vec<PoolRedemptionForecast>,
    pub account_deltas: Vec<AccountDelta>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

fn account<'a>(snapshot: &'a Snapshot, id: &str) -> Option<&'a AccountState> {
    snapshot
        .accounts
        .iter()
        .find(|candidate| candidate.id == id)
}

fn minimum_balance(account: &AccountState, base_reserve: u64) -> Result<u128, String> {
    let units = 2_u128
        .checked_add(u128::from(account.subentries))
        .and_then(|value| value.checked_add(u128::from(account.num_sponsoring)))
        .and_then(|value| value.checked_sub(u128::from(account.num_sponsored)))
        .ok_or_else(|| format!("reserve units underflow for account {}", account.id))?;
    units
        .checked_mul(u128::from(base_reserve))
        .ok_or_else(|| format!("reserve multiplication overflow for account {}", account.id))
}

fn forecast_amount(shares: u64, reserve: u64, total: u64) -> Result<u64, String> {
    if total == 0 {
        return Err("pool total shares is zero".to_owned());
    }
    let value = u128::from(shares)
        .checked_mul(u128::from(reserve))
        .ok_or_else(|| "pool redemption multiplication overflow".to_owned())?
        / u128::from(total);
    u64::try_from(value).map_err(|_| "pool redemption exceeds int64 amount".to_owned())
}

pub fn discovery_manifest_sha256(
    network_passphrase: &str,
    ledger_sequence: u32,
    pool_ids: &[String],
) -> String {
    let mut sorted_ids = pool_ids.to_vec();
    sorted_ids.sort();
    let material = format!(
        "{}\n{}\n{}",
        network_passphrase,
        ledger_sequence,
        sorted_ids.join("\n")
    );
    hex::encode(Sha256::digest(material.as_bytes()))
}

fn validate_snapshot(snapshot: &Snapshot, operation: &OperationSpec) -> Vec<String> {
    let mut errors = Vec::new();
    if snapshot.ledger_sequence != snapshot.entries_ledger_sequence {
        errors.push("snapshot entries come from a different ledger sequence".to_owned());
    }
    if snapshot.discovery.target_ledger_sequence != snapshot.ledger_sequence {
        errors.push("discovery proof targets a different ledger sequence".to_owned());
    }
    let mut expected_pool_ids: Vec<_> = snapshot
        .pool_share_trustlines
        .iter()
        .map(|pool| pool.pool_id.clone())
        .collect();
    expected_pool_ids.sort();
    let mut proven_pool_ids = snapshot.discovery.pool_ids.clone();
    proven_pool_ids.sort();
    if expected_pool_ids != proven_pool_ids {
        errors.push("discovery manifest does not exactly cover pool-share trustlines".to_owned());
    }
    if snapshot.discovery.manifest_sha256
        != discovery_manifest_sha256(
            &snapshot.network_passphrase,
            snapshot.ledger_sequence,
            &snapshot.discovery.pool_ids,
        )
    {
        errors.push("discovery manifest hash is invalid".to_owned());
    }
    let mut manifest_pool_ids = std::collections::BTreeSet::new();
    for pool_id in &snapshot.discovery.pool_ids {
        if !manifest_pool_ids.insert(pool_id) {
            errors.push(format!(
                "duplicate pool ID in discovery manifest: {}",
                pool_id
            ));
        }
    }
    if let DiscoverySource::LedgerCapture { endpoint } = &snapshot.discovery.source
        && endpoint.trim().is_empty()
    {
        errors.push("ledger capture endpoint is empty".to_owned());
    }
    if let DiscoverySource::TwoTierDiscovery {
        horizon_endpoint,
        rpc_endpoint,
    } = &snapshot.discovery.source
    {
        if horizon_endpoint.trim().is_empty() {
            errors.push("discovery horizon endpoint is empty".to_owned());
        }
        if rpc_endpoint.trim().is_empty() {
            errors.push("discovery rpc endpoint is empty".to_owned());
        }
    }
    if let DiscoverySource::AuthoritativeExport { export_id } = &snapshot.discovery.source
        && export_id.trim().is_empty()
    {
        errors.push("authoritative export ID is empty".to_owned());
    }
    if let Some(protocol_version) = snapshot.protocol_version
        && protocol_version < 18
    {
        errors.push("unsupported protocol version: protocol version is below 18".to_owned());
    }
    if snapshot
        .base_reserve_stroops
        .is_none_or(|reserve| reserve == 0)
    {
        errors.push("base reserve is unavailable or non-positive".to_owned());
    }
    if operation.operation != "SetTrustLineFlags" && operation.operation != "AllowTrust" {
        errors.push(format!("unsupported operation {}", operation.operation));
    }
    if account(snapshot, &operation.source_account).is_none() {
        errors.push("operation source account is missing".to_owned());
    }
    if let Some(tx_src) = &operation.tx_source_account
        && account(snapshot, tx_src).is_none()
    {
        errors.push(format!("transaction source account {} is missing", tx_src));
    }
    if operation.asset.issuer != operation.source_account {
        errors.push("operation source is not the asset issuer".to_owned());
    }
    if operation.trustor == operation.source_account {
        errors.push("operation trustor must differ from issuer source".to_owned());
    }
    if operation.asset.code.is_empty() || operation.asset.issuer.is_empty() {
        errors.push("operation asset identity is incomplete".to_owned());
    }
    let matching_trustlines: Vec<_> = snapshot
        .trustlines
        .iter()
        .filter(|trustline| {
            trustline.owner == operation.trustor && same_asset(&trustline.asset, &operation.asset)
        })
        .collect();
    if matching_trustlines.len() != 1 {
        errors.push(format!(
            "expected exactly one target credit trustline, found {}",
            matching_trustlines.len()
        ));
    } else if matching_trustlines[0].flags != operation.before_flags {
        errors.push("operation before flags do not match target trustline".to_owned());
    } else {
        let target_tl = matching_trustlines[0];
        let affected_pool_share_count = snapshot
            .pool_share_trustlines
            .iter()
            .filter(|pool| {
                pool.owner == operation.trustor
                    && ((pool.asset_a == operation.asset.code
                        && pool.asset_a_issuer == operation.asset.issuer)
                        || (pool.asset_b == operation.asset.code
                            && pool.asset_b_issuer == operation.asset.issuer))
            })
            .count() as u32;

        if let Some(expected_use_count) = target_tl.liquidity_pool_use_count
            && affected_pool_share_count != expected_use_count
        {
            errors.push(format!(
                "target credit trustline liquidityPoolUseCount ({}) does not match discovered affected pools ({})",
                expected_use_count, affected_pool_share_count
            ));
        }

        match &snapshot.discovery.coverage {
            DiscoveryCoverage::AuthoritativeReconciled {
                liquidity_pool_use_count,
                verified_pool_count,
            } => {
                if *liquidity_pool_use_count != *verified_pool_count {
                    errors.push(format!(
                        "discovery coverage reconciliation mismatch: liquidityPoolUseCount {} != verified_pool_count {}",
                        liquidity_pool_use_count, verified_pool_count
                    ));
                }
                if *verified_pool_count != affected_pool_share_count {
                    errors.push(format!(
                        "discovery coverage verified_pool_count {} does not match snapshot affected pools {}",
                        verified_pool_count, affected_pool_share_count
                    ));
                }
                if target_tl.liquidity_pool_use_count != Some(*liquidity_pool_use_count) {
                    errors.push(
                        "discovery coverage count differs from target credit trustline count"
                            .to_owned(),
                    );
                }
            }
            DiscoveryCoverage::Unproven => {}
        }
    }
    for (label, flags) in [
        ("before", operation.before_flags),
        ("after", operation.after_flags),
    ] {
        if flags & !0b111 != 0 {
            errors.push(format!("{} trustline flags contain unknown bits", label));
        }
        if flags & (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG)
            == (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG)
        {
            errors.push(format!(
                "{} trustline flags contain conflicting auth bits",
                label
            ));
        }
    }
    let mut account_ids = std::collections::BTreeSet::new();
    for entry in &snapshot.accounts {
        if !account_ids.insert(&entry.id) {
            errors.push(format!("duplicate account {}", entry.id));
        }
        if let Some(seq) = entry.last_modified_ledger_seq
            && seq > snapshot.ledger_sequence
        {
            errors.push(format!(
                "account {} lastModifiedLedgerSeq {} is newer than snapshot ledger {}",
                entry.id, seq, snapshot.ledger_sequence
            ));
        }
        if entry.balance_stroops < entry.selling_liabilities_stroops {
            errors.push(format!(
                "account {} selling liabilities exceed balance",
                entry.id
            ));
        }
        if u128::from(entry.balance_stroops) + u128::from(entry.buying_liabilities_stroops)
            > u128::from(i64::MAX as u64)
        {
            errors.push(format!(
                "account {} balance plus buying liabilities exceeds int64 limit",
                entry.id
            ));
        }
        if u128::from(entry.num_sponsored)
            > 2 + u128::from(entry.subentries) + u128::from(entry.num_sponsoring)
        {
            errors.push(format!(
                "account {} num_sponsored violates invariant: exceeds subentries + num_sponsoring + 2",
                entry.id
            ));
        }
        if u128::from(entry.num_sponsoring) + u128::from(entry.subentries) > u128::from(u32::MAX) {
            errors.push(format!(
                "account {} sponsorship accounting exceeds UINT32_MAX",
                entry.id
            ));
        }
    }
    let mut trustline_keys = std::collections::BTreeSet::new();
    for tl in &snapshot.trustlines {
        let key = (&tl.owner, &tl.asset.code, &tl.asset.issuer);
        if !trustline_keys.insert(key) {
            errors.push(format!(
                "duplicate trustline for owner {} and asset {}:{}",
                tl.owner, tl.asset.code, tl.asset.issuer
            ));
        }
        if let Some(seq) = tl.last_modified_ledger_seq
            && seq > snapshot.ledger_sequence
        {
            errors.push(format!(
                "trustline for owner {} and asset {}:{} lastModifiedLedgerSeq {} is newer than snapshot ledger {}",
                tl.owner, tl.asset.code, tl.asset.issuer, seq, snapshot.ledger_sequence
            ));
        }
        if account(snapshot, &tl.owner).is_none() {
            errors.push(format!("trustline owner {} is missing", tl.owner));
        }
        if let Some(sponsor) = &tl.sponsor
            && account(snapshot, sponsor).is_none()
        {
            errors.push(format!("trustline sponsor {} is missing", sponsor));
        }
    }
    let mut pool_ids = std::collections::BTreeSet::new();
    for pool in &snapshot.pool_share_trustlines {
        if !pool_ids.insert(&pool.pool_id) {
            errors.push(format!("duplicate pool trustline {}", pool.pool_id));
        }
        if let Some(seq) = pool.last_modified_ledger_seq
            && seq > snapshot.ledger_sequence
        {
            errors.push(format!(
                "pool {} lastModifiedLedgerSeq {} is newer than snapshot ledger {}",
                pool.pool_id, seq, snapshot.ledger_sequence
            ));
        }
        if account(snapshot, &pool.owner).is_none() {
            errors.push(format!("pool owner {} is missing", pool.owner));
        }
        if let Some(sponsor) = &pool.sponsor
            && account(snapshot, sponsor).is_none()
        {
            errors.push(format!("pool sponsor {} is missing", sponsor));
        }
        if let Some(sponsor) = &pool.sponsor {
            if account(snapshot, sponsor).is_some_and(|account| account.num_sponsoring < 2) {
                errors.push(format!(
                    "pool {} sponsor counter does not include its two-reserve trustline",
                    pool.pool_id
                ));
            }
            if account(snapshot, &pool.owner).is_some_and(|account| account.num_sponsored < 2) {
                errors.push(format!(
                    "pool {} owner counter does not include its two-reserve trustline",
                    pool.pool_id
                ));
            }
        }
        if pool.owner_pool_shares > pool.total_pool_shares {
            errors.push(format!(
                "pool {} has more owner shares than total shares",
                pool.pool_id
            ));
        }
        if pool.asset_a.is_empty()
            || pool.asset_a_issuer.is_empty()
            || pool.asset_b.is_empty()
            || pool.asset_b_issuer.is_empty()
        {
            errors.push(format!(
                "pool {} has incomplete asset identity",
                pool.pool_id
            ));
        }
        if pool.asset_a == pool.asset_b && pool.asset_a_issuer == pool.asset_b_issuer {
            errors.push(format!(
                "pool {} has contradictory identical constituent assets",
                pool.pool_id
            ));
        }
        if pool.total_pool_shares > 0 && (pool.reserve_a == 0 || pool.reserve_b == 0) {
            errors.push(format!(
                "pool {} has an arithmetic edge-case reserve state not accepted as ledger-reachable",
                pool.pool_id
            ));
        }
    }
    if !snapshot.sponsorship_handoffs.is_empty() && operation.operation_index.is_none() {
        errors.push(
            "operation index is missing but required to evaluate sponsorship handoffs".to_owned(),
        );
    }
    let mut handoff_targets = std::collections::BTreeSet::new();
    for handoff in &snapshot.sponsorship_handoffs {
        if !handoff_targets.insert(&handoff.sponsored_account) {
            errors.push(format!(
                "conflicting sponsorship handoffs for account {}",
                handoff.sponsored_account
            ));
        }
        if account(snapshot, &handoff.sponsored_account).is_none() {
            errors.push(format!(
                "sponsorship handoff references missing sponsored account {}",
                handoff.sponsored_account
            ));
        }
        if account(snapshot, &handoff.replacement_sponsor).is_none() {
            errors.push(format!(
                "sponsorship handoff references missing replacement sponsor {}",
                handoff.replacement_sponsor
            ));
        }
        if handoff.end_operation_index.is_none() {
            errors
                .push("sponsorship handoff is unclosed: end_operation_index is missing".to_owned());
        }
        if handoff.begin_operation_index >= handoff.revoke_operation_index {
            errors
                .push("sponsorship handoff begin index must be less than revoke index".to_owned());
        }
        if let Some(end) = handoff.end_operation_index
            && end <= handoff.revoke_operation_index
        {
            errors
                .push("sponsorship handoff end index must be greater than revoke index".to_owned());
        }
        if let Some(op_idx) = operation.operation_index
            && handoff.revoke_operation_index != op_idx
        {
            errors.push(
                "sponsorship handoff revoke_operation_index does not match operation index"
                    .to_owned(),
            );
        }
    }
    errors
}

pub fn evaluate(operation: &OperationSpec, snapshot: &Snapshot) -> Report {
    let transition = classify_transition(operation.before_flags, operation.after_flags);
    let validation_errors = validate_snapshot(snapshot, operation);
    if !validation_errors.is_empty() {
        let classification = if validation_errors
            .iter()
            .any(|error| error.starts_with("unsupported"))
        {
            Classification::Unsupported
        } else {
            Classification::Inconclusive
        };
        return Report {
            classification,
            transition,
            pool_redemptions: Vec::new(),
            account_deltas: Vec::new(),
            warnings: Vec::new(),
            errors: validation_errors,
        };
    }

    let is_coverage_proven = match &snapshot.discovery.coverage {
        DiscoveryCoverage::AuthoritativeReconciled { .. } => true,
        DiscoveryCoverage::Unproven => false,
    };
    let coverage_warning = if !is_coverage_proven {
        Some(
            "forecast discovery coverage is unproven; liquidityPoolUseCount not verified on-chain"
                .to_owned(),
        )
    } else {
        None
    };
    let sponsorship_warning = (!snapshot.sponsorship_evidence_complete).then_some(
        "sponsorship identities and reserve counters are incomplete; forecast is not a complete preflight"
            .to_owned(),
    );

    if transition != Transition::ForcedPoolRedemption {
        let mut warnings = vec![
            "forecast is internally consistent but discovery is not independently verified"
                .to_owned(),
        ];
        if let Some(w) = coverage_warning {
            warnings.push(w);
        }
        if let Some(w) = sponsorship_warning {
            warnings.push(w);
        }
        return Report {
            classification: Classification::UnverifiedForecast,
            transition,
            pool_redemptions: Vec::new(),
            account_deltas: Vec::new(),
            warnings,
            errors: Vec::new(),
        };
    }

    let mut redemptions = Vec::new();
    let mut deltas = std::collections::BTreeMap::<String, AccountDelta>::new();
    let mut eval_errors = Vec::new();
    let mut eval_warnings = Vec::new();

    let mut affected_pools: Vec<_> = snapshot
        .pool_share_trustlines
        .iter()
        .filter(|pool| {
            pool.owner == operation.trustor
                && ((pool.asset_a == operation.asset.code
                    && pool.asset_a_issuer == operation.asset.issuer)
                    || (pool.asset_b == operation.asset.code
                        && pool.asset_b_issuer == operation.asset.issuer))
        })
        .collect();
    // Deterministic ordering by pool_id matching Stellar Core's std::sort on poolTLKeys
    affected_pools.sort_by(|a, b| a.pool_id.cmp(&b.pool_id));

    let can_derive_cb_id = operation.tx_source_account.is_some()
        && operation.sequence.is_some()
        && operation.operation_index.is_some();
    if !can_derive_cb_id && !affected_pools.is_empty() {
        eval_warnings.push(
            "claimable balance ID derivation skipped: operation context (tx_source_account, sequence, or operation_index) is unavailable".to_owned(),
        );
    }

    for pool in affected_pools {
        let amount_a = match forecast_amount(
            pool.owner_pool_shares,
            pool.reserve_a,
            pool.total_pool_shares,
        ) {
            Ok(amount) => amount,
            Err(error) => {
                eval_errors.push(format!("{}: {}", pool.pool_id, error));
                continue;
            }
        };
        let amount_b = match forecast_amount(
            pool.owner_pool_shares,
            pool.reserve_b,
            pool.total_pool_shares,
        ) {
            Ok(amount) => amount,
            Err(error) => {
                eval_errors.push(format!("{}: {}", pool.pool_id, error));
                continue;
            }
        };

        let base_sponsor = pool.sponsor.clone().unwrap_or_else(|| pool.owner.clone());
        let active_replacement_sponsor = snapshot
            .sponsorship_handoffs
            .iter()
            .find(|handoff| handoff.sponsored_account == base_sponsor)
            .map(|handoff| handoff.replacement_sponsor.clone());
        let sponsor = active_replacement_sponsor
            .clone()
            .unwrap_or_else(|| base_sponsor.clone());

        let mut claimable_balances = Vec::new();

        let constituent_assets = [
            (&pool.asset_a, &pool.asset_a_issuer, amount_a),
            (&pool.asset_b, &pool.asset_b_issuer, amount_b),
        ];

        for (asset_code, asset_issuer, amount) in constituent_assets {
            if amount > 0 && *asset_issuer != pool.owner {
                // Determine clawback flag from constituent trustline
                let clawback_flag_enabled = if *asset_code == operation.asset.code
                    && *asset_issuer == operation.asset.issuer
                {
                    (operation.before_flags & TRUSTLINE_CLAWBACK_ENABLED_FLAG) != 0
                } else {
                    snapshot
                        .trustlines
                        .iter()
                        .find(|tl| {
                            tl.owner == pool.owner
                                && tl.asset.code == *asset_code
                                && tl.asset.issuer == *asset_issuer
                        })
                        .is_some_and(|tl| (tl.flags & TRUSTLINE_CLAWBACK_ENABLED_FLAG) != 0)
                };

                let claimable_balance_id = if can_derive_cb_id {
                    let tx_src = operation.tx_source_account.as_ref().unwrap();
                    let seq = operation.sequence.unwrap();
                    let op_idx = operation.operation_index.unwrap();

                    match (
                        decode_account_id(tx_src),
                        discovery::decode_pool_id(&pool.pool_id),
                        make_xdr_asset(asset_code, asset_issuer),
                    ) {
                        (Ok(src_bytes), Ok(p_id), Ok(xdr_asset)) => {
                            let src_acc_id =
                                AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(src_bytes)));
                            match derive_pool_revoke_claimable_balance_id(
                                src_acc_id,
                                SequenceNumber(seq as i64),
                                op_idx,
                                p_id.0,
                                xdr_asset,
                            ) {
                                Ok(h) => Some(hex::encode(h.0)),
                                Err(_) => None,
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                };

                claimable_balances.push(ClaimableBalanceForecast {
                    pool_id: pool.pool_id.clone(),
                    asset: (*asset_code).clone(),
                    amount_stroops: amount,
                    sponsor: sponsor.clone(),
                    claimable_balance_id,
                    clawback_flag_enabled,
                });
            }
        }

        let num_cb = claimable_balances.len() as i64;
        let owner_delta = deltas.entry(pool.owner.clone()).or_insert(AccountDelta {
            id: pool.owner.clone(),
            balance_stroops: 0,
            subentries: 0,
            num_sponsoring: 0,
            num_sponsored: 0,
        });
        owner_delta.subentries -= 2;
        if pool.sponsor.is_some() {
            owner_delta.num_sponsored -= 2;
        } else if active_replacement_sponsor.is_none() {
            owner_delta.num_sponsoring += num_cb;
        }

        if pool.sponsor.is_some() {
            let pool_sponsor_delta = deltas.entry(base_sponsor.clone()).or_insert(AccountDelta {
                id: base_sponsor.clone(),
                balance_stroops: 0,
                subentries: 0,
                num_sponsoring: 0,
                num_sponsored: 0,
            });
            pool_sponsor_delta.num_sponsoring -= 2;
            if active_replacement_sponsor.is_none() {
                pool_sponsor_delta.num_sponsoring += num_cb;
            }
        }

        if let Some(replacement) = active_replacement_sponsor {
            let replacement_delta = deltas.entry(replacement.clone()).or_insert(AccountDelta {
                id: replacement,
                balance_stroops: 0,
                subentries: 0,
                num_sponsoring: 0,
                num_sponsored: 0,
            });
            replacement_delta.num_sponsoring += num_cb;
        }

        redemptions.push(PoolRedemptionForecast {
            pool_id: pool.pool_id.clone(),
            owner: pool.owner.clone(),
            withdrawn_a_stroops: amount_a,
            withdrawn_b_stroops: amount_b,
            claimable_balances,
        });
    }

    if redemptions.is_empty() && eval_errors.is_empty() {
        let mut warnings = vec![
            "no affected pool-share trustlines were found; discovery is not independently verified"
                .to_owned(),
        ];
        if let Some(w) = coverage_warning {
            warnings.push(w);
        }
        if let Some(w) = sponsorship_warning {
            warnings.push(w);
        }
        warnings.extend(eval_warnings);
        return Report {
            classification: Classification::UnverifiedForecast,
            transition,
            pool_redemptions: redemptions,
            account_deltas: deltas.into_values().collect(),
            warnings,
            errors: eval_errors,
        };
    }

    // Evaluate deltas and reserves
    let mut invalid_counter_errors = Vec::new();
    let mut blocked_errors = Vec::new();

    for delta in deltas.values() {
        let Some(before) = account(snapshot, &delta.id) else {
            invalid_counter_errors.push(format!("account {} disappeared from snapshot", delta.id));
            continue;
        };

        let subentries_res: Result<u32, _> =
            (i64::from(before.subentries) + delta.subentries).try_into();
        let sponsoring_res: Result<u32, _> =
            (i64::from(before.num_sponsoring) + delta.num_sponsoring).try_into();
        let sponsored_res: Result<u32, _> =
            (i64::from(before.num_sponsored) + delta.num_sponsored).try_into();

        let (subentries, num_sponsoring, num_sponsored) =
            match (subentries_res, sponsoring_res, sponsored_res) {
                (Ok(sub), Ok(sping), Ok(sped)) => (sub, sping, sped),
                _ => {
                    invalid_counter_errors.push(format!(
                        "counter arithmetic underflow or overflow for account {}",
                        delta.id
                    ));
                    continue;
                }
            };

        let after = AccountState {
            id: before.id.clone(),
            balance_stroops: before.balance_stroops,
            buying_liabilities_stroops: before.buying_liabilities_stroops,
            selling_liabilities_stroops: before.selling_liabilities_stroops,
            subentries,
            num_sponsoring,
            num_sponsored,
            last_modified_ledger_seq: before.last_modified_ledger_seq,
        };

        // Protocol invariant: num_sponsored <= 2 + subentries + num_sponsoring
        if u128::from(after.num_sponsored)
            > 2 + u128::from(after.subentries) + u128::from(after.num_sponsoring)
        {
            invalid_counter_errors.push(format!(
                "account {} num_sponsored violates invariant: exceeds subentries + num_sponsoring + 2",
                after.id
            ));
            continue;
        }

        // Stellar Core opTOO_MANY_SPONSORING
        if u128::from(after.num_sponsoring) + u128::from(after.subentries) > u128::from(u32::MAX) {
            blocked_errors.push(format!(
                "{} exceeds the UINT32_MAX sponsorship accounting limit",
                after.id
            ));
            continue;
        }

        // Reserve check
        let base_reserve = match snapshot.base_reserve_stroops {
            Some(r) => r,
            None => {
                invalid_counter_errors.push("base reserve is unavailable".to_owned());
                continue;
            }
        };

        let min_balance = match minimum_balance(&after, base_reserve) {
            Ok(m) => m,
            Err(e) => {
                invalid_counter_errors.push(e);
                continue;
            }
        };

        let total_required =
            match min_balance.checked_add(u128::from(after.selling_liabilities_stroops)) {
                Some(t) => t,
                None => {
                    invalid_counter_errors.push(format!(
                        "reserve and liabilities overflow for account {}",
                        after.id
                    ));
                    continue;
                }
            };

        if u128::from(after.balance_stroops) < total_required {
            blocked_errors.push(format!(
                "{} would be below reserve: balance {}, minimum {}",
                after.id, after.balance_stroops, total_required
            ));
        }
    }

    let mut all_errors = eval_errors;
    let classification = if !invalid_counter_errors.is_empty() {
        all_errors.extend(invalid_counter_errors);
        all_errors.extend(blocked_errors);
        Classification::Inconclusive
    } else if !blocked_errors.is_empty() {
        all_errors.extend(blocked_errors);
        Classification::SupportedBlocked
    } else if !all_errors.is_empty() {
        Classification::Inconclusive
    } else {
        Classification::UnverifiedForecast
    };

    let mut warnings = vec![
        "forecast is internally consistent but discovery is not independently verified".to_owned(),
    ];
    if let Some(w) = coverage_warning {
        warnings.push(w);
    }
    if let Some(w) = sponsorship_warning {
        warnings.push(w);
    }
    warnings.extend(eval_warnings);

    Report {
        classification,
        transition,
        pool_redemptions: redemptions,
        account_deltas: deltas.into_values().collect(),
        warnings,
        errors: all_errors,
    }
}

fn maintains_liabilities(flags: u32) -> bool {
    flags & (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG) != 0
}

pub fn classify_transition(before: u32, after: u32) -> Transition {
    if before == after {
        Transition::NoEffect
    } else if maintains_liabilities(before) && !maintains_liabilities(after) {
        Transition::ForcedPoolRedemption
    } else {
        Transition::MaintainLiabilitiesOnly
    }
}

pub fn decode_set_trust_line_flags(
    bytes: &[u8],
) -> Result<SetTrustLineFlagsOp, stellar_xdr::Error> {
    SetTrustLineFlagsOp::from_xdr(bytes, Limits::none())
}

pub fn decode_flags(bytes: &[u8]) -> Result<u32, stellar_xdr::Error> {
    Ok(decode_set_trust_line_flags(bytes)?.set_flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{AccountId, AlphaNum4, Asset, AssetCode4, PublicKey, Uint256, WriteXdr};

    fn snapshot(sponsor: Option<&str>, manifest_valid: bool) -> Snapshot {
        let pool_ids = vec!["pool-1".to_owned()];
        Snapshot {
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
            ledger_sequence: 100,
            entries_ledger_sequence: 100,
            discovery: DiscoveryProof {
                source: DiscoverySource::SyntheticFixture,
                target_ledger_sequence: 100,
                pool_ids: if manifest_valid {
                    pool_ids.clone()
                } else {
                    Vec::new()
                },
                manifest_sha256: if manifest_valid {
                    discovery_manifest_sha256("Test SDF Network ; September 2015", 100, &pool_ids)
                } else {
                    "invalid".to_owned()
                },
                coverage: DiscoveryCoverage::Unproven,
                evidence_classification: None,
            },
            base_reserve_stroops: Some(5_000_000),
            protocol_version: Some(20),
            sponsorship_evidence_complete: true,
            accounts: vec![
                AccountState {
                    id: "issuer".to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: None,
                },
                AccountState {
                    id: "holder".to_owned(),
                    balance_stroops: 20_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 2,
                    num_sponsoring: 0,
                    num_sponsored: if sponsor.is_some() { 2 } else { 0 },
                    last_modified_ledger_seq: None,
                },
                AccountState {
                    id: "sponsor".to_owned(),
                    balance_stroops: 100_000_000,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: if sponsor.is_some() { 2 } else { 0 },
                    num_sponsored: 0,
                    last_modified_ledger_seq: None,
                },
                AccountState {
                    id: "replacement".to_owned(),
                    balance_stroops: 0,
                    buying_liabilities_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                    last_modified_ledger_seq: None,
                },
            ],
            trustlines: vec![CreditTrustlineState {
                owner: "holder".to_owned(),
                asset: CreditAsset {
                    code: "USD".to_owned(),
                    issuer: "issuer".to_owned(),
                },
                flags: AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG,
                sponsor: None,
                liquidity_pool_use_count: None,
                last_modified_ledger_seq: None,
            }],
            pool_share_trustlines: vec![PoolShareState {
                pool_id: "pool-1".to_owned(),
                owner: "holder".to_owned(),
                asset_a: "USD".to_owned(),
                asset_a_issuer: "issuer".to_owned(),
                asset_b: "EUR".to_owned(),
                asset_b_issuer: "other-issuer".to_owned(),
                reserve_a: 5_000,
                reserve_b: 8_000,
                total_pool_shares: 1_000,
                owner_pool_shares: 125,
                sponsor: sponsor.map(str::to_owned),
                last_modified_ledger_seq: None,
            }],
            sponsorship_handoffs: Vec::new(),
        }
    }

    fn revoke() -> OperationSpec {
        OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "issuer".to_owned(),
            tx_source_account: None,
            trustor: "holder".to_owned(),
            sequence: Some(42),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "USD".to_owned(),
                issuer: "issuer".to_owned(),
            },
            before_flags: AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG,
            after_flags: 0,
        }
    }

    #[test]
    fn maintain_liabilities_transition_does_not_redeem() {
        assert_eq!(
            classify_transition(AUTHORIZED_FLAG, AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG),
            Transition::MaintainLiabilitiesOnly
        );
    }

    #[test]
    fn clearing_maintain_liabilities_enters_redemption_path() {
        assert_eq!(
            classify_transition(AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG, 0),
            Transition::ForcedPoolRedemption
        );
    }

    #[test]
    fn exact_integer_redemption_uses_floor() {
        let amount = 125_u128;
        let reserve_a = 5_000_u128;
        let reserve_b = 8_000_u128;
        let total = 1_000_u128;
        assert_eq!(amount * reserve_a / total, 625);
        assert_eq!(amount * reserve_b / total, 1_000);
    }

    #[test]
    fn decodes_a_classic_set_trust_line_flags_op() {
        let issuer = AccountId::from(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])));
        let op = SetTrustLineFlagsOp {
            trustor: issuer.clone(),
            asset: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"TEST"),
                issuer,
            }),
            clear_flags: AUTHORIZED_FLAG,
            set_flags: AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG,
        };
        let encoded = op.to_xdr(Limits::none()).expect("encode fixture");
        let decoded = decode_set_trust_line_flags(&encoded).expect("decode fixture");
        assert_eq!(decoded.clear_flags, AUTHORIZED_FLAG);
        assert_eq!(decoded.set_flags, AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG);
    }

    #[test]
    fn evaluates_two_claimable_balance_redemption() {
        let report = evaluate(&revoke(), &snapshot(None, true));
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_eq!(report.pool_redemptions[0].withdrawn_a_stroops, 625);
        assert_eq!(report.pool_redemptions[0].withdrawn_b_stroops, 1_000);
        assert_eq!(report.pool_redemptions[0].claimable_balances.len(), 2);
    }

    #[test]
    fn zero_or_one_claimable_balance_is_not_collapsed_to_two() {
        let mut one = snapshot(None, true);
        one.pool_share_trustlines[0].asset_b_issuer = "holder".to_owned();
        let report = evaluate(&revoke(), &one);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_eq!(report.pool_redemptions[0].claimable_balances.len(), 1);

        let mut zero = one;
        zero.pool_share_trustlines[0].owner_pool_shares = 1;
        zero.pool_share_trustlines[0].reserve_a = 1;
        let report = evaluate(&revoke(), &zero);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert!(report.pool_redemptions[0].claimable_balances.is_empty());
    }

    #[test]
    fn sponsored_pool_share_uses_sponsor_and_sponsorship_handoff_uses_replacement() {
        let sponsored = snapshot(Some("sponsor"), true);
        let report = evaluate(&revoke(), &sponsored);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert!(
            report.pool_redemptions[0]
                .claimable_balances
                .iter()
                .all(|balance| balance.sponsor == "sponsor")
        );

        let mut sandwich = sponsored;
        sandwich.accounts[3].balance_stroops = 100_000_000;
        sandwich.sponsorship_handoffs.push(SponsorshipHandoff {
            sponsored_account: "sponsor".to_owned(),
            replacement_sponsor: "replacement".to_owned(),
            begin_operation_index: 0,
            revoke_operation_index: 1,
            end_operation_index: Some(2),
        });
        let mut op = revoke();
        op.operation_index = Some(1);
        let report = evaluate(&op, &sandwich);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert!(
            report.pool_redemptions[0]
                .claimable_balances
                .iter()
                .all(|balance| balance.sponsor == "replacement")
        );
    }

    #[test]
    fn only_the_target_trustor_and_exact_issuer_asset_are_affected() {
        let mut state = snapshot(None, true);
        state.pool_share_trustlines.push(PoolShareState {
            pool_id: "pool-2".to_owned(),
            owner: "other-holder".to_owned(),
            asset_a: "USD".to_owned(),
            asset_a_issuer: "issuer".to_owned(),
            asset_b: "EUR".to_owned(),
            asset_b_issuer: "other-issuer".to_owned(),
            reserve_a: 5_000,
            reserve_b: 8_000,
            total_pool_shares: 1_000,
            owner_pool_shares: 125,
            sponsor: None,
            last_modified_ledger_seq: None,
        });
        state.pool_share_trustlines.push(PoolShareState {
            pool_id: "pool-3".to_owned(),
            owner: "holder".to_owned(),
            asset_a: "USD".to_owned(),
            asset_a_issuer: "wrong-issuer".to_owned(),
            asset_b: "EUR".to_owned(),
            asset_b_issuer: "other-issuer".to_owned(),
            reserve_a: 5_000,
            reserve_b: 8_000,
            total_pool_shares: 1_000,
            owner_pool_shares: 125,
            sponsor: None,
            last_modified_ledger_seq: None,
        });
        state.accounts.push(AccountState {
            id: "other-holder".to_owned(),
            balance_stroops: 20_000_000,
            buying_liabilities_stroops: 0,
            selling_liabilities_stroops: 0,
            subentries: 2,
            num_sponsoring: 0,
            num_sponsored: 0,
            last_modified_ledger_seq: None,
        });
        state.discovery.pool_ids.push("pool-2".to_owned());
        state.discovery.pool_ids.push("pool-3".to_owned());
        state.discovery.manifest_sha256 = discovery_manifest_sha256(
            &state.network_passphrase,
            state.ledger_sequence,
            &state.discovery.pool_ids,
        );
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_eq!(report.pool_redemptions.len(), 1);
        assert_eq!(report.pool_redemptions[0].pool_id, "pool-1");
    }

    #[test]
    fn target_trustline_mismatch_is_inconclusive() {
        let mut state = snapshot(None, true);
        state.trustlines[0].flags = AUTHORIZED_FLAG;
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("before flags"))
        );
    }

    #[test]
    fn invalid_discovery_manifest_is_inconclusive() {
        let report = evaluate(&revoke(), &snapshot(None, false));
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(report.pool_redemptions.is_empty());
    }

    #[test]
    fn mismatched_ledger_sequences_are_inconclusive() {
        let mut state = snapshot(None, true);
        state.entries_ledger_sequence = 99;
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::Inconclusive);
    }

    #[test]
    fn internally_consistent_but_incomplete_snapshot_is_unverified_only() {
        let mut state = snapshot(None, true);
        state.pool_share_trustlines.clear();
        state.discovery.pool_ids.clear();
        state.discovery.manifest_sha256 = discovery_manifest_sha256(
            &state.network_passphrase,
            state.ledger_sequence,
            &state.discovery.pool_ids,
        );
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("not independently verified"))
        );
        assert_ne!(report.classification, Classification::SupportedSafe);
    }

    #[test]
    fn ledger_capture_metadata_alone_cannot_establish_completeness() {
        let mut state = snapshot(None, true);
        state.discovery.source = DiscoverySource::LedgerCapture {
            endpoint: "https://rpc.example.invalid".to_owned(),
        };
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_ne!(report.classification, Classification::SupportedSafe);
    }

    #[test]
    fn contradictory_pool_identity_is_inconclusive() {
        let mut state = snapshot(None, true);
        state.pool_share_trustlines[0].asset_b = "USD".to_owned();
        state.pool_share_trustlines[0].asset_b_issuer = "issuer".to_owned();
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::Inconclusive);
    }

    #[test]
    fn active_sponsorship_handoff_can_block_on_low_reserve() {
        let mut state = snapshot(Some("sponsor"), true);
        state.sponsorship_handoffs.push(SponsorshipHandoff {
            sponsored_account: "sponsor".to_owned(),
            replacement_sponsor: "replacement".to_owned(),
            begin_operation_index: 0,
            revoke_operation_index: 1,
            end_operation_index: Some(2),
        });
        let mut op = revoke();
        op.operation_index = Some(1);
        let report = evaluate(&op, &state);
        assert_eq!(report.classification, Classification::SupportedBlocked);
        assert_ne!(report.classification, Classification::UnverifiedForecast);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("replacement"))
        );
    }

    #[test]
    fn unsponsored_active_sponsorship_context_blocks_on_low_reserve() {
        let mut state = snapshot(None, true);
        state.sponsorship_handoffs.push(SponsorshipHandoff {
            sponsored_account: "holder".to_owned(),
            replacement_sponsor: "replacement".to_owned(),
            begin_operation_index: 0,
            revoke_operation_index: 1,
            end_operation_index: Some(2),
        });
        let mut op = revoke();
        op.operation_index = Some(1);
        let report = evaluate(&op, &state);
        assert_eq!(report.classification, Classification::SupportedBlocked);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("replacement") && error.contains("below reserve"))
        );
    }

    #[test]
    fn inconsistent_sponsorship_counters_are_inconclusive() {
        let mut state = snapshot(Some("sponsor"), true);
        state.accounts[2].num_sponsoring = 0;
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("sponsor counter"))
        );
    }

    #[test]
    fn fixture_schema_round_trips_as_json() {
        let encoded = serde_json::to_string(&snapshot(None, true)).expect("serialize fixture");
        let decoded: Snapshot = serde_json::from_str(&encoded).expect("deserialize fixture");
        assert_eq!(decoded.ledger_sequence, 100);
        assert_eq!(decoded.pool_share_trustlines.len(), 1);
    }

    #[test]
    fn authoritative_result_codes_map_conservatively() {
        assert_eq!(
            map_allow_trust_result(AllowTrustResultCode::Success),
            Classification::UnverifiedForecast
        );
        assert_eq!(
            map_allow_trust_result(AllowTrustResultCode::LowReserve),
            Classification::SupportedBlocked
        );
        assert_eq!(
            map_set_trust_line_flags_result(SetTrustLineFlagsResultCode::InvalidState),
            Classification::SupportedBlocked
        );
        assert_eq!(
            map_set_trust_line_flags_result(SetTrustLineFlagsResultCode::LowReserve),
            Classification::SupportedBlocked
        );
        assert_eq!(
            map_operation_result(OperationResultCode::OpTooManySponsoring),
            Classification::SupportedBlocked
        );
        assert_eq!(
            map_operation_result(OperationResultCode::OpNotSupported),
            Classification::Unsupported
        );
        assert_eq!(
            map_operation_result(OperationResultCode::OpInner),
            Classification::Inconclusive
        );
    }

    #[test]
    fn derives_cap0038_pool_revoke_id_from_xdr_preimage() {
        let source = AccountId::from(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])));
        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"TEST"),
            issuer: source.clone(),
        });
        let id = derive_pool_revoke_claimable_balance_id(
            source,
            SequenceNumber(42),
            0,
            Hash([9; 32]),
            asset,
        )
        .expect("derive claimable balance ID");
        assert_eq!(
            hex::encode(id.0),
            "0a76bfde6dafd3b0f171ec064a56242f7cbc846bef3bc50296b87714a39e1553"
        );
    }

    #[test]
    fn derives_canonical_constant_product_pool_ids() {
        // Pool 1: SDK:GA5Q3FB... and FLUTTER:GBYEWT4...
        let sdk_issuer_hex = "3b0d94347e15c9ec301a17598cadd4c4b5b423c002c2e637993415ddfd166ee8";
        let mut sdk_code = [0u8; 4];
        sdk_code[..3].copy_from_slice(b"SDK");
        let mut sdk_issuer_bytes = [0u8; 32];
        hex::decode_to_slice(sdk_issuer_hex, &mut sdk_issuer_bytes).unwrap();
        let sdk = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(sdk_code),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(sdk_issuer_bytes))),
        });

        let flutter_issuer_hex = "704b4f98b83b04bd23c149257a7adb926a172399c053d32d2d72bb31c93710e9";
        let mut flutter_code = [0u8; 12];
        flutter_code[..7].copy_from_slice(b"FLUTTER");
        let mut flutter_issuer_bytes = [0u8; 32];
        hex::decode_to_slice(flutter_issuer_hex, &mut flutter_issuer_bytes).unwrap();
        let flutter = Asset::CreditAlphanum12(stellar_xdr::AlphaNum12 {
            asset_code: stellar_xdr::AssetCode12(flutter_code),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                flutter_issuer_bytes,
            ))),
        });

        let pool1_id = derive_constant_product_pool_id(&sdk, &flutter, 30).unwrap();
        assert_eq!(
            hex::encode(pool1_id.0),
            "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46"
        );

        // Pool 2: Native and FLUTTER:GBYEWT4...
        let pool2_id = derive_constant_product_pool_id(&Asset::Native, &flutter, 30).unwrap();
        assert_eq!(
            hex::encode(pool2_id.0),
            "078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c"
        );
    }

    #[test]
    fn evaluates_live_testnet_discovery_fixture() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert_eq!(report.transition, Transition::ForcedPoolRedemption);
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(report.pool_redemptions.len(), 2);

        let pool1_redemption = report
            .pool_redemptions
            .iter()
            .find(|r| {
                r.pool_id == "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46"
            })
            .expect("pool 1 redemption");
        assert_eq!(pool1_redemption.withdrawn_a_stroops, 700000000);
        assert_eq!(pool1_redemption.withdrawn_b_stroops, 514506217);

        let pool2_redemption = report
            .pool_redemptions
            .iter()
            .find(|r| {
                r.pool_id == "078ff7f339a3a1c950812bd143431498f880082e0ebdb95fb348a5b87693465c"
            })
            .expect("pool 2 redemption");
        assert_eq!(pool2_redemption.withdrawn_a_stroops, 4980000000);
        assert_eq!(pool2_redemption.withdrawn_b_stroops, 4980000000);

        assert!(
            pool1_redemption
                .claimable_balances
                .iter()
                .all(|cb| cb.claimable_balance_id.is_some()),
            "claimable balance IDs must be derived when context is present"
        );
        assert!(
            pool2_redemption
                .claimable_balances
                .iter()
                .all(|cb| cb.claimable_balance_id.is_some()),
            "claimable balance IDs must be derived when context is present"
        );

        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("not independently verified")),
            "missing unverified warning"
        );
    }

    #[test]
    fn incomplete_pool_discovery_fails_closed_as_inconclusive() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // Omit pool 2 from pool_share_trustlines and manifest
        snapshot.pool_share_trustlines.retain(|p| {
            p.pool_id == "00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46"
        });
        snapshot.discovery.pool_ids =
            vec!["00171ffe02f113eb286c4fe0642ceb9f1b508e09c6160374a22bb9ab4240ad46".to_owned()];
        snapshot.discovery.manifest_sha256 = discovery_manifest_sha256(
            &snapshot.network_passphrase,
            snapshot.ledger_sequence,
            &snapshot.discovery.pool_ids,
        );

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report.errors.iter().any(|e| e.contains(
                "liquidityPoolUseCount (2) does not match discovered affected pools (1)"
            )),
            "expected count mismatch error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn mixed_ledger_sequence_fails_closed_as_inconclusive() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // One pool has a newer ledger sequence than the target ledger
        snapshot.pool_share_trustlines[0].last_modified_ledger_seq = Some(5413925);

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("newer than snapshot ledger")),
            "expected ledger sequence error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn wrong_issuer_in_pool_fails_reconciliation() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // Mutate pool 2 asset_b_issuer to a wrong issuer
        snapshot.pool_share_trustlines[1].asset_b_issuer =
            "GA5Q3FBUPYK4T3BQDILVTDFN2TCLLNBDYABMFZRXTE2BLXP5CZXOQFWM".to_owned();

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report.errors.iter().any(|e| e.contains(
                "liquidityPoolUseCount (2) does not match discovered affected pools (1)"
            )),
            "expected affected pool count mismatch due to wrong issuer, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn unproven_coverage_emits_explicit_warning() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        snapshot.discovery.coverage = DiscoveryCoverage::Unproven;

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::UnverifiedForecast);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("coverage is unproven; liquidityPoolUseCount not verified")),
            "expected unproven coverage warning, got: {:?}",
            report.warnings
        );
    }

    #[test]
    fn test_manifest_duplicate_pool_id_rejected() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // Duplicate pool 1 in manifest
        snapshot
            .discovery
            .pool_ids
            .push(snapshot.discovery.pool_ids[0].clone());
        snapshot.discovery.manifest_sha256 = discovery_manifest_sha256(
            &snapshot.network_passphrase,
            snapshot.ledger_sequence,
            &snapshot.discovery.pool_ids,
        );

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("duplicate pool ID in discovery manifest")),
            "expected duplicate manifest pool ID error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn test_pool_share_owned_by_other_account_cannot_satisfy_counter() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // Mutate pool 2 owner to another account
        snapshot.pool_share_trustlines[1].owner =
            "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned();

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report.errors.iter().any(|e| e.contains(
                "liquidityPoolUseCount (2) does not match discovered affected pools (1)"
            )),
            "expected count mismatch when pool is owned by different account, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn test_spurious_non_matching_pool_cannot_satisfy_counter() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // Mutate pool 2 assets to not include the credit asset FLUTTER
        snapshot.pool_share_trustlines[1].asset_a = "BTC".to_owned();
        snapshot.pool_share_trustlines[1].asset_a_issuer =
            "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned();
        snapshot.pool_share_trustlines[1].asset_b = "ETH".to_owned();
        snapshot.pool_share_trustlines[1].asset_b_issuer =
            "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned();

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report.errors.iter().any(|e| e.contains(
                "liquidityPoolUseCount (2) does not match discovered affected pools (1)"
            )),
            "expected count mismatch when pool has non-matching assets, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn test_credit_trustline_newer_than_snapshot_rejected() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // Target credit trustline is newer than snapshot ledger
        snapshot.trustlines[0].last_modified_ledger_seq = Some(snapshot.ledger_sequence + 1);

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("newer than snapshot ledger")),
            "expected trustline newer than snapshot error, got: {:?}",
            report.errors
        );
    }

    #[test]
    fn test_authoritative_reconciliation_count_mismatch_rejected() {
        let fixture_bytes = include_bytes!("../fixtures/live-testnet-discovery.json");
        let mut snapshot: Snapshot = serde_json::from_slice(fixture_bytes).unwrap();

        // Reconciliation coverage reports 3 pools when trustline has 2
        snapshot.discovery.coverage = DiscoveryCoverage::AuthoritativeReconciled {
            liquidity_pool_use_count: 3,
            verified_pool_count: 3,
        };

        let op = OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            tx_source_account: Some(
                "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            ),
            trustor: "GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB".to_owned(),
            sequence: Some(1),
            operation_index: Some(0),
            asset: CreditAsset {
                code: "FLUTTER".to_owned(),
                issuer: "GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG".to_owned(),
            },
            before_flags: AUTHORIZED_FLAG,
            after_flags: 0,
        };

        let report = evaluate(&op, &snapshot);
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(
            report.errors.iter().any(|e| e.contains(
                "discovery coverage verified_pool_count 3 does not match snapshot affected pools 2"
            )),
            "expected coverage reconciliation mismatch error, got: {:?}",
            report.errors
        );
    }
}
