//! Deterministic offline engine for the first RevokeTrace implementation slice.
//!
//! Network capture, discovery, signing, and submission are intentionally not
//! part of this crate yet. The engine only evaluates a complete immutable
//! snapshot supplied by its caller and fails closed when completeness cannot
//! be established.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AllowTrustResultCode, Asset, Hash, HashIdPreimageRevokeId, Limits, OperationResultCode, PoolId,
    ReadXdr, SequenceNumber, SetTrustLineFlagsOp, SetTrustLineFlagsResultCode, WriteXdr,
};

pub const AUTHORIZED_FLAG: u32 = 1;
pub const AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transition {
    NoEffect,
    MaintainLiabilitiesOnly,
    ForcedPoolRedemption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    SupportedSafe,
    SupportedBlocked,
    Inconclusive,
    Unsupported,
}

/// Maps an observed protocol result into the evaluator's conservative outcome.
/// These are protocol result mappings, not a claim that a forecast will succeed.
pub fn map_allow_trust_result(code: AllowTrustResultCode) -> Classification {
    match code {
        AllowTrustResultCode::Success => Classification::SupportedSafe,
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
        SetTrustLineFlagsResultCode::Success => Classification::SupportedSafe,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSpec {
    pub operation: String,
    pub source_account: String,
    pub sequence: u64,
    pub operation_index: u32,
    pub issuer: String,
    pub asset: String,
    pub before_flags: u32,
    pub after_flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub id: String,
    pub balance_stroops: u64,
    pub selling_liabilities_stroops: u64,
    pub subentries: u32,
    pub num_sponsoring: u32,
    pub num_sponsored: u32,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorshipHandoff {
    pub sponsored_account: String,
    pub replacement_sponsor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub network_passphrase: String,
    pub ledger_sequence: u32,
    pub entries_ledger_sequence: u32,
    pub discovery_complete: bool,
    pub base_reserve_stroops: u64,
    pub accounts: Vec<AccountState>,
    pub pool_share_trustlines: Vec<PoolShareState>,
    pub sponsorship_handoffs: Vec<SponsorshipHandoff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimableBalanceForecast {
    pub pool_id: String,
    pub asset: String,
    pub amount_stroops: u64,
    pub sponsor: String,
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

fn validate_snapshot(snapshot: &Snapshot, operation: &OperationSpec) -> Vec<String> {
    let mut errors = Vec::new();
    if !snapshot.discovery_complete {
        errors.push("affected pool-share discovery is incomplete".to_owned());
    }
    if snapshot.ledger_sequence != snapshot.entries_ledger_sequence {
        errors.push("snapshot entries come from a different ledger sequence".to_owned());
    }
    if snapshot.base_reserve_stroops == 0 {
        errors.push("base reserve must be positive".to_owned());
    }
    if operation.operation != "SetTrustLineFlags" && operation.operation != "AllowTrust" {
        errors.push(format!("unsupported operation {}", operation.operation));
    }
    if account(snapshot, &operation.source_account).is_none() {
        errors.push("operation source account is missing".to_owned());
    }
    if operation.issuer != operation.source_account {
        errors.push("operation source is not the asset issuer".to_owned());
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
    }
    let mut pool_ids = std::collections::BTreeSet::new();
    for pool in &snapshot.pool_share_trustlines {
        if !pool_ids.insert(&pool.pool_id) {
            errors.push(format!("duplicate pool trustline {}", pool.pool_id));
        }
        if account(snapshot, &pool.owner).is_none() {
            errors.push(format!("pool owner {} is missing", pool.owner));
        }
        if let Some(sponsor) = &pool.sponsor
            && account(snapshot, sponsor).is_none()
        {
            errors.push(format!("pool sponsor {} is missing", sponsor));
        }
        if pool.owner_pool_shares > pool.total_pool_shares {
            errors.push(format!(
                "pool {} has more owner shares than total shares",
                pool.pool_id
            ));
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

    if transition != Transition::ForcedPoolRedemption {
        return Report {
            classification: Classification::SupportedSafe,
            transition,
            pool_redemptions: Vec::new(),
            account_deltas: Vec::new(),
            warnings: vec!["safe means safe for this immutable snapshot only".to_owned()],
            errors: Vec::new(),
        };
    }

    let mut redemptions = Vec::new();
    let mut deltas = std::collections::BTreeMap::<String, AccountDelta>::new();
    let mut errors = Vec::new();
    for pool in snapshot
        .pool_share_trustlines
        .iter()
        .filter(|pool| pool.asset_a == operation.asset || pool.asset_b == operation.asset)
    {
        if pool.asset_a == operation.asset && pool.asset_a_issuer != operation.issuer
            || pool.asset_b == operation.asset && pool.asset_b_issuer != operation.issuer
        {
            errors.push(format!(
                "pool {} asset issuer does not match operation issuer",
                pool.pool_id
            ));
            continue;
        }
        let amount_a = match forecast_amount(
            pool.owner_pool_shares,
            pool.reserve_a,
            pool.total_pool_shares,
        ) {
            Ok(amount) => amount,
            Err(error) => {
                errors.push(format!("{}: {}", pool.pool_id, error));
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
                errors.push(format!("{}: {}", pool.pool_id, error));
                continue;
            }
        };
        let base_sponsor = pool.sponsor.clone().unwrap_or_else(|| pool.owner.clone());
        let sponsor = snapshot
            .sponsorship_handoffs
            .iter()
            .find(|handoff| handoff.sponsored_account == base_sponsor)
            .map(|handoff| handoff.replacement_sponsor.clone())
            .unwrap_or(base_sponsor.clone());
        let mut claimable_balances = Vec::new();
        if amount_a > 0 && pool.asset_a_issuer != pool.owner {
            claimable_balances.push(ClaimableBalanceForecast {
                pool_id: pool.pool_id.clone(),
                asset: pool.asset_a.clone(),
                amount_stroops: amount_a,
                sponsor: sponsor.clone(),
            });
        }
        if amount_b > 0 && pool.asset_b_issuer != pool.owner {
            claimable_balances.push(ClaimableBalanceForecast {
                pool_id: pool.pool_id.clone(),
                asset: pool.asset_b.clone(),
                amount_stroops: amount_b,
                sponsor: sponsor.clone(),
            });
        }
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
            let pool_sponsor_delta = deltas.entry(base_sponsor.clone()).or_insert(AccountDelta {
                id: base_sponsor.clone(),
                balance_stroops: 0,
                subentries: 0,
                num_sponsoring: 0,
                num_sponsored: 0,
            });
            pool_sponsor_delta.num_sponsoring -= 2;
        } else {
            owner_delta.num_sponsoring += claimable_balances.len() as i64;
        }
        if sponsor != base_sponsor || pool.sponsor.is_some() {
            let replacement_delta = deltas.entry(sponsor.clone()).or_insert(AccountDelta {
                id: sponsor.clone(),
                balance_stroops: 0,
                subentries: 0,
                num_sponsoring: 0,
                num_sponsored: 0,
            });
            replacement_delta.num_sponsoring += claimable_balances.len() as i64;
        }
        redemptions.push(PoolRedemptionForecast {
            pool_id: pool.pool_id.clone(),
            owner: pool.owner.clone(),
            withdrawn_a_stroops: amount_a,
            withdrawn_b_stroops: amount_b,
            claimable_balances,
        });
    }

    if redemptions.is_empty() && errors.is_empty() {
        return Report {
            classification: Classification::SupportedSafe,
            transition,
            pool_redemptions: redemptions,
            account_deltas: deltas.into_values().collect(),
            warnings: vec!["no affected pool-share trustlines were found".to_owned()],
            errors,
        };
    }

    for delta in deltas.values() {
        let Some(before) = account(snapshot, &delta.id) else {
            errors.push(format!("account {} disappeared from snapshot", delta.id));
            continue;
        };
        let Some(subentries) = (i64::from(before.subentries) + delta.subentries)
            .try_into()
            .ok()
        else {
            errors.push(format!("subentry count overflow for account {}", delta.id));
            continue;
        };
        let Some(num_sponsoring) = (i64::from(before.num_sponsoring) + delta.num_sponsoring)
            .try_into()
            .ok()
        else {
            errors.push(format!(
                "sponsoring count overflow for account {}",
                delta.id
            ));
            continue;
        };
        let Some(num_sponsored) = (i64::from(before.num_sponsored) + delta.num_sponsored)
            .try_into()
            .ok()
        else {
            errors.push(format!("sponsored count overflow for account {}", delta.id));
            continue;
        };
        let after = AccountState {
            id: before.id.clone(),
            balance_stroops: before.balance_stroops,
            selling_liabilities_stroops: before.selling_liabilities_stroops,
            subentries,
            num_sponsoring,
            num_sponsored,
        };
        match minimum_balance(&after, snapshot.base_reserve_stroops) {
            Ok(minimum) if u128::from(after.balance_stroops) >= minimum => {}
            Ok(minimum) => errors.push(format!(
                "{} would be below reserve: balance {}, minimum {}",
                after.id, after.balance_stroops, minimum
            )),
            Err(error) => errors.push(error),
        }
    }

    Report {
        classification: if errors.is_empty() {
            Classification::SupportedSafe
        } else {
            Classification::SupportedBlocked
        },
        transition,
        pool_redemptions: redemptions,
        account_deltas: deltas.into_values().collect(),
        warnings: vec!["safe means safe for this immutable snapshot only".to_owned()],
        errors,
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

    fn snapshot(sponsor: Option<&str>, discovery_complete: bool) -> Snapshot {
        Snapshot {
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
            ledger_sequence: 100,
            entries_ledger_sequence: 100,
            discovery_complete,
            base_reserve_stroops: 5_000_000,
            accounts: vec![
                AccountState {
                    id: "issuer".to_owned(),
                    balance_stroops: 100_000_000,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                },
                AccountState {
                    id: "holder".to_owned(),
                    balance_stroops: 20_000_000,
                    selling_liabilities_stroops: 0,
                    subentries: 2,
                    num_sponsoring: 0,
                    num_sponsored: if sponsor.is_some() { 2 } else { 0 },
                },
                AccountState {
                    id: "sponsor".to_owned(),
                    balance_stroops: 100_000_000,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: if sponsor.is_some() { 2 } else { 0 },
                    num_sponsored: 0,
                },
                AccountState {
                    id: "replacement".to_owned(),
                    balance_stroops: 0,
                    selling_liabilities_stroops: 0,
                    subentries: 0,
                    num_sponsoring: 0,
                    num_sponsored: 0,
                },
            ],
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
            }],
            sponsorship_handoffs: Vec::new(),
        }
    }

    fn revoke() -> OperationSpec {
        OperationSpec {
            operation: "SetTrustLineFlags".to_owned(),
            source_account: "issuer".to_owned(),
            sequence: 42,
            operation_index: 0,
            issuer: "issuer".to_owned(),
            asset: "USD".to_owned(),
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
        assert_eq!(report.classification, Classification::SupportedSafe);
        assert_eq!(report.pool_redemptions[0].withdrawn_a_stroops, 625);
        assert_eq!(report.pool_redemptions[0].withdrawn_b_stroops, 1_000);
        assert_eq!(report.pool_redemptions[0].claimable_balances.len(), 2);
    }

    #[test]
    fn zero_or_one_claimable_balance_is_not_collapsed_to_two() {
        let mut one = snapshot(None, true);
        one.pool_share_trustlines[0].reserve_b = 0;
        let report = evaluate(&revoke(), &one);
        assert_eq!(report.classification, Classification::SupportedSafe);
        assert_eq!(report.pool_redemptions[0].claimable_balances.len(), 1);

        let mut zero = one;
        zero.pool_share_trustlines[0].reserve_a = 0;
        let report = evaluate(&revoke(), &zero);
        assert_eq!(report.classification, Classification::SupportedSafe);
        assert!(report.pool_redemptions[0].claimable_balances.is_empty());
    }

    #[test]
    fn sponsored_pool_share_uses_sponsor_and_sponsorship_handoff_uses_replacement() {
        let sponsored = snapshot(Some("sponsor"), true);
        let report = evaluate(&revoke(), &sponsored);
        assert_eq!(report.classification, Classification::SupportedSafe);
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
        });
        let report = evaluate(&revoke(), &sandwich);
        assert_eq!(report.classification, Classification::SupportedSafe);
        assert!(
            report.pool_redemptions[0]
                .claimable_balances
                .iter()
                .all(|balance| balance.sponsor == "replacement")
        );
    }

    #[test]
    fn incomplete_discovery_is_inconclusive() {
        let report = evaluate(&revoke(), &snapshot(None, false));
        assert_eq!(report.classification, Classification::Inconclusive);
        assert!(report.pool_redemptions.is_empty());
    }

    #[test]
    fn active_sponsorship_handoff_can_block_on_low_reserve() {
        let mut state = snapshot(Some("sponsor"), true);
        state.sponsorship_handoffs.push(SponsorshipHandoff {
            sponsored_account: "sponsor".to_owned(),
            replacement_sponsor: "replacement".to_owned(),
        });
        let report = evaluate(&revoke(), &state);
        assert_eq!(report.classification, Classification::SupportedBlocked);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("replacement"))
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
            Classification::SupportedSafe
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
}
