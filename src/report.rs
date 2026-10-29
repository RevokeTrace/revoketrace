//! Stable human-readable and JSON report projections for the RevokeTrace engine.
//!
//! This module deliberately contains no forecasting logic. It converts the
//! engine's `Snapshot`, `OperationSpec`, and `Report` values into a versioned
//! output contract with deterministic ordering and explicit evidence limits.

use serde::{Deserialize, Serialize};

use crate::evidence::EvidenceClassification;
use crate::{
    AccountDelta, Classification, DiscoveryCoverage, DiscoverySource, OperationSpec,
    PoolRedemptionForecast, Report as EngineReport, Snapshot, Transition,
};

pub const REPORT_SCHEMA_VERSION: u32 = 1;
pub const REPORT_TYPE: &str = "revoketrace.forecast";
pub const TOOL_NAME: &str = "revoketrace";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportMode {
    Offline,
    LiveTestnet,
}

impl ReportMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Offline => "Offline snapshot",
            Self::LiveTestnet => "Live Testnet bounded discovery",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDocument {
    pub schema_version: u32,
    pub report_type: String,
    pub tool: ReportTool,
    pub mode: ReportMode,
    pub operation: ReportOperation,
    pub evidence: ReportEvidence,
    pub forecast: ReportForecast,
    pub warnings: Vec<Diagnostic>,
    pub errors: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOperation {
    pub operation: String,
    pub source_account: String,
    pub transaction_source_account: Option<String>,
    pub trustor: String,
    pub asset: ReportAsset,
    pub before_flags: u32,
    pub after_flags: u32,
    pub sequence: Option<u64>,
    pub operation_index: Option<u32>,
    pub requested_transition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportAsset {
    pub code: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEvidence {
    pub network_passphrase: String,
    pub ledger_sequence: u32,
    pub entries_ledger_sequence: u32,
    pub target_ledger_sequence: u32,
    pub source: ReportSource,
    pub manifest_sha256: String,
    pub coverage: ReportCoverage,
    pub evidence_classification: ReportEvidenceClassification,
    pub base_reserve_stroops: Option<u64>,
    pub protocol_version: Option<u32>,
    pub sponsorship_evidence_complete: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportSource {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportCoverage {
    Unproven,
    AuthoritativeReconciled {
        liquidity_pool_use_count: u32,
        verified_pool_count: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportEvidenceClassification {
    UntrustedCandidate,
    BoundedCurrentTipRpc,
    LedgerConsistentIncomplete,
    CompleteAuthoritativeLedger,
    InvalidOrContradictory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportForecast {
    pub classification: ReportClassification,
    pub transition: ReportTransition,
    pub pool_redemptions: Vec<ReportPoolRedemption>,
    pub account_deltas: Vec<ReportAccountDelta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportClassification {
    SupportedBlocked,
    UnverifiedForecast,
    Inconclusive,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportTransition {
    NoEffect,
    MaintainLiabilitiesOnly,
    ForcedPoolRedemption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPoolRedemption {
    pub pool_id: String,
    pub owner: String,
    pub withdrawn_a_stroops: u64,
    pub withdrawn_b_stroops: u64,
    pub claimable_balances: Vec<ReportClaimableBalance>,
    pub pool_deletion: ReportPoolDeletion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportClaimableBalance {
    pub pool_id: String,
    pub asset: String,
    pub amount_stroops: u64,
    pub sponsor: String,
    pub claimable_balance_id: Option<String>,
    pub clawback_flag_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPoolDeletion {
    pub forecast: Option<bool>,
    pub limitation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportAccountDelta {
    pub id: String,
    pub balance_delta_stroops: i128,
    pub subentries_delta: i64,
    pub num_sponsoring_delta: i64,
    pub num_sponsored_delta: i64,
    pub reserve_units_delta: i64,
    pub reserve_effect_stroops: Option<i128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
}

impl ReportDocument {
    /// Builds a deterministic report from the engine's derived values.
    ///
    /// `evidence_classification` must be the result of the strict evidence
    /// adapter, not a caller-supplied label. `SupportedSafe` is intentionally
    /// rejected because the current engine does not independently verify a
    /// complete authoritative ledger.
    pub fn from_engine(
        mode: ReportMode,
        operation: &OperationSpec,
        snapshot: &Snapshot,
        evidence_classification: EvidenceClassification,
        engine_report: &EngineReport,
    ) -> Result<Self, String> {
        let classification = report_classification(engine_report.classification)?;
        let transition = report_transition(engine_report.transition);
        let evidence = build_evidence(snapshot, evidence_classification, engine_report);

        let mut pool_redemptions = engine_report
            .pool_redemptions
            .iter()
            .map(|pool| build_pool_redemption(pool, &engine_report.warnings))
            .collect::<Vec<_>>();
        pool_redemptions.sort_by(|left, right| left.pool_id.cmp(&right.pool_id));

        let mut account_deltas = engine_report
            .account_deltas
            .iter()
            .map(|delta| build_account_delta(delta, snapshot.base_reserve_stroops))
            .collect::<Result<Vec<_>, _>>()?;
        account_deltas.sort_by(|left, right| left.id.cmp(&right.id));

        let mut warnings = engine_report
            .warnings
            .iter()
            .map(|message| Diagnostic {
                code: warning_code(message).to_owned(),
                message: message.clone(),
            })
            .collect::<Vec<_>>();
        warnings.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then_with(|| left.message.cmp(&right.message))
        });

        let mut errors = engine_report
            .errors
            .iter()
            .map(|message| Diagnostic {
                code: error_code(message).to_owned(),
                message: message.clone(),
            })
            .collect::<Vec<_>>();
        errors.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then_with(|| left.message.cmp(&right.message))
        });

        Ok(Self {
            schema_version: REPORT_SCHEMA_VERSION,
            report_type: REPORT_TYPE.to_owned(),
            tool: ReportTool {
                name: TOOL_NAME.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            mode,
            operation: ReportOperation {
                operation: operation.operation.clone(),
                source_account: operation.source_account.clone(),
                transaction_source_account: operation.tx_source_account.clone(),
                trustor: operation.trustor.clone(),
                asset: ReportAsset {
                    code: operation.asset.code.clone(),
                    issuer: operation.asset.issuer.clone(),
                },
                before_flags: operation.before_flags,
                after_flags: operation.after_flags,
                sequence: operation.sequence,
                operation_index: operation.operation_index,
                requested_transition: transition_name(engine_report.transition).to_owned(),
            },
            evidence,
            forecast: ReportForecast {
                classification,
                transition,
                pool_redemptions,
                account_deltas,
            },
            warnings,
            errors,
        })
    }

    pub fn json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn validate_schema(&self) -> Result<(), String> {
        if self.schema_version != REPORT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported report schema version {}; expected {}",
                self.schema_version, REPORT_SCHEMA_VERSION
            ));
        }
        if self.report_type != REPORT_TYPE {
            return Err(format!(
                "unsupported report type {}; expected {}",
                self.report_type, REPORT_TYPE
            ));
        }
        if self.tool.name != TOOL_NAME {
            return Err(format!(
                "report was produced by unsupported tool {}",
                self.tool.name
            ));
        }
        Ok(())
    }
}

fn build_evidence(
    snapshot: &Snapshot,
    derived_classification: EvidenceClassification,
    engine_report: &EngineReport,
) -> ReportEvidence {
    let mut limitations = Vec::new();

    match derived_classification {
        EvidenceClassification::UntrustedCandidate => limitations.push(
            "the supplied snapshot is not independently verified as complete ledger evidence"
                .to_owned(),
        ),
        EvidenceClassification::BoundedCurrentTipRpc => limitations.push(
            "live discovery is bounded to the enumerated candidate set and does not prove complete ledger coverage"
                .to_owned(),
        ),
        EvidenceClassification::LedgerConsistentIncomplete => limitations.push(
            "ledger sequences are consistent, but one or more required evidence inputs are incomplete"
                .to_owned(),
        ),
        EvidenceClassification::CompleteAuthoritativeLedger => {}
        EvidenceClassification::InvalidOrContradictory => limitations.push(
            "evidence is invalid or contradictory; no authoritative conclusion is available"
                .to_owned(),
        ),
    }

    if snapshot.discovery.evidence_classification != Some(derived_classification) {
        limitations.push(
            "the evidence classification in the input is not used; this value is derived from verified snapshot properties"
                .to_owned(),
        );
    }
    if matches!(snapshot.discovery.coverage, DiscoveryCoverage::Unproven) {
        limitations
            .push("liquidityPoolUseCount reconciliation is unproven for this snapshot".to_owned());
    }
    if !snapshot.sponsorship_evidence_complete {
        limitations.push("sponsorship identities and reserve counters are incomplete".to_owned());
    }
    if snapshot.base_reserve_stroops.is_none() {
        limitations.push("base reserve evidence is unavailable".to_owned());
    }
    if matches!(
        engine_report.classification,
        Classification::UnverifiedForecast
    ) {
        limitations.push(
            "UNVERIFIED_FORECAST is not a successful transaction preflight and does not certify transaction execution"
                .to_owned(),
        );
    }
    if !engine_report.errors.is_empty() {
        limitations.push(
            "forecast errors prevent treating this result as a complete preflight".to_owned(),
        );
    }

    for pool in &engine_report.pool_redemptions {
        if pool.pool_will_be_deleted.is_none() {
            limitations.push(format!(
                "pool deletion is not forecast for pool {} because pool_shares_trust_line_count evidence is unavailable",
                pool.pool_id
            ));
        }
    }
    sort_unique(&mut limitations);

    ReportEvidence {
        network_passphrase: snapshot.network_passphrase.clone(),
        ledger_sequence: snapshot.ledger_sequence,
        entries_ledger_sequence: snapshot.entries_ledger_sequence,
        target_ledger_sequence: snapshot.discovery.target_ledger_sequence,
        source: source_to_report(&snapshot.discovery.source),
        manifest_sha256: snapshot.discovery.manifest_sha256.clone(),
        coverage: coverage_to_report(&snapshot.discovery.coverage),
        evidence_classification: evidence_classification_to_report(derived_classification),
        base_reserve_stroops: snapshot.base_reserve_stroops,
        protocol_version: snapshot.protocol_version,
        sponsorship_evidence_complete: snapshot.sponsorship_evidence_complete,
        limitations,
    }
}

fn source_to_report(source: &DiscoverySource) -> ReportSource {
    match source {
        DiscoverySource::SyntheticFixture => ReportSource::SyntheticFixture,
        DiscoverySource::LedgerCapture { endpoint } => ReportSource::LedgerCapture {
            endpoint: endpoint.clone(),
        },
        DiscoverySource::TwoTierDiscovery {
            horizon_endpoint,
            rpc_endpoint,
        } => ReportSource::TwoTierDiscovery {
            horizon_endpoint: horizon_endpoint.clone(),
            rpc_endpoint: rpc_endpoint.clone(),
        },
        DiscoverySource::AuthoritativeExport { export_id } => ReportSource::AuthoritativeExport {
            export_id: export_id.clone(),
        },
    }
}

fn coverage_to_report(coverage: &DiscoveryCoverage) -> ReportCoverage {
    match coverage {
        DiscoveryCoverage::Unproven => ReportCoverage::Unproven,
        DiscoveryCoverage::AuthoritativeReconciled {
            liquidity_pool_use_count,
            verified_pool_count,
        } => ReportCoverage::AuthoritativeReconciled {
            liquidity_pool_use_count: *liquidity_pool_use_count,
            verified_pool_count: *verified_pool_count,
        },
    }
}

fn evidence_classification_to_report(
    classification: EvidenceClassification,
) -> ReportEvidenceClassification {
    match classification {
        EvidenceClassification::UntrustedCandidate => {
            ReportEvidenceClassification::UntrustedCandidate
        }
        EvidenceClassification::BoundedCurrentTipRpc => {
            ReportEvidenceClassification::BoundedCurrentTipRpc
        }
        EvidenceClassification::LedgerConsistentIncomplete => {
            ReportEvidenceClassification::LedgerConsistentIncomplete
        }
        EvidenceClassification::CompleteAuthoritativeLedger => {
            ReportEvidenceClassification::CompleteAuthoritativeLedger
        }
        EvidenceClassification::InvalidOrContradictory => {
            ReportEvidenceClassification::InvalidOrContradictory
        }
    }
}

fn build_pool_redemption(
    pool: &PoolRedemptionForecast,
    warnings: &[String],
) -> ReportPoolRedemption {
    let mut claimable_balances = pool
        .claimable_balances
        .iter()
        .map(|claimable| ReportClaimableBalance {
            pool_id: claimable.pool_id.clone(),
            asset: claimable.asset.clone(),
            amount_stroops: claimable.amount_stroops,
            sponsor: claimable.sponsor.clone(),
            claimable_balance_id: claimable.claimable_balance_id.clone(),
            clawback_flag_enabled: claimable.clawback_flag_enabled,
        })
        .collect::<Vec<_>>();
    claimable_balances.sort_by(|left, right| {
        left.pool_id
            .cmp(&right.pool_id)
            .then_with(|| left.asset.cmp(&right.asset))
            .then_with(|| left.amount_stroops.cmp(&right.amount_stroops))
            .then_with(|| left.sponsor.cmp(&right.sponsor))
            .then_with(|| left.claimable_balance_id.cmp(&right.claimable_balance_id))
    });

    let limitation = if pool.pool_will_be_deleted.is_none() {
        warnings
            .iter()
            .find(|warning| warning.contains(&pool.pool_id))
            .cloned()
            .or_else(|| {
                Some("pool deletion is not forecast because the pool trustline count was not supplied".to_owned())
            })
    } else {
        None
    };

    ReportPoolRedemption {
        pool_id: pool.pool_id.clone(),
        owner: pool.owner.clone(),
        withdrawn_a_stroops: pool.withdrawn_a_stroops,
        withdrawn_b_stroops: pool.withdrawn_b_stroops,
        claimable_balances,
        pool_deletion: ReportPoolDeletion {
            forecast: pool.pool_will_be_deleted,
            limitation,
        },
    }
}

fn build_account_delta(
    delta: &AccountDelta,
    base_reserve_stroops: Option<u64>,
) -> Result<ReportAccountDelta, String> {
    let reserve_units_delta = delta
        .subentries
        .checked_add(delta.num_sponsoring)
        .and_then(|value| value.checked_sub(delta.num_sponsored))
        .ok_or_else(|| format!("reserve-unit arithmetic overflow for account {}", delta.id))?;
    let reserve_effect_stroops =
        base_reserve_stroops.map(|base| i128::from(reserve_units_delta) * i128::from(base));
    Ok(ReportAccountDelta {
        id: delta.id.clone(),
        balance_delta_stroops: delta.balance_stroops,
        subentries_delta: delta.subentries,
        num_sponsoring_delta: delta.num_sponsoring,
        num_sponsored_delta: delta.num_sponsored,
        reserve_units_delta,
        reserve_effect_stroops,
    })
}

fn report_classification(classification: Classification) -> Result<ReportClassification, String> {
    match classification {
        Classification::SupportedBlocked => Ok(ReportClassification::SupportedBlocked),
        Classification::UnverifiedForecast => Ok(ReportClassification::UnverifiedForecast),
        Classification::Inconclusive => Ok(ReportClassification::Inconclusive),
        Classification::Unsupported => Ok(ReportClassification::Unsupported),
        Classification::SupportedSafe => Err(
            "the engine produced SupportedSafe, but this CLI has no independently verified safe-evidence path"
                .to_owned(),
        ),
    }
}

fn report_transition(transition: Transition) -> ReportTransition {
    match transition {
        Transition::NoEffect => ReportTransition::NoEffect,
        Transition::MaintainLiabilitiesOnly => ReportTransition::MaintainLiabilitiesOnly,
        Transition::ForcedPoolRedemption => ReportTransition::ForcedPoolRedemption,
    }
}

fn transition_name(transition: Transition) -> &'static str {
    match transition {
        Transition::NoEffect => "NO_EFFECT",
        Transition::MaintainLiabilitiesOnly => "MAINTAIN_LIABILITIES_ONLY",
        Transition::ForcedPoolRedemption => "FORCED_POOL_REDEMPTION",
    }
}

fn warning_code(message: &str) -> &'static str {
    if message.contains("discovery coverage") {
        "W_UNPROVEN_COVERAGE"
    } else if message.contains("sponsorship") {
        "W_INCOMPLETE_SPONSORSHIP"
    } else if message.contains("claimable balance ID") {
        "W_OPERATION_CONTEXT"
    } else if message.contains("poolSharesTrustLineCount") {
        "W_POOL_DELETION_UNFORECAST"
    } else if message.contains("not independently verified") {
        "W_UNVERIFIED_DISCOVERY"
    } else {
        "W_ENGINE"
    }
}

fn error_code(message: &str) -> &'static str {
    if message.starts_with("unsupported") {
        "E_UNSUPPORTED"
    } else if message.contains("ledger sequence") || message.contains("LedgerSeq") {
        "E_LEDGER_SEQUENCE"
    } else if message.contains("missing") {
        "E_MISSING_EVIDENCE"
    } else if message.contains("pool") {
        "E_POOL_EVIDENCE"
    } else if message.contains("sponsor") {
        "E_SPONSORSHIP"
    } else {
        "E_ENGINE"
    }
}

fn sort_unique(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

/// Renders a report in plain English without presenting it as transaction
/// approval or authoritative ledger certification.
pub fn render_human(report: &ReportDocument) -> String {
    let mut out = String::new();
    out.push_str("RevokeTrace Forecast Report\n");
    out.push_str("============================\n");
    out.push_str(&format!("Mode: {}\n", report.mode.label()));
    out.push_str(&format!(
        "Requested authorization change: {}\n",
        report.operation.operation
    ));
    out.push_str(&format!(
        "Asset: {} issued by {}\n",
        report.operation.asset.code, report.operation.asset.issuer
    ));
    out.push_str(&format!("Trustor: {}\n", report.operation.trustor));
    out.push_str(&format!(
        "Flags: {} -> {}\n",
        report.operation.before_flags, report.operation.after_flags
    ));
    out.push_str(&format!(
        "Network: {}\nLedger evidence: ledger {} (entries {})\n",
        report.evidence.network_passphrase,
        report.evidence.ledger_sequence,
        report.evidence.entries_ledger_sequence
    ));
    out.push_str(&format!(
        "Evidence classification: {}\n",
        evidence_classification_label(report.evidence.evidence_classification)
    ));
    out.push_str(&format!(
        "Forecast classification: {}\n",
        classification_label(report.forecast.classification)
    ));
    out.push_str(&format!(
        "Transition: {}\n",
        transition_label(report.forecast.transition)
    ));
    if let Some(base_reserve) = report.evidence.base_reserve_stroops {
        out.push_str(&format!("Base reserve: {} stroops\n", base_reserve));
    } else {
        out.push_str("Base reserve: unavailable\n");
    }

    out.push_str(&format!(
        "\nAffected liquidity pools: {}\n",
        report.forecast.pool_redemptions.len()
    ));
    for pool in &report.forecast.pool_redemptions {
        out.push_str(&format!("- Pool {} (owner {})\n", pool.pool_id, pool.owner));
        out.push_str(&format!(
            "  Expected redemption: asset A {} stroops; asset B {} stroops\n",
            pool.withdrawn_a_stroops, pool.withdrawn_b_stroops
        ));
        match (pool.pool_deletion.forecast, &pool.pool_deletion.limitation) {
            (Some(true), _) => out.push_str("  Pool deletion forecast: yes\n"),
            (Some(false), _) => out.push_str("  Pool deletion forecast: no\n"),
            (None, Some(reason)) => out.push_str(&format!(
                "  Pool deletion forecast: unavailable ({})\n",
                reason
            )),
            (None, None) => out.push_str("  Pool deletion forecast: unavailable\n"),
        }
        out.push_str(&format!(
            "  Expected claimable balances: {}\n",
            pool.claimable_balances.len()
        ));
        for claimable in &pool.claimable_balances {
            out.push_str(&format!(
                "    - {}: {} stroops, sponsor {}, clawback {}, ID {}\n",
                claimable.asset,
                claimable.amount_stroops,
                claimable.sponsor,
                if claimable.clawback_flag_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                claimable
                    .claimable_balance_id
                    .as_deref()
                    .unwrap_or("not derived")
            ));
        }
    }

    out.push_str("\nReserve and sponsorship effects:\n");
    if report.forecast.account_deltas.is_empty() {
        out.push_str("- None forecast.\n");
    } else {
        for delta in &report.forecast.account_deltas {
            let reserve_effect = delta
                .reserve_effect_stroops
                .map(|value| format!("{} stroops", value))
                .unwrap_or_else(|| "unavailable".to_owned());
            out.push_str(&format!(
                "- {}: subentries {:+}, sponsoring {:+}, sponsored {:+}, reserve units {:+} (reserve effect {})\n",
                delta.id,
                delta.subentries_delta,
                delta.num_sponsoring_delta,
                delta.num_sponsored_delta,
                delta.reserve_units_delta,
                reserve_effect
            ));
        }
    }

    append_diagnostics(&mut out, "Warnings", &report.warnings);
    append_diagnostics(&mut out, "Errors", &report.errors);
    out.push_str("\nEvidence limitations:\n");
    if report.evidence.limitations.is_empty() {
        out.push_str("- None recorded.\n");
    } else {
        for limitation in &report.evidence.limitations {
            out.push_str(&format!("- {}\n", limitation));
        }
    }
    out
}

fn append_diagnostics(out: &mut String, title: &str, diagnostics: &[Diagnostic]) {
    out.push_str(&format!("\n{}:\n", title));
    if diagnostics.is_empty() {
        out.push_str("- None.\n");
    } else {
        for diagnostic in diagnostics {
            out.push_str(&format!("- [{}] {}\n", diagnostic.code, diagnostic.message));
        }
    }
}

fn evidence_classification_label(classification: ReportEvidenceClassification) -> &'static str {
    match classification {
        ReportEvidenceClassification::UntrustedCandidate => "UNTRUSTED_CANDIDATE",
        ReportEvidenceClassification::BoundedCurrentTipRpc => "BOUNDED_CURRENT_TIP_RPC",
        ReportEvidenceClassification::LedgerConsistentIncomplete => "LEDGER_CONSISTENT_INCOMPLETE",
        ReportEvidenceClassification::CompleteAuthoritativeLedger => {
            "COMPLETE_AUTHORITATIVE_LEDGER"
        }
        ReportEvidenceClassification::InvalidOrContradictory => "INVALID_OR_CONTRADICTORY",
    }
}

fn classification_label(classification: ReportClassification) -> &'static str {
    match classification {
        ReportClassification::SupportedBlocked => "SUPPORTED_BLOCKED (blocked by modeled rules)",
        ReportClassification::UnverifiedForecast => {
            "UNVERIFIED_FORECAST (not a successful transaction preflight)"
        }
        ReportClassification::Inconclusive => {
            "INCONCLUSIVE (required evidence is missing or contradictory)"
        }
        ReportClassification::Unsupported => "UNSUPPORTED (outside the supported operation scope)",
    }
}

fn transition_label(transition: ReportTransition) -> &'static str {
    match transition {
        ReportTransition::NoEffect => "no effect",
        ReportTransition::MaintainLiabilitiesOnly => "maintain liabilities only",
        ReportTransition::ForcedPoolRedemption => "forced pool redemption",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_classification_never_serializes_supported_safe() {
        assert!(report_classification(Classification::SupportedSafe).is_err());
    }

    #[test]
    fn report_diagnostic_sorting_is_stable() {
        let mut values = vec!["z".to_owned(), "a".to_owned(), "a".to_owned()];
        sort_unique(&mut values);
        assert_eq!(values, vec!["a", "z"]);
    }
}
