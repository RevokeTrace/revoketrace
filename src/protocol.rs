//! Stellar protocol support policy.
//!
//! This is the single place that decides which ledger protocol versions the
//! forecasting engine will evaluate. Every path (offline snapshots, live
//! ledger headers, stored capture validation) must use it.
//!
//! The range is a review boundary, not a statement that every version inside
//! it was observed on a live network. The evidence behind each bound is
//! recorded in `research/protocol-support-decision.md`.

/// First protocol version with CAP-0038 liquidity-pool revocation behavior.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 18;

/// Highest protocol version covered by the recorded source review.
///
/// Protocol 30 is excluded because the pinned `stellar-xdr` 28.0.1 decoder
/// cannot parse the millisecond `StellarValue` arms that Stellar Core starts
/// using at protocol 30, so a protocol 30 ledger header cannot be validated.
pub const MAX_REVIEWED_PROTOCOL_VERSION: u32 = 29;

/// Returns true when the version is inside the reviewed range.
pub const fn is_reviewed_protocol_version(version: u32) -> bool {
    version >= MIN_SUPPORTED_PROTOCOL_VERSION && version <= MAX_REVIEWED_PROTOCOL_VERSION
}

/// Human-readable refusal for a version outside the reviewed range.
pub fn unsupported_protocol_message(version: u32) -> String {
    format!(
        "unsupported protocol version: {} is outside the reviewed range {} to {}",
        version, MIN_SUPPORTED_PROTOCOL_VERSION, MAX_REVIEWED_PROTOCOL_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_the_reviewed_range() {
        assert!(!is_reviewed_protocol_version(0));
        assert!(!is_reviewed_protocol_version(17));
        assert!(is_reviewed_protocol_version(18));
        assert!(is_reviewed_protocol_version(28));
        assert!(is_reviewed_protocol_version(29));
        assert!(!is_reviewed_protocol_version(30));
        assert!(!is_reviewed_protocol_version(u32::MAX));
    }

    #[test]
    fn refusal_message_names_version_and_range() {
        let message = unsupported_protocol_message(30);
        assert!(message.starts_with("unsupported protocol version"));
        assert!(message.contains("30"));
        assert!(message.contains("18 to 29"));
    }
}
