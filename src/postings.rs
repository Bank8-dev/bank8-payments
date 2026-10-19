// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Posting types for Bank8:Ledger submissions (design §4.6).
//! The `Sentin8CorePostingsStep` builds posting instructions from one of the
//! eight posting-type templates and submits the batch to Bank8:Ledger's
//! `POST /v1/postings`. Each posting type maps to the debit/credit side and
//! the ledger phase semantics the design §4.6 table describes:
//! | Posting type | Ledger impact |
//! | Transfer | Debit source, credit destination |
//! | InboundHardSettlement | Credit beneficiary account |
//! | OutboundHardSettlement | Debit debtor account |
//! | InboundAuthorisation | Hold funds on beneficiary side |
//! | OutboundAuthorisation | Hold funds on debtor side |
//! | AuthorisationAdjustment | Modify held amount |
//! | Release | Reverse authorisation postings |
//! | Settlement | Debit held funds, credit final |
//! The TIPS/SEPA/B8 flow modules (`tips_flows`, `sepa_flows`, `b8_flows`)
//! construct these types when building their posting steps.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The eight posting types (design §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostingType {
    Transfer,
    InboundHardSettlement,
    OutboundHardSettlement,
    InboundAuthorisation,
    OutboundAuthorisation,
    AuthorisationAdjustment,
    Release,
    Settlement,
}

impl PostingType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "Transfer" | "transfer" => Ok(Self::Transfer),
            "InboundHardSettlement" | "inbound_hard_settlement" => Ok(Self::InboundHardSettlement),
            "OutboundHardSettlement" | "outbound_hard_settlement" => {
                Ok(Self::OutboundHardSettlement)
            }
            "InboundAuthorisation" | "inbound_authorisation" => Ok(Self::InboundAuthorisation),
            "OutboundAuthorisation" | "outbound_authorisation" => Ok(Self::OutboundAuthorisation),
            "AuthorisationAdjustment" | "authorisation_adjustment" => {
                Ok(Self::AuthorisationAdjustment)
            }
            "Release" | "release" => Ok(Self::Release),
            "Settlement" | "settlement" => Ok(Self::Settlement),
            other => Err(format!("unknown posting type: {other}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::InboundHardSettlement => "inbound_hard_settlement",
            Self::OutboundHardSettlement => "outbound_hard_settlement",
            Self::InboundAuthorisation => "inbound_authorisation",
            Self::OutboundAuthorisation => "outbound_authorisation",
            Self::AuthorisationAdjustment => "authorisation_adjustment",
            Self::Release => "release",
            Self::Settlement => "settlement",
        }
    }

    /// Whether this posting type is a funds reservation (pending phase) or a
    /// final movement (committed phase). Authorisation postings hold funds;
    /// everything else moves them.
    pub fn is_pending_phase(self) -> bool {
        matches!(
            self,
            Self::InboundAuthorisation
                | Self::OutboundAuthorisation
                | Self::AuthorisationAdjustment
        )
    }

    /// Whether the posting releases previously-held funds (a negative
    /// reservation).
    pub fn is_release(self) -> bool {
        matches!(self, Self::Release)
    }

    /// Whether this posting type reverses a previous movement.
    pub fn is_reversal(self) -> bool {
        matches!(self, Self::Release)
    }
}

/// A single posting instruction built for Bank8:Ledger.
/// `debit_account` / `credit_account` are Bank8:Ledger account UUIDs (the
/// `core_account_id` resolved via the routing workflow); `direction` is
/// derived from the posting type by [`build_instruction`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostingInstruction {
    pub instruction_type: String,
    pub debit_account: Uuid,
    pub credit_account: Uuid,
    /// Amount as a decimal string - never rounded through a float (design §8.4).
    pub amount: String,
    #[serde(default = "default_denom")]
    pub denomination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

fn default_denom() -> String {
    "CAD".into()
}

/// Build a ledger posting instruction for the given posting type.
/// * `source` - the account the value comes from (debtor / payer side).
/// * `destination` - the account the value goes to (creditor / payee side).
/// * For authorisation holds the "debit" side is the ledger's PENDING_OUT
///
/// bucket, which the ledger models via the instruction type.
pub fn build_instruction(
    posting_type: PostingType,
    source: Uuid,
    destination: Uuid,
    amount: &str,
    denomination: &str,
    description: Option<&str>,
) -> PostingInstruction {
    // Validate the amount parses as a decimal - never round through f64.
    let _ = amount
        .parse::<rust_decimal::Decimal>()
        .expect("posting amount must be a decimal string");
    PostingInstruction {
        instruction_type: posting_type.as_str().to_string(),
        debit_account: source,
        credit_account: destination,
        amount: amount.to_string(),
        denomination: denomination.to_string(),
        value_timestamp: Some(chrono::Utc::now()),
        description: description.map(str::to_string),
    }
}

/// Batch id for the ledger posting call - deterministic, derived from the
/// instruction id so retries dedupe on the ledger side.
pub fn batch_id_for(instruction_id: Uuid, posting_type: PostingType) -> String {
    format!("payments-{instruction_id}-{}", posting_type.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posting_type_round_trip() {
        for p in [
            PostingType::Transfer,
            PostingType::InboundHardSettlement,
            PostingType::OutboundHardSettlement,
            PostingType::InboundAuthorisation,
            PostingType::OutboundAuthorisation,
            PostingType::AuthorisationAdjustment,
            PostingType::Release,
            PostingType::Settlement,
        ] {
            assert_eq!(PostingType::from_str(p.as_str()).unwrap(), p);
        }
        assert!(PostingType::from_str("bogus").is_err());
    }

    #[test]
    fn authorisation_types_are_pending_phase() {
        assert!(PostingType::InboundAuthorisation.is_pending_phase());
        assert!(PostingType::OutboundAuthorisation.is_pending_phase());
        assert!(PostingType::AuthorisationAdjustment.is_pending_phase());
        assert!(!PostingType::Transfer.is_pending_phase());
        assert!(!PostingType::Settlement.is_pending_phase());
        assert!(!PostingType::InboundHardSettlement.is_pending_phase());
        assert!(!PostingType::OutboundHardSettlement.is_pending_phase());
        assert!(!PostingType::Release.is_pending_phase());
    }

    #[test]
    fn release_is_reversal() {
        assert!(PostingType::Release.is_release());
        assert!(PostingType::Release.is_reversal());
        assert!(!PostingType::Settlement.is_release());
        assert!(!PostingType::Transfer.is_reversal());
    }

    #[test]
    fn build_instruction_maps_sides() {
        let src = Uuid::new_v4();
        let dst = Uuid::new_v4();
        let instr = build_instruction(
            PostingType::Transfer,
            src,
            dst,
            "100.50",
            "CAD",
            Some("test transfer"),
        );
        assert_eq!(instr.instruction_type, "transfer");
        assert_eq!(instr.debit_account, src);
        assert_eq!(instr.credit_account, dst);
        assert_eq!(instr.amount, "100.50");
        assert_eq!(instr.denomination, "CAD");
        assert_eq!(instr.description.as_deref(), Some("test transfer"));
    }

    #[test]
    fn batch_id_is_deterministic() {
        let id = Uuid::new_v4();
        let b1 = batch_id_for(id, PostingType::Settlement);
        let b2 = batch_id_for(id, PostingType::Settlement);
        assert_eq!(b1, b2);
        assert_ne!(b1, batch_id_for(id, PostingType::Transfer));
        assert!(b1.starts_with(&format!("payments-{id}-")));
    }
}
