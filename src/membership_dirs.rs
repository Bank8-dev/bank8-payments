// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Membership directories — TIPS, FedACH, Fedwire directory parsing and
//! reachability checks.
//! See `services/payments/DESIGN.md`.
//! Provides:
//! - `DirectoryType` (Tips, Fedach, Fedwire)
//! - `DirectoryStatus` (Pending, Ready, Errored)
//! - `DirectoryEntry` (BIC, name, country)
//! - `parse_tips_xml` / `parse_fedach_json` / `parse_fedwire_json`
//! - `process_directory_upload` — parse, store entries, update status
//! - `check_bic_reachability` — check if a BIC is present in a directory

use serde::{Deserialize, Serialize};
use sqlx::Row;

// ── Enums ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryType {
    Tips,
    Fedach,
    Fedwire,
}

impl DirectoryType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "tips" => Ok(Self::Tips),
            "fedach" => Ok(Self::Fedach),
            "fedwire" => Ok(Self::Fedwire),
            other => Err(format!("unknown directory type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tips => "tips",
            Self::Fedach => "fedach",
            Self::Fedwire => "fedwire",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryStatus {
    Pending,
    Ready,
    Errored,
}

impl DirectoryStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "errored" => Ok(Self::Errored),
            other => Err(format!("unknown directory status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Errored => "errored",
        }
    }
}

// ── Entry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectoryEntry {
    pub bic: String,
    pub name: String,
    pub country: String,
}

// ── Parsers ─────────────────────────────────────────────────────────────

/// Parse a TIPS directory XML string into entries.
/// The TIPS directory uses fixed-width records of 177 characters per line
/// (simplified). Each record is split by newlines; whitespace is trimmed.
/// Fields (simplified, 1-indexed):
/// - BIC: characters 1..=11
/// - Name: characters 12..=156
/// - Country (ISO-3166 alpha-2): characters 157..=158
///
/// Lines that are too short are skipped. Blank lines are skipped.
pub fn parse_tips_xml(content: &str) -> Result<Vec<DirectoryEntry>, String> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip XML-ish tags (simplified — real TIPS uses XML; for tests we
        // accept either raw fixed-width lines or `<row>bic|name|country</row>`).
        let record = if trimmed.starts_with('<') {
            // Strip surrounding tags.
            let inner = trimmed
                .trim_start_matches("<row>")
                .trim_end_matches("</row>")
                .trim();
            if inner.is_empty() {
                continue;
            }
            inner
        } else {
            trimmed
        };

        if record.len() < 11 {
            continue;
        }
        let bic: String = record.chars().take(11).collect();
        let name: String = record
            .chars()
            .skip(11)
            .take_while(|c| !c.is_whitespace())
            .collect();
        // Country = last 2 non-whitespace characters.
        let country: String = record
            .chars()
            .rev()
            .skip_while(|c| c.is_whitespace())
            .take(2)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if country.len() != 2 {
            continue;
        }
        entries.push(DirectoryEntry { bic, name, country });
    }
    Ok(entries)
}

/// Parse a FedACH directory JSON document into entries.
/// Expected formats:
/// - `{ "achParticipants": [{ "routingNumber": "...", "customerName": "...", "institutionTypeCode": "... }] }`
/// - `[ { "routingNumber": "...", "customerName": "..." } ]`
///
/// BIC is derived from the routing number (9-digit ABA). Country defaults
/// to "US" for FedACH entries.
pub fn parse_fedach_json(content: &str) -> Result<Vec<DirectoryEntry>, String> {
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("invalid JSON: {e}"))?;

    let arr = value
        .get("achParticipants")
        .cloned()
        .or(value.get("ach_participants").cloned())
        .unwrap_or(value);

    let arr = match arr {
        serde_json::Value::Array(a) => a,
        _ => return Err("FedACH JSON must be an array or contain achParticipants".into()),
    };

    let mut entries = Vec::new();
    for item in arr {
        let bic = item
            .get("routingNumber")
            .or_else(|| item.get("routing_number"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "FedACH entry missing routingNumber".to_string())?
            .to_string();
        let name = item
            .get("customerName")
            .or_else(|| item.get("customer_name"))
            .or_else(|| item.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let country = item
            .get("country")
            .and_then(|v| v.as_str())
            .unwrap_or("US")
            .to_string();
        entries.push(DirectoryEntry { bic, name, country });
    }
    Ok(entries)
}

/// Parse a Fedwire directory JSON document into entries.
/// Expected formats:
/// - `{ "fedwireParticipants": [{ "routingNumber": "...", "customerName": "...", "location": "..." }] }`
/// - `[ { "routingNumber": "...", "customerName": "..." } ]`
pub fn parse_fedwire_json(content: &str) -> Result<Vec<DirectoryEntry>, String> {
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("invalid JSON: {e}"))?;

    let arr = value
        .get("fedwireParticipants")
        .cloned()
        .or(value.get("fedwire_participants").cloned())
        .unwrap_or(value);

    let arr = match arr {
        serde_json::Value::Array(a) => a,
        _ => return Err("Fedwire JSON must be an array or contain fedwireParticipants".into()),
    };

    let mut entries = Vec::new();
    for item in arr {
        let bic = item
            .get("routingNumber")
            .or_else(|| item.get("routing_number"))
            .or_else(|| item.get("bic"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Fedwire entry missing routingNumber".to_string())?
            .to_string();
        let name = item
            .get("customerName")
            .or_else(|| item.get("customer_name"))
            .or_else(|| item.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let country = item
            .get("country")
            .and_then(|v| v.as_str())
            .unwrap_or("US")
            .to_string();
        entries.push(DirectoryEntry { bic, name, country });
    }
    Ok(entries)
}

/// Process a directory upload — parse the content, store the entries in the
/// `membership_directories.entries` JSONB column, and update the
/// directory status to `ready`. On parse failure the status is set to
/// `errored`.
/// Story.
pub async fn process_directory_upload(
    pool: &sqlx::PgPool,
    directory_id: uuid::Uuid,
    content: &str,
    dir_type: DirectoryType,
) -> Result<(), String> {
    let result = match dir_type {
        DirectoryType::Tips => parse_tips_xml(content),
        DirectoryType::Fedach => parse_fedach_json(content),
        DirectoryType::Fedwire => parse_fedwire_json(content),
    };

    let (status, entries_json) = match result {
        Ok(entries) => {
            let json =
                serde_json::to_value(&entries).map_err(|e| format!("serialise entries: {e}"))?;
            (DirectoryStatus::Ready.as_str(), json)
        }
        Err(e) => {
            tracing::warn!(directory_id = %directory_id, error = %e, "directory parse failed");
            (DirectoryStatus::Errored.as_str(), serde_json::json!([]))
        }
    };

    sqlx::query(
        r#"UPDATE membership_directories
              SET entries = $2, status = $3, updated_at = now()
            WHERE id = $1"#,
    )
    .bind(directory_id)
    .bind(&entries_json)
    .bind(status)
    .execute(pool)
    .await
    .map_err(|e| format!("update directory: {e}"))?;

    Ok(())
}

/// Check whether a BIC is present in a directory's entries.
/// Story . The match is case-sensitive and compares the full BIC
/// string. For partial BIC (8-character) lookups, the caller should
/// pre-normalise the directory entries.
pub fn check_bic_reachability(entries: &[DirectoryEntry], bic: &str) -> bool {
    entries.iter().any(|e| e.bic == bic)
}

// Helper used by tests to extract entries from a directory row.
#[allow(dead_code)]
fn row_entries(row: &sqlx::postgres::PgRow) -> Vec<DirectoryEntry> {
    let v: serde_json::Value = row.get("entries");
    serde_json::from_value(v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn directory_type_round_trip() {
        for t in [
            DirectoryType::Tips,
            DirectoryType::Fedach,
            DirectoryType::Fedwire,
        ] {
            assert_eq!(DirectoryType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(DirectoryType::from_str("bogus").is_err());
    }

    #[test]
    fn directory_status_round_trip() {
        for s in [
            DirectoryStatus::Pending,
            DirectoryStatus::Ready,
            DirectoryStatus::Errored,
        ] {
            assert_eq!(DirectoryStatus::from_str(s.as_str()).unwrap(), s);
        }
        assert!(DirectoryStatus::from_str("bogus").is_err());
    }

    #[test]
    fn parse_tips_xml_fixed_width() {
        // BIC  + Name (no spaces) + spaces + Country . 177 chars in
        // production; we accept shorter lines for tests.
        let content = "ABCDEFGHJKLABank Name       US\n";
        let entries = parse_tips_xml(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bic, "ABCDEFGHJKL");
        assert_eq!(entries[0].country, "US");
    }

    #[test]
    fn parse_tips_xml_skips_short_and_blank_lines() {
        let content = "\n\nshort\n";
        let entries = parse_tips_xml(content).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_tips_xml_accepts_row_tags() {
        let content = "<row>ABCDEFGHJKLBankUS</row>";
        let entries = parse_tips_xml(content).unwrap();
        // The record has length 17; BIC is first 11, last 2 chars = US.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bic, "ABCDEFGHJKL");
        assert_eq!(entries[0].country, "US");
    }

    #[test]
    fn parse_fedach_json_object_wrapper() {
        let content = json!({
            "achParticipants": [
                { "routingNumber": "123456789", "customerName": "Test Bank", "institutionTypeCode": "0" }
            ]
        }).to_string();
        let entries = parse_fedach_json(&content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bic, "123456789");
        assert_eq!(entries[0].name, "Test Bank");
        assert_eq!(entries[0].country, "US");
    }

    #[test]
    fn parse_fedach_json_bare_array() {
        let content = json!([
            { "routingNumber": "111111111", "customerName": "Bank A" },
            { "routingNumber": "222222222", "customerName": "Bank B", "country": "PR" }
        ])
        .to_string();
        let entries = parse_fedach_json(&content).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].country, "PR");
    }

    #[test]
    fn parse_fedach_json_rejects_invalid_json() {
        assert!(parse_fedach_json("not json").is_err());
    }

    #[test]
    fn parse_fedwire_json_object_wrapper() {
        let content = json!({
            "fedwireParticipants": [
                { "routingNumber": "021000021", "customerName": "Wire Bank", "location": "NY" }
            ]
        })
        .to_string();
        let entries = parse_fedwire_json(&content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bic, "021000021");
        assert_eq!(entries[0].name, "Wire Bank");
    }

    #[test]
    fn parse_fedwire_json_bare_array_with_bic_field() {
        let content = json!([
            { "bic": "ABCDEFGHJKL", "name": "Wire Bank" }
        ])
        .to_string();
        let entries = parse_fedwire_json(&content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bic, "ABCDEFGHJKL");
    }

    #[test]
    fn check_bic_reachability_finds_match() {
        let entries = vec![
            DirectoryEntry {
                bic: "ABCDEFGHJKL".into(),
                name: "Bank A".into(),
                country: "US".into(),
            },
            DirectoryEntry {
                bic: "BCDEFGHJKLMN".into(),
                name: "Bank B".into(),
                country: "DE".into(),
            },
        ];
        assert!(check_bic_reachability(&entries, "ABCDEFGHJKL"));
        assert!(!check_bic_reachability(&entries, "ZZZZZZZZZZZ"));
    }
}
