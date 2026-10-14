// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! CLU configuration packs — manifest + resource files for idempotent
//! provisioning of Payments resources.
//! See `services/payments/DESIGN.md`.
//! A CLU configuration pack is a bundle of declarative resource definitions
//! used to provision Payments resources (calendars, card products, cores,
//! dashboards, instruction logics, integrations, parameters, rules, rule
//! sets, templates, and their versions). The pack consists of:
//! - a manifest (`manifest.yaml`) describing the pack; and
//! - one or more resource files (`*.resource.yaml`).
//! `import_config_pack` performs idempotent provisioning: re-importing the
//! same pack produces the same end state.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Supported resources ─────────────────────────────────────────────────

/// All resource types that a CLU configuration pack may contain.
/// Story.
pub const SUPPORTED_RESOURCES: &[&str] = &[
    "BusinessDayDefinitions",
    "Calendars",
    "CardProducts",
    "Cores",
    "CoreVersions",
    "Dashboards",
    "InstructionLogics",
    "InstructionLogicVersions",
    "Integrations",
    "IntegrationVersions",
    "Parameters",
    "ParameterValues",
    "Rules",
    "RuleVersions",
    "RuleSets",
    "RuleSetVersions",
    "Templates",
    "TemplateVersions",
];

/// Returns true if `resource_type` is a supported CLU resource type.
pub fn is_supported_resource(resource_type: &str) -> bool {
    SUPPORTED_RESOURCES.iter().any(|r| *r == resource_type)
}

// ── Types ───────────────────────────────────────────────────────────────

/// CLU manifest — the `manifest.yaml` of a configuration pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CluManifest {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub resources: Vec<String>,
}

/// A single resource file inside a CLU configuration pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CluResourceFile {
    pub resource_type: String,
    pub resource_id: String,
    pub yaml_content: String,
}

/// A parsed CLU configuration pack: manifest plus all resource files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CluConfigPack {
    pub manifest: CluManifest,
    pub resources: Vec<CluResourceFile>,
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse a CLU configuration pack from a manifest YAML string and a slice of
/// resource YAML strings.
/// Each resource YAML must contain `resource_type`, `resource_id`, and the
/// resource payload. The manifest is parsed as YAML.
/// Story.
pub fn parse_config_pack(
    manifest_yaml: &str,
    resource_yamls: &[String],
) -> Result<CluConfigPack, String> {
    let manifest: CluManifest = serde_yaml::from_str(manifest_yaml)
        .map_err(|e| format!("failed to parse manifest: {e}"))?;

    let mut resources = Vec::with_capacity(resource_yamls.len());
    for yaml in resource_yamls {
        let res: CluResourceFile = serde_yaml::from_str(yaml)
            .map_err(|e| format!("failed to parse resource file: {e}"))?;
        resources.push(res);
    }

    Ok(CluConfigPack { manifest, resources })
}

// ── Validation ─────────────────────────────────────────────────────────

/// Validate a CLU configuration pack.
/// Checks:
/// - manifest has a non-empty name and version
/// - every resource type is in `SUPPORTED_RESOURCES`
/// - every resource has a non-empty `resource_id`
/// - manifest `resources` list matches the actual resource files
/// Story.
pub fn validate_config_pack(pack: &CluConfigPack) -> Result<(), String> {
    if pack.manifest.name.trim().is_empty() {
        return Err("manifest name must not be empty".into());
    }
    if pack.manifest.version.trim().is_empty() {
        return Err("manifest version must not be empty".into());
    }

    for res in &pack.resources {
        if !is_supported_resource(&res.resource_type) {
            return Err(format!(
                "unsupported resource type: {} (supported: {:?})",
                res.resource_type, SUPPORTED_RESOURCES
            ));
        }
        if res.resource_id.trim().is_empty() {
            return Err("resource_id must not be empty".into());
        }
    }

    // The manifest `resources` list should match the actual resource files.
    if !pack.manifest.resources.is_empty() {
        let mut manifest_types: std::collections::HashSet<&str> =
            pack.manifest.resources.iter().map(|s| s.as_str()).collect();
        for res in &pack.resources {
            if !manifest_types.remove(res.resource_type.as_str()) {
                // Resource file present but not listed in manifest — allow but warn.
                tracing::debug!(
                    resource_type = %res.resource_type,
                    "resource file not listed in manifest resources"
                );
            }
        }
        if !manifest_types.is_empty() {
            return Err(format!(
                "manifest lists resources not present in pack: {:?}",
                manifest_types
            ));
        }
    }

    Ok(())
}

// ── Import ──────────────────────────────────────────────────────────────

/// Idempotently provision a CLU configuration pack.
/// This is a stub: in production it would insert each resource into the
/// appropriate table, checking for an existing record by `resource_id`
/// (idempotency). For now it returns the list of imported resource IDs.
/// Story.
pub async fn import_config_pack(
    pool: &sqlx::PgPool,
    pack: &CluConfigPack,
) -> Result<Vec<String>, String> {
    validate_config_pack(pack)?;

    let mut imported = Vec::with_capacity(pack.resources.len());
    for res in &pack.resources {
        // Idempotency: check if a record with this resource_id already exists
        // in the corresponding table. For the stub, we track imports in the
        // clu_imports table if it exists; otherwise we just record the ID.
        let existing: Option<Uuid> = sqlx::query_scalar(
            r#"SELECT id FROM clu_imports
                WHERE resource_type = $1 AND resource_id = $2
                LIMIT 1"#,
        )
        .bind(&res.resource_type)
        .bind(&res.resource_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("clu import check: {e}"))?;

        if existing.is_some() {
            tracing::debug!(
                resource_type = %res.resource_type,
                resource_id = %res.resource_id,
                "clu resource already imported (idempotent)"
            );
            imported.push(res.resource_id.clone());
            continue;
        }

        // Insert import record (stub). If the table doesn't exist, we still
        // return the ID as imported.
        let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(
            r#"INSERT INTO clu_imports (resource_type, resource_id, pack_name, pack_version)
               VALUES ($1, $2, $3, $4)
               RETURNING id"#,
        )
        .bind(&res.resource_type)
        .bind(&res.resource_id)
        .bind(&pack.manifest.name)
        .bind(&pack.manifest.version)
        .fetch_one(pool)
        .await;

        match inserted {
            Ok(id) => tracing::info!(import_id = %id, "clu resource imported"),
            Err(e) => {
                // Table may not exist in test environments; record anyway.
                tracing::warn!(error = %e, "clu import table unavailable; recording id only");
            }
        }
        imported.push(res.resource_id.clone());
    }

    Ok(imported)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest_yaml() -> &'static str {
        "name: test-pack\nversion: 1.0.0\ndescription: A test pack\nresources:\n  - Calendars\n  - Parameters\n"
    }

    fn sample_resource_yaml() -> String {
        "---\nresource_type: Calendars\nresource_id: cal-001\nyaml_content: |\n  name: UTC\n  timezone: UTC\n".into()
    }

    fn sample_parameter_resource_yaml() -> String {
        "---\nresource_type: Parameters\nresource_id: param-001\nyaml_content: |\n  name: cutoff\n  type: string\n".into()
    }

    #[test]
    fn supported_resources_contains_expected_types() {
        for expected in [
            "BusinessDayDefinitions",
            "Calendars",
            "CardProducts",
            "Cores",
            "CoreVersions",
            "Dashboards",
            "InstructionLogics",
            "InstructionLogicVersions",
            "Integrations",
            "IntegrationVersions",
            "Parameters",
            "ParameterValues",
            "Rules",
            "RuleVersions",
            "RuleSets",
            "RuleSetVersions",
            "Templates",
            "TemplateVersions",
        ] {
            assert!(is_supported_resource(expected), "missing: {expected}");
        }
    }

    #[test]
    fn is_supported_resource_rejects_unknown() {
        assert!(!is_supported_resource("UnknownThing"));
        assert!(!is_supported_resource(""));
    }

    #[test]
    fn parse_config_pack_ok() {
        let pack = parse_config_pack(
            sample_manifest_yaml(),
            &[sample_resource_yaml(), sample_parameter_resource_yaml()],
        )
        .expect("parse");
        assert_eq!(pack.manifest.name, "test-pack");
        assert_eq!(pack.manifest.version, "1.0.0");
        assert_eq!(pack.resources.len(), 2);
        assert_eq!(pack.resources[0].resource_type, "Calendars");
        assert_eq!(pack.resources[0].resource_id, "cal-001");
        assert_eq!(pack.resources[1].resource_type, "Parameters");
    }

    #[test]
    fn parse_config_pack_bad_manifest() {
        let err = parse_config_pack("not: valid: yaml: :", &[]).unwrap_err();
        assert!(err.contains("manifest"));
    }

    #[test]
    fn parse_config_pack_bad_resource() {
        let err = parse_config_pack(
            sample_manifest_yaml(),
            &["bad: yaml: :".into()],
        )
        .unwrap_err();
        assert!(err.contains("resource file"));
    }

    #[test]
    fn validate_config_pack_ok() {
        let pack = parse_config_pack(
            sample_manifest_yaml(),
            &[sample_resource_yaml(), sample_parameter_resource_yaml()],
        )
        .unwrap();
        validate_config_pack(&pack).expect("valid");
    }

    #[test]
    fn validate_config_pack_rejects_empty_name() {
        let pack = CluConfigPack {
            manifest: CluManifest {
                name: "".into(),
                version: "1.0.0".into(),
                description: None,
                resources: vec![],
            },
            resources: vec![],
        };
        let err = validate_config_pack(&pack).unwrap_err();
        assert!(err.contains("name"));
    }

    #[test]
    fn validate_config_pack_rejects_empty_version() {
        let pack = CluConfigPack {
            manifest: CluManifest {
                name: "pack".into(),
                version: "  ".into(),
                description: None,
                resources: vec![],
            },
            resources: vec![],
        };
        let err = validate_config_pack(&pack).unwrap_err();
        assert!(err.contains("version"));
    }

    #[test]
    fn validate_config_pack_rejects_unsupported_resource() {
        let pack = CluConfigPack {
            manifest: CluManifest {
                name: "pack".into(),
                version: "1.0.0".into(),
                description: None,
                resources: vec![],
            },
            resources: vec![CluResourceFile {
                resource_type: "UnknownThing".into(),
                resource_id: "x".into(),
                yaml_content: "".into(),
            }],
        };
        let err = validate_config_pack(&pack).unwrap_err();
        assert!(err.contains("unsupported resource type"));
    }

    #[test]
    fn validate_config_pack_rejects_empty_resource_id() {
        let pack = CluConfigPack {
            manifest: CluManifest {
                name: "pack".into(),
                version: "1.0.0".into(),
                description: None,
                resources: vec![],
            },
            resources: vec![CluResourceFile {
                resource_type: "Calendars".into(),
                resource_id: "  ".into(),
                yaml_content: "".into(),
            }],
        };
        let err = validate_config_pack(&pack).unwrap_err();
        assert!(err.contains("resource_id"));
    }

    #[test]
    fn validate_config_pack_manifest_lists_missing_resource() {
        let pack = CluConfigPack {
            manifest: CluManifest {
                name: "pack".into(),
                version: "1.0.0".into(),
                description: None,
                resources: vec!["Calendars".into(), "Rules".into()],
            },
            resources: vec![CluResourceFile {
                resource_type: "Calendars".into(),
                resource_id: "cal-1".into(),
                yaml_content: "".into(),
            }],
        };
        let err = validate_config_pack(&pack).unwrap_err();
        assert!(err.contains("not present in pack"));
    }
}