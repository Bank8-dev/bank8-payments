// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Payments host functions map (Story ).
//! `payments_host_functions ` returns the map of host-function names to
//! path templates that Payments passes in the Flow/Func execute request's
//! `callbackConfig.host_functions`. Func resolves the templates
//! dynamically when a WASM module invokes a host function — there is no
//! pre-registration in Func.
//! The path templates use `{args.0}` placeholders that Func substitutes
//! with the first argument passed by the WASM module. For example,
//! `payments_get_instruction` → `/v1/internal/instructions/{args.0}`.
//! The corresponding internal endpoints live in `handlers.rs` (Story )
//! and are registered in `server.rs`.

use std::collections::HashMap;

/// The host-functions map Payments passes to Flow/Func.
/// Keys are the host-function names callable from a WASM module; values are
/// path templates resolved against Payments's internal API. Placeholders use
/// the `{args.N}` form where `N` is the zero-based positional argument index.
pub fn payments_host_functions() -> HashMap<String, String> {
    let mut m: HashMap<String, String> = HashMap::with_capacity(13);
    m.insert(
        "payments_get_instruction".into(),
        "/v1/internal/instructions/{args.0}".into(),
    );
    m.insert(
        "payments_update_instruction".into(),
        "/v1/internal/instructions/{args.0}".into(),
    );
    m.insert(
        "payments_get_payment".into(),
        "/v1/internal/payments/{args.0}".into(),
    );
    m.insert(
        "payments_get_payment_instrument".into(),
        "/v1/internal/payment-instruments/{args.0}".into(),
    );
    m.insert(
        "payments_get_account_link".into(),
        "/v1/internal/account-links/{args.0}".into(),
    );
    m.insert(
        "payments_get_parameter".into(),
        "/v1/internal/parameters/{args.0}".into(),
    );
    m.insert(
        "payments_get_rule".into(),
        "/v1/internal/rules/{args.0}".into(),
    );
    m.insert(
        "payments_get_integration".into(),
        "/v1/internal/integrations/{args.0}".into(),
    );
    m.insert(
        "payments_get_mandate".into(),
        "/v1/internal/mandates/{args.0}".into(),
    );
    m.insert(
        "payments_get_manual_decision".into(),
        "/v1/internal/manual-decisions/{args.0}".into(),
    );
    m.insert(
        "payments_get_calendar".into(),
        "/v1/internal/calendars/{args.0}".into(),
    );
    m.insert(
        "payments_get_card".into(),
        "/v1/internal/cards/{args.0}".into(),
    );
    m.insert(
        "payments_get_cardholder".into(),
        "/v1/internal/cardholders/{args.0}".into(),
    );
    m
}

/// Substitute the `{args.N}` placeholders in a path template with the given
/// positional arguments. Returns `None` if a required argument is missing.
/// This helper is used by the Func client when it needs to resolve a host
/// function call back to a concrete Payments internal URL. The Payments server
/// itself does not need to resolve templates — it owns the endpoints.
pub fn resolve_host_function_path(template: &str, args: &[&str]) -> Option<String> {
    let mut out = template.to_string();
    for (i, arg) in args.iter().enumerate() {
        let placeholder = format!("{{args.{i}}}");
        if !out.contains(&placeholder) {
            continue;
        }
        out = out.replace(&placeholder, arg);
    }
    // If any placeholder remains unresolved, return None.
    if out.contains("{args.") {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_functions_contains_all_expected_entries() {
        let m = payments_host_functions();
        assert_eq!(m.len(), 13, "expected 13 host functions");
        assert_eq!(
            m.get("payments_get_instruction"),
            Some(&"/v1/internal/instructions/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_update_instruction"),
            Some(&"/v1/internal/instructions/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_payment"),
            Some(&"/v1/internal/payments/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_payment_instrument"),
            Some(&"/v1/internal/payment-instruments/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_account_link"),
            Some(&"/v1/internal/account-links/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_parameter"),
            Some(&"/v1/internal/parameters/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_rule"),
            Some(&"/v1/internal/rules/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_integration"),
            Some(&"/v1/internal/integrations/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_mandate"),
            Some(&"/v1/internal/mandates/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_manual_decision"),
            Some(&"/v1/internal/manual-decisions/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_calendar"),
            Some(&"/v1/internal/calendars/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_card"),
            Some(&"/v1/internal/cards/{args.0}".to_string()),
        );
        assert_eq!(
            m.get("payments_get_cardholder"),
            Some(&"/v1/internal/cardholders/{args.0}".to_string()),
        );
    }

    #[test]
    fn host_function_names_are_unique_and_prefixed() {
        let m = payments_host_functions();
        for key in m.keys() {
            assert!(
                key.starts_with("payments_"),
                "host function name '{key}' must start with payments_",
            );
        }
    }

    #[test]
    fn host_function_paths_target_internal_endpoints() {
        let m = payments_host_functions();
        for value in m.values() {
            assert!(
                value.starts_with("/v1/internal/"),
                "host function path '{value}' must start with /v1/internal/",
            );
            assert!(
                value.contains("{args.0}"),
                "host function path '{value}' must include an {{args.0}} placeholder",
            );
        }
    }

    #[test]
    fn resolve_host_function_path_substitutes_args() {
        let path = resolve_host_function_path(
            "/v1/internal/instructions/{args.0}",
            &["abc-123"],
        );
        assert_eq!(path.as_deref(), Some("/v1/internal/instructions/abc-123"));
    }

    #[test]
    fn resolve_host_function_path_returns_none_for_missing_arg() {
        let path = resolve_host_function_path("/v1/internal/instructions/{args.0}", &[]);
        assert!(path.is_none());
    }

    #[test]
    fn resolve_host_function_path_ignores_extra_args() {
        let path =
            resolve_host_function_path("/v1/internal/payments/{args.0}", &["p-1", "extra"]);
        assert_eq!(path.as_deref(), Some("/v1/internal/payments/p-1"));
    }

    #[test]
    fn host_functions_is_stable_across_calls() {
        let a = payments_host_functions();
        let b = payments_host_functions();
        assert_eq!(a.len(), b.len());
        for key in a.keys() {
            assert_eq!(a.get(key), b.get(key), "mismatch for key {key}");
        }
    }
}