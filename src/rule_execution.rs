// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Func rule function execution - Story.
//! Payments calls Func Server to execute rule functions compiled to WASM.
//! Supported function names:
//! - `rule` - returns restrictions / instruction edits
//! - `account_link_selection` - returns true/false for account link selection
//! See `services/payments/DESIGN.md` §4.8 (Rule Functions).

use sentin8_func_sdk::client::{CallbackConfig, ExecuteRequest, FuncClient};

/// Execute a rule function on Func Server over the certificate-presenting
/// client (CERTFREE-4F - the `payments` workload certificate presents in
/// the TLS handshake; no bearer token exists on the path).
/// `client` - the boot-built Func client.
/// `wasm_module_id` - the WASM module ID (UUID or version label) to execute.
/// `function_name` - the rule function to invoke (`rule` or
/// `account_link_selection`).
/// `input` - the JSON context passed to the rule function (typically the
/// instruction, matched instrument, and resolved parameters).
/// Returns the JSON result produced by the WASM rule function.
pub async fn execute_rule_func(
    client: &FuncClient,
    wasm_module_id: &str,
    function_name: &str,
    input: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // Validate function name - only `rule` and `account_link_selection` are
    // supported by the Payments rule execution contract.
    match function_name {
        "rule" | "account_link_selection" => {}
        other => {
            return Err(format!(
                "unsupported rule function name: '{other}' (expected 'rule' or 'account_link_selection')"
            ));
        }
    }

    let req = ExecuteRequest {
        hook: function_name.to_string(),
        context: input,
        // Payments does not currently expose host functions back to the WASM
        // module during rule evaluation; rules are pure functions over their
        // input context. Callback config is omitted.
        callback_config: None,
    };
    let _ = CallbackConfig {
        base_url: String::new(),
        auth_token: String::new(),
        internal_path: String::new(),
        host_functions: std::collections::HashMap::new(),
    };
    let result = client
        .execute(wasm_module_id, &req)
        .await
        .map_err(|e| format!("func execute {function_name}: {e}"))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A local client stub - the validation these tests exercise happens
    /// before any HTTP call, so the transport never runs.
    fn stub() -> FuncClient {
        FuncClient::new("http://invalid.localhost:0", "")
    }

    /// Verify the function rejects unsupported function names without
    /// contacting Func Server.
    #[tokio::test]
    async fn test_execute_rule_sentin8_func_rejects_unknown_function_name() {
        let err = execute_rule_func(&stub(), "module-1", "bogus_function", json!({}))
            .await
            .expect_err("should reject unknown function name");
        assert!(
            err.contains("unsupported rule function name"),
            "unexpected error: {err}"
        );
    }

    /// Verify the function accepts `rule`.
    #[tokio::test]
    async fn test_execute_rule_sentin8_func_accepts_rule_function_name() {
        // The function name validation happens before any HTTP call, so
        // passing `rule` should pass the validation step and then fail at the
        // (non-existent) HTTP layer rather than the validation layer.
        let err = execute_rule_func(&stub(), "module-1", "rule", json!({}))
            .await
            .expect_err("should fail at HTTP layer, not validation");
        // We expect the error to mention the HTTP/Func call, not the
        // function-name validation.
        assert!(
            !err.contains("unsupported rule function name"),
            "expected non-validation error, got: {err}"
        );
    }

    /// Verify the function accepts `account_link_selection`.
    #[tokio::test]
    async fn test_execute_rule_sentin8_func_accepts_account_link_selection_function_name() {
        let err = execute_rule_func(&stub(), "module-1", "account_link_selection", json!({}))
            .await
            .expect_err("should fail at HTTP layer, not validation");
        assert!(
            !err.contains("unsupported rule function name"),
            "expected non-validation error, got: {err}"
        );
    }

    /// Verify the input context is passed through unchanged in the request
    /// payload by constructing the request manually (unit test of the
    /// request shape without a real server).
    #[test]
    fn test_execute_request_shape_for_rule_function() {
        let input = json!({
            "instruction": {"id": "i-1", "amount": "100.00"},
            "matched_instrument" : {"id": "pi-1"},
            "params": {"max_amount": "1000.00"}
        });
        let req = ExecuteRequest {
            hook: "rule".to_string(),
            context: input.clone(),
            callback_config: None,
        };
        let serialized = serde_json::to_value(&req).expect("serialize");
        assert_eq!(serialized["hook"], "rule");
        assert_eq!(serialized["context"], input);
        assert!(serialized.get("callback_config").unwrap().is_null());
    }
}
