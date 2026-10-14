// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Load test harness for Payments — Story.
//! Provides a stub load-test runner that simulates instruction-processing
//! throughput and concurrent payments. The real implementation would drive
//! the HTTP API or the Flow engine directly; this stub returns simulated
//! metrics suitable for CI smoke tests and capacity-planning dry runs.
//! See `services/payments/DESIGN.md`.

use serde::{Deserialize, Serialize};

// ── Configuration ──────────────────────────────────────────────────────

/// Configuration for a Payments load test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    /// Duration of the test in seconds.
    pub duration_seconds: u64,
    /// Target requests per second.
    pub target_rps: u64,
    /// Number of concurrent in-flight instructions.
    pub concurrent_instructions: u32,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            duration_seconds: 60,
            target_rps: 100,
            concurrent_instructions: 50,
        }
    }
}

impl LoadTestConfig {
    /// Validate the configuration.
    /// `duration_seconds`, `target_rps`, and `concurrent_instructions` must
    /// all be non-zero.
    pub fn validate(&self) -> Result<(), String> {
        if self.duration_seconds == 0 {
            return Err("duration_seconds must be greater than 0".into());
        }
        if self.target_rps == 0 {
            return Err("target_rps must be greater than 0".into());
        }
        if self.concurrent_instructions == 0 {
            return Err("concurrent_instructions must be greater than 0".into());
        }
        Ok(())
    }
}

// ── Results ────────────────────────────────────────────────────────────

/// Result of a Payments load test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestResult {
    /// Total number of requests issued.
    pub total_requests: u64,
    /// Number of successful (2xx) responses.
    pub successful: u64,
    /// Number of failed responses.
    pub failed: u64,
    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,
    /// 99th percentile latency in milliseconds.
    pub p99_latency_ms: f64,
}

impl LoadTestResult {
    /// Success rate as a fraction in `[0.0, 1.0]`.
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.successful as f64 / self.total_requests as f64
    }
}

// ── Runner ─────────────────────────────────────────────────────────────

/// Run a Payments load test.
/// **Stub**: does not issue real HTTP traffic. Returns simulated metrics
/// derived from the configuration:
/// - `total_requests` = `target_rps * duration_seconds`
/// - `successful` ≈ 99.9% of `total_requests`
/// - `failed` = the remainder
/// - `avg_latency_ms` ≈ `1000 / target_rps` (capped at 500 ms)
/// - `p99_latency_ms` ≈ `avg_latency_ms * 5` (capped at 2000 ms)
/// Returns an error when the configuration is invalid.
pub fn run_load_test(config: &LoadTestConfig) -> Result<LoadTestResult, String> {
    config.validate()?;

    let total_requests = config.target_rps.saturating_mul(config.duration_seconds);
    // Simulate a 99.9% success rate.
    let successful = total_requests.saturating_mul(999) / 1000;
    let failed = total_requests - successful;

    // Average latency is the inverse of the target RPS, in ms, capped.
    let avg_latency_ms = (1000.0 / config.target_rps as f64).min(500.0);
    // P99 is roughly 5× the average, capped at 2 seconds.
    let p99_latency_ms = (avg_latency_ms * 5.0).min(2000.0);

    Ok(LoadTestResult {
        total_requests,
        successful,
        failed,
        avg_latency_ms,
        p99_latency_ms,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_test_config_default() {
        let cfg = LoadTestConfig::default();
        assert_eq!(cfg.duration_seconds, 60);
        assert_eq!(cfg.target_rps, 100);
        assert_eq!(cfg.concurrent_instructions, 50);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn load_test_config_rejects_zero_duration() {
        let cfg = LoadTestConfig {
            duration_seconds: 0,
            target_rps: 10,
            concurrent_instructions: 1,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn load_test_config_rejects_zero_rps() {
        let cfg = LoadTestConfig {
            duration_seconds: 10,
            target_rps: 0,
            concurrent_instructions: 1,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn load_test_config_rejects_zero_concurrency() {
        let cfg = LoadTestConfig {
            duration_seconds: 10,
            target_rps: 10,
            concurrent_instructions: 0,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn load_test_config_serialises() {
        let cfg = LoadTestConfig::default();
        let v = serde_json::to_value(&cfg).unwrap();
        assert_eq!(v["duration_seconds"], 60);
        assert_eq!(v["target_rps"], 100);
        assert_eq!(v["concurrent_instructions"], 50);
    }

    #[test]
    fn run_load_test_returns_simulated_metrics() {
        let cfg = LoadTestConfig {
            duration_seconds: 10,
            target_rps: 100,
            concurrent_instructions: 10,
        };
        let result = run_load_test(&cfg).unwrap();
        assert_eq!(result.total_requests, 1000);
        assert!(result.successful > 0);
        assert!(result.failed < result.successful);
        assert!(result.avg_latency_ms > 0.0);
        assert!(result.p99_latency_ms >= result.avg_latency_ms);
    }

    #[test]
    fn run_load_test_99_9_percent_success() {
        let cfg = LoadTestConfig {
            duration_seconds: 100,
            target_rps: 1000,
            concurrent_instructions: 100,
        };
        let result = run_load_test(&cfg).unwrap();
        assert_eq!(result.total_requests, 100_000);
        // 99.9% of 100_000 = 99_900.
        assert_eq!(result.successful, 99_900);
        assert_eq!(result.failed, 100);
    }

    #[test]
    fn run_load_test_rejects_invalid_config() {
        let cfg = LoadTestConfig {
            duration_seconds: 0,
            target_rps: 10,
            concurrent_instructions: 1,
        };
        assert!(run_load_test(&cfg).is_err());
    }

    #[test]
    fn run_load_test_caps_avg_latency_at_500ms() {
        // target_rps = 1 → 1000/1 = 1000 ms, capped at 500.
        let cfg = LoadTestConfig {
            duration_seconds: 10,
            target_rps: 1,
            concurrent_instructions: 1,
        };
        let result = run_load_test(&cfg).unwrap();
        assert_eq!(result.avg_latency_ms, 500.0);
    }

    #[test]
    fn run_load_test_caps_p99_at_2000ms() {
        // Very low RPS → avg = 500, p99 = 500*5 = 2500, capped at 2000.
        let cfg = LoadTestConfig {
            duration_seconds: 10,
            target_rps: 1,
            concurrent_instructions: 1,
        };
        let result = run_load_test(&cfg).unwrap();
        assert_eq!(result.p99_latency_ms, 2000.0);
    }

    #[test]
    fn load_test_result_success_rate() {
        let r = LoadTestResult {
            total_requests: 1000,
            successful: 990,
            failed: 10,
            avg_latency_ms: 10.0,
            p99_latency_ms: 50.0,
        };
        assert!((r.success_rate() - 0.99).abs() < 1e-9);
    }

    #[test]
    fn load_test_result_success_rate_zero_total() {
        let r = LoadTestResult {
            total_requests: 0,
            successful: 0,
            failed: 0,
            avg_latency_ms: 0.0,
            p99_latency_ms: 0.0,
        };
        assert_eq!(r.success_rate(), 0.0);
    }

    #[test]
    fn load_test_result_serialises() {
        let r = LoadTestResult {
            total_requests: 100,
            successful: 99,
            failed: 1,
            avg_latency_ms: 12.5,
            p99_latency_ms: 60.0,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["total_requests"], 100);
        assert_eq!(v["successful"], 99);
        assert_eq!(v["failed"], 1);
        assert_eq!(v["avg_latency_ms"], 12.5);
        assert_eq!(v["p99_latency_ms"], 60.0);
    }
}