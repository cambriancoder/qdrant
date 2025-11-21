//! Auditing module for logging all requests with configurable headers.
//!
//! This module provides middleware for both HTTP (actix-web) and gRPC (tonic)
//! to log all incoming requests along with selected request headers.

use std::collections::HashSet;
use std::sync::Arc;

use serde::Deserialize;
use validator::Validate;

/// Configuration for the audit logging feature.
#[derive(Debug, Deserialize, Clone, Validate, Default)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// List of HTTP headers to include in audit logs (case-insensitive).
    /// Common examples: "x-request-id", "x-forwarded-for", "user-agent", "authorization"
    /// Note: The "authorization" header value will be redacted for security.
    #[serde(default)]
    pub headers: Vec<String>,
}

impl AuditConfig {
    /// Returns a set of lowercase header names for efficient lookup.
    pub fn headers_set(&self) -> HashSet<String> {
        self.headers.iter().map(|h| h.to_lowercase()).collect()
    }

    /// Create an Arc-wrapped copy of the headers set for use in middleware.
    pub fn headers_set_arc(&self) -> Arc<HashSet<String>> {
        Arc::new(self.headers_set())
    }
}

/// Headers that should have their values redacted in audit logs.
pub const REDACTED_HEADERS: &[&str] = &["authorization", "api-key", "x-api-key"];

/// Check if a header value should be redacted.
pub fn should_redact_header(header_name: &str) -> bool {
    let lower = header_name.to_lowercase();
    REDACTED_HEADERS.iter().any(|&h| h == lower)
}

/// Redact sensitive header values.
pub fn redact_if_needed(header_name: &str, value: &str) -> String {
    if should_redact_header(header_name) {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuditConfig::default();
        assert!(!config.enabled);
        assert!(config.headers.is_empty());
    }

    #[test]
    fn test_headers_set() {
        let config = AuditConfig {
            enabled: true,
            headers: vec!["X-Request-ID".to_string(), "User-Agent".to_string()],
        };
        let set = config.headers_set();
        assert!(set.contains("x-request-id"));
        assert!(set.contains("user-agent"));
        assert!(!set.contains("X-Request-ID")); // Should be lowercase
    }

    #[test]
    fn test_should_redact_header() {
        assert!(should_redact_header("authorization"));
        assert!(should_redact_header("Authorization"));
        assert!(should_redact_header("AUTHORIZATION"));
        assert!(should_redact_header("api-key"));
        assert!(should_redact_header("x-api-key"));
        assert!(!should_redact_header("user-agent"));
        assert!(!should_redact_header("x-request-id"));
    }

    #[test]
    fn test_redact_if_needed() {
        assert_eq!(
            redact_if_needed("authorization", "Bearer token123"),
            "[REDACTED]"
        );
        assert_eq!(redact_if_needed("user-agent", "Mozilla/5.0"), "Mozilla/5.0");
    }
}
