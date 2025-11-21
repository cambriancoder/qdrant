//! Actix-web middleware for audit logging of HTTP requests.

use std::collections::HashSet;
use std::future::{Ready, ready};
use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::Error;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::HeaderMap;
use futures_util::future::LocalBoxFuture;

use crate::common::audit::redact_if_needed;

/// Audit middleware service that wraps the inner service.
pub struct AuditService<S> {
    service: S,
    headers_to_log: Arc<HashSet<String>>,
}

/// Audit middleware transform (factory) for creating audit services.
pub struct AuditTransform {
    headers_to_log: Arc<HashSet<String>>,
}

impl AuditTransform {
    pub fn new(headers_to_log: Arc<HashSet<String>>) -> Self {
        Self { headers_to_log }
    }
}

/// Extract selected headers from the request for logging.
fn extract_headers(headers: &HeaderMap, headers_to_log: &HashSet<String>) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if headers_to_log.contains(&name_lower) {
            if let Ok(value_str) = value.to_str() {
                let logged_value = redact_if_needed(&name_lower, value_str);
                result.push((name_lower, logged_value));
            }
        }
    }

    result
}

/// Format headers for logging output.
fn format_headers(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        return String::new();
    }

    let parts: Vec<String> = headers
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    format!(" headers=[{}]", parts.join(", "))
}

impl<S, B> Service<ServiceRequest> for AuditService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        // Extract request information before passing to inner service
        let method = request.method().to_string();
        let path = request.path().to_string();
        let query_string = request.query_string().to_string();

        // Get client IP address
        let peer_addr: Option<SocketAddr> = request.peer_addr();
        let client_ip = peer_addr
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "-".to_string());

        // Extract configured headers
        let headers = extract_headers(request.headers(), &self.headers_to_log);
        let headers_str = format_headers(&headers);

        let future = self.service.call(request);

        Box::pin(async move {
            let start = std::time::Instant::now();
            let response = future.await?;
            let elapsed = start.elapsed();
            let status = response.response().status().as_u16();

            // Format query string if present
            let query_part = if query_string.is_empty() {
                String::new()
            } else {
                format!("?{}", query_string)
            };

            // Log the audit entry
            log::info!(
                target: "qdrant::audit",
                "AUDIT: {} {}{} client_ip={} status={} duration_ms={:.3}{}",
                method,
                path,
                query_part,
                client_ip,
                status,
                elapsed.as_secs_f64() * 1000.0,
                headers_str,
            );

            Ok(response)
        })
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuditTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuditService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuditService {
            service,
            headers_to_log: self.headers_to_log.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderName, HeaderValue};

    #[test]
    fn test_extract_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("abc123"),
        );
        headers.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("test-agent"),
        );
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let mut headers_to_log = HashSet::new();
        headers_to_log.insert("x-request-id".to_string());
        headers_to_log.insert("authorization".to_string());

        let result = extract_headers(&headers, &headers_to_log);

        assert_eq!(result.len(), 2);

        // Find x-request-id
        let request_id = result.iter().find(|(k, _)| k == "x-request-id");
        assert!(request_id.is_some());
        assert_eq!(request_id.unwrap().1, "abc123");

        // Find authorization (should be redacted)
        let auth = result.iter().find(|(k, _)| k == "authorization");
        assert!(auth.is_some());
        assert_eq!(auth.unwrap().1, "[REDACTED]");
    }

    #[test]
    fn test_format_headers_empty() {
        let headers: Vec<(String, String)> = vec![];
        assert_eq!(format_headers(&headers), "");
    }

    #[test]
    fn test_format_headers_single() {
        let headers = vec![("x-request-id".to_string(), "abc123".to_string())];
        assert_eq!(format_headers(&headers), " headers=[x-request-id=abc123]");
    }

    #[test]
    fn test_format_headers_multiple() {
        let headers = vec![
            ("x-request-id".to_string(), "abc123".to_string()),
            ("user-agent".to_string(), "test".to_string()),
        ];
        let result = format_headers(&headers);
        assert!(result.contains("x-request-id=abc123"));
        assert!(result.contains("user-agent=test"));
    }
}
