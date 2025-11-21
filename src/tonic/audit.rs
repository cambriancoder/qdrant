//! Tonic (gRPC) middleware for audit logging of gRPC requests.

use std::collections::HashSet;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use tonic::body::BoxBody;
use tonic::codegen::http::{Request, Response};
use tower::Service;
use tower_layer::Layer;

use crate::common::audit::redact_if_needed;

/// Audit middleware service that wraps the inner gRPC service.
#[derive(Clone)]
pub struct AuditMiddleware<T> {
    inner: T,
    headers_to_log: Arc<HashSet<String>>,
}

/// Audit middleware layer (factory) for creating audit middleware.
#[derive(Clone)]
pub struct AuditMiddlewareLayer {
    headers_to_log: Arc<HashSet<String>>,
}

impl AuditMiddlewareLayer {
    pub fn new(headers_to_log: Arc<HashSet<String>>) -> Self {
        Self { headers_to_log }
    }
}

/// Extract selected headers/metadata from the gRPC request for logging.
fn extract_metadata<B>(
    request: &Request<B>,
    headers_to_log: &HashSet<String>,
) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for (name, value) in request.headers().iter() {
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

/// Format headers/metadata for logging output.
fn format_metadata(metadata: &[(String, String)]) -> String {
    if metadata.is_empty() {
        return String::new();
    }

    let parts: Vec<String> = metadata
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    format!(" metadata=[{}]", parts.join(", "))
}

impl<S> Service<Request<tonic::transport::Body>> for AuditMiddleware<S>
where
    S: Service<Request<tonic::transport::Body>, Response = Response<BoxBody>> + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<tonic::transport::Body>) -> Self::Future {
        // Clone the service to avoid borrowing issues
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        // Extract request information
        let method_name = request.uri().path().to_string();

        // Extract client IP from headers if available (commonly x-forwarded-for or x-real-ip)
        let client_ip = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
            })
            .unwrap_or("-")
            .to_string();

        // Extract configured metadata
        let metadata = extract_metadata(&request, &self.headers_to_log);
        let metadata_str = format_metadata(&metadata);

        let instant = std::time::Instant::now();
        let future = inner.call(request);

        Box::pin(async move {
            let response = future.await;
            let elapsed = instant.elapsed();

            match &response {
                Err(_) => {
                    log::info!(
                        target: "qdrant::audit",
                        "AUDIT gRPC: {} client_ip={} status=ERROR duration_ms={:.3}{}",
                        method_name,
                        client_ip,
                        elapsed.as_secs_f64() * 1000.0,
                        metadata_str,
                    );
                }
                Ok(response_tonic) => {
                    // Try to get gRPC status from headers
                    let grpc_status = tonic::Status::from_header_map(response_tonic.headers());
                    let status_str = if let Some(status) = grpc_status {
                        format!("{}", status.code())
                    } else {
                        format!("HTTP_{}", response_tonic.status().as_u16())
                    };

                    log::info!(
                        target: "qdrant::audit",
                        "AUDIT gRPC: {} client_ip={} status={} duration_ms={:.3}{}",
                        method_name,
                        client_ip,
                        status_str,
                        elapsed.as_secs_f64() * 1000.0,
                        metadata_str,
                    );
                }
            }

            response
        })
    }
}

impl<S> Layer<S> for AuditMiddlewareLayer {
    type Service = AuditMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuditMiddleware {
            inner: service,
            headers_to_log: self.headers_to_log.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_metadata_empty() {
        let metadata: Vec<(String, String)> = vec![];
        assert_eq!(format_metadata(&metadata), "");
    }

    #[test]
    fn test_format_metadata_single() {
        let metadata = vec![("x-request-id".to_string(), "abc123".to_string())];
        assert_eq!(
            format_metadata(&metadata),
            " metadata=[x-request-id=abc123]"
        );
    }

    #[test]
    fn test_format_metadata_multiple() {
        let metadata = vec![
            ("x-request-id".to_string(), "abc123".to_string()),
            ("user-agent".to_string(), "test".to_string()),
        ];
        let result = format_metadata(&metadata);
        assert!(result.contains("x-request-id=abc123"));
        assert!(result.contains("user-agent=test"));
    }
}
