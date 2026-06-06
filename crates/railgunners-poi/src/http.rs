//! Default HTTP transport for POI JSON-RPC.

use std::time::Duration;

use ureq::{Error, http::Uri};

use crate::{PoiError, PoiJsonRpcTransport};

/// Configuration for the default POI HTTP transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoiHttpTransportConfig {
    timeout: Duration,
    max_retries: u32,
}

impl PoiHttpTransportConfig {
    /// Creates transport configuration from explicit timeout and retry settings.
    #[must_use]
    pub const fn new(timeout: Duration, max_retries: u32) -> Self {
        Self { timeout, max_retries }
    }

    /// Returns the per-request timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Returns the number of retry attempts after the first request.
    #[must_use]
    pub const fn max_retries(self) -> u32 {
        self.max_retries
    }
}

impl Default for PoiHttpTransportConfig {
    fn default() -> Self {
        Self::new(Duration::from_secs(30), 0)
    }
}

/// Default HTTP POST transport for POI JSON-RPC requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiHttpTransport {
    endpoint: String,
    config: PoiHttpTransportConfig,
}

impl PoiHttpTransport {
    /// Creates a POI HTTP transport for the provided endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint is not an absolute HTTP or HTTPS URL.
    pub fn new(
        endpoint: impl Into<String>,
        config: PoiHttpTransportConfig,
    ) -> Result<Self, PoiError> {
        let endpoint = endpoint.into();
        validate_endpoint(&endpoint)?;
        Ok(Self { endpoint, config })
    }

    fn execute_once(&self, request_body: &str) -> Result<String, PoiError> {
        let mut response = ureq::post(&self.endpoint)
            .config()
            .timeout_global(Some(self.config.timeout()))
            .build()
            .content_type("application/json")
            .send(request_body)
            .map_err(map_ureq_error)?;

        response.body_mut().read_to_string().map_err(map_ureq_error)
    }
}

impl PoiJsonRpcTransport for PoiHttpTransport {
    fn execute(&self, request_body: &str) -> Result<String, PoiError> {
        let total_attempts = self.config.max_retries().saturating_add(1);

        for attempt in 1..=total_attempts {
            match self.execute_once(request_body) {
                Ok(response_body) => return Ok(response_body),
                Err(error) => {
                    let retryable = is_retryable_transport_error(&error);
                    let should_retry = retryable && attempt < total_attempts;
                    if should_retry {
                        continue;
                    }
                    if retryable && attempt > 1 {
                        return Err(PoiError::PoiTransportRetryExhausted {
                            attempts: attempt,
                            last_error: Box::new(error),
                        });
                    }
                    return Err(error);
                }
            }
        }

        Err(PoiError::PoiTransportFailed("transport retry loop terminated unexpectedly".to_owned()))
    }
}

fn validate_endpoint(endpoint: &str) -> Result<(), PoiError> {
    let uri = endpoint
        .parse::<Uri>()
        .map_err(|_| PoiError::InvalidPoiTransportEndpoint(endpoint.to_owned()))?;
    let has_http_scheme = matches!(uri.scheme_str(), Some("http" | "https"));
    if !has_http_scheme || uri.authority().is_none() {
        return Err(PoiError::InvalidPoiTransportEndpoint(endpoint.to_owned()));
    }
    Ok(())
}

fn is_retryable_transport_error(error: &PoiError) -> bool {
    matches!(error, PoiError::PoiTransportFailed(_) | PoiError::PoiTransportTimeout)
}

fn map_ureq_error(error: Error) -> PoiError {
    match error {
        Error::Timeout(_) => PoiError::PoiTransportTimeout,
        Error::StatusCode(status) => PoiError::PoiTransportUnexpectedHttpStatus(status),
        Error::BadUri(_) => {
            PoiError::PoiTransportFailed("request endpoint became invalid".to_owned())
        }
        other => PoiError::PoiTransportFailed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpListener},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use super::{PoiHttpTransport, PoiHttpTransportConfig};
    use crate::{PoiClient, PoiError};

    fn spawn_server(handler: impl FnOnce(TcpListener, SocketAddr) + Send + 'static) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("test listener should bind: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("test listener should have local addr: {error}"));
        thread::spawn(move || handler(listener, address));
        address
    }

    #[test]
    fn rejects_invalid_endpoint_url() {
        let Err(error) = PoiHttpTransport::new("not a url", PoiHttpTransportConfig::default())
        else {
            panic!("invalid endpoint should fail");
        };

        assert_eq!(error, PoiError::InvalidPoiTransportEndpoint("not a url".to_owned()));
    }

    #[test]
    fn timeout_error_stays_distinct_without_retries() {
        let address = spawn_server(|listener, _address| {
            let (_stream, _) = listener
                .accept()
                .unwrap_or_else(|error| panic!("server should accept client: {error}"));
            thread::sleep(Duration::from_millis(150));
        });
        let transport = PoiHttpTransport::new(
            format!("http://{address}"),
            PoiHttpTransportConfig::new(Duration::from_millis(50), 0),
        )
        .unwrap_or_else(|error| panic!("endpoint should validate: {error}"));
        let client = PoiClient::new(transport);

        let Err(error) = client.health() else {
            panic!("timed out request should fail");
        };

        assert_eq!(error, PoiError::PoiTransportTimeout);
    }

    #[test]
    fn retries_exhaustion_is_reported_distinctly() {
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_server = Arc::clone(&accepted);
        let address = spawn_server(move |listener, _address| {
            for _ in 0..2 {
                let (_stream, _) = listener
                    .accept()
                    .unwrap_or_else(|error| panic!("server should accept client: {error}"));
                accepted_server.fetch_add(1, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(150));
            }
        });
        let transport = PoiHttpTransport::new(
            format!("http://{address}"),
            PoiHttpTransportConfig::new(Duration::from_millis(50), 1),
        )
        .unwrap_or_else(|error| panic!("endpoint should validate: {error}"));
        let client = PoiClient::new(transport);

        let Err(error) = client.health() else {
            panic!("retries should eventually fail");
        };

        assert!(accepted.load(Ordering::Relaxed) >= 1);
        assert_eq!(
            error,
            PoiError::PoiTransportRetryExhausted {
                attempts: 2,
                last_error: Box::new(PoiError::PoiTransportTimeout),
            }
        );
    }

    #[test]
    fn parses_successful_health_response() {
        let address = spawn_server(|listener, _address| {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|error| panic!("server should accept client: {error}"));
            let mut request = [0_u8; 1024];
            let read = stream
                .read(&mut request)
                .unwrap_or_else(|error| panic!("server should read request: {error}"));
            assert!(read > 0);

            let body = r#"{"jsonrpc":"2.0","result":"ok","id":1}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("server should write response: {error}"));
        });
        let transport =
            PoiHttpTransport::new(format!("http://{address}"), PoiHttpTransportConfig::default())
                .unwrap_or_else(|error| panic!("endpoint should validate: {error}"));
        let client = PoiClient::new(transport);

        let response = client
            .health()
            .unwrap_or_else(|error| panic!("health request should succeed: {error}"));

        assert_eq!(response.status(), "ok");
    }

    #[test]
    fn classifies_http_status_errors_distinctly() {
        let address = spawn_server(|listener, _address| {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|error| panic!("server should accept client: {error}"));
            let mut request = [0_u8; 1024];
            let _ = stream
                .read(&mut request)
                .unwrap_or_else(|error| panic!("server should read request: {error}"));

            let response =
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("server should write response: {error}"));
        });
        let transport =
            PoiHttpTransport::new(format!("http://{address}"), PoiHttpTransportConfig::default())
                .unwrap_or_else(|error| panic!("endpoint should validate: {error}"));
        let client = PoiClient::new(transport);

        let Err(error) = client.health() else {
            panic!("non-success status should fail");
        };

        assert_eq!(error, PoiError::PoiTransportUnexpectedHttpStatus(502));
    }
}
