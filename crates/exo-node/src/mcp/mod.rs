//! MCP (Model Context Protocol) server — constitutional AI interface.
//!
//! Embeds the MCP server directly in the exo-node process, giving AI agents
//! access to governance operations through constitutionally enforced tools.
//! Every tool invocation is verified by the CGR Kernel and MCP enforcement rules.
//!
//! ## Usage
//!
//! ```bash
//! exochain mcp                            # start MCP server on stdio
//! exochain mcp --actor-did did:exo:x      # use a specific DID
//! exochain mcp --sse 127.0.0.1:3030       # start MCP server on HTTP+SSE
//! ```

pub mod context;
pub mod error;
pub mod handler;
pub mod middleware;
pub mod prompts;
pub mod protocol;
pub mod resources;
pub mod tools;

use std::{
    convert::Infallible,
    io::{Error, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_stream::stream;
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
#[allow(unused_imports)]
pub use context::NodeContext;
pub use handler::{MAX_JSON_RPC_MESSAGE_BYTES, McpServer};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::Semaphore,
    time::sleep,
};
use zeroize::Zeroizing;

const EXO_MCP_SSE_TOKEN_ENV: &str = "EXO_MCP_SSE_TOKEN";
const MAX_SSE_EVENT_CONNECTIONS: usize = 64;

/// Run the MCP server on stdio (stdin/stdout).
///
/// Reads newline-delimited JSON-RPC messages from stdin,
/// processes them through the `McpServer`, and writes responses to stdout.
/// This is the primary transport for Claude Code and similar MCP clients.
///
/// All diagnostic logging goes to stderr so stdout remains a clean JSON-RPC channel.
pub async fn serve_stdio(server: McpServer) -> std::io::Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    eprintln!("[exochain-mcp] Constitutional MCP server ready on stdio");
    eprintln!("[exochain-mcp] Actor: {}", server.actor_did());
    eprintln!("[exochain-mcp] Tools: {}", server.tool_count());

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        if let Some(response) = server.handle_message(&line) {
            stdout.write_all(response.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    Ok(())
}

/// SSE transport state shared across handlers.
#[derive(Clone)]
pub struct SseState {
    /// The MCP server shared across all HTTP handlers.
    server: Arc<McpServer>,
    bearer_token: Arc<Zeroizing<String>>,
    event_connections: Arc<Semaphore>,
}

impl SseState {
    #[must_use]
    pub fn new(
        server: Arc<McpServer>,
        bearer_token: Zeroizing<String>,
        max_event_connections: usize,
    ) -> Self {
        Self {
            server,
            bearer_token: Arc::new(bearer_token),
            event_connections: Arc::new(Semaphore::new(max_event_connections)),
        }
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        let header = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());

        match header.and_then(|value| value.strip_prefix("Bearer ")) {
            Some(provided)
                if constant_time_eq(provided.as_bytes(), self.bearer_token.as_bytes()) =>
            {
                Ok(())
            }
            Some(_) => Err(StatusCode::FORBIDDEN),
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn sse_bearer_token_from_env() -> std::io::Result<Zeroizing<String>> {
    match std::env::var(EXO_MCP_SSE_TOKEN_ENV) {
        Ok(token) if !token.is_empty() => Ok(Zeroizing::new(token)),
        Ok(_) => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{EXO_MCP_SSE_TOKEN_ENV} must not be empty"),
        )),
        Err(_) => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{EXO_MCP_SSE_TOKEN_ENV} must be set before enabling MCP SSE"),
        )),
    }
}

fn parse_sse_bind_addr(bind: &str) -> std::io::Result<SocketAddr> {
    let addr = bind
        .parse::<SocketAddr>()
        .or_else(|_| parse_localhost_bind_addr(bind))?;
    if !addr.ip().is_loopback() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "MCP SSE plaintext transport may only bind to loopback; place a TLS terminator in front of 127.0.0.1 when remote access is required",
        ));
    }
    Ok(addr)
}

fn parse_localhost_bind_addr(bind: &str) -> std::io::Result<SocketAddr> {
    let Some(port) = bind.strip_prefix("localhost:") else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "MCP SSE bind must be a literal loopback socket address",
        ));
    };
    let port = port.parse::<u16>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid localhost MCP SSE port: {error}"),
        )
    })?;
    Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// Run the MCP server over HTTP + Server-Sent Events.
///
/// This is an additive transport for remote MCP clients that cannot attach
/// over stdio. The stdio transport remains the primary path for Claude Code
/// and other local clients.
///
/// Protocol:
/// - `POST /mcp/message` — send a JSON-RPC request, receive a JSON-RPC response
/// - `GET /mcp/events` — subscribe to server-sent notifications (future fan-out)
/// - `GET /mcp/health` — health check for load balancers
pub async fn serve_sse(server: McpServer, bind: &str) -> std::io::Result<()> {
    let bind_addr = parse_sse_bind_addr(bind)?;
    let bearer_token = sse_bearer_token_from_env()?;
    let state = SseState::new(Arc::new(server), bearer_token, MAX_SSE_EVENT_CONNECTIONS);

    eprintln!("[exochain-mcp] Constitutional MCP server ready on SSE");
    eprintln!("[exochain-mcp] Actor: {}", state.server.actor_did());
    eprintln!("[exochain-mcp] Tools: {}", state.server.tool_count());
    eprintln!("[exochain-mcp] Listening on loopback http://{bind_addr}");

    let router = build_sse_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// Build the MCP SSE router. Exposed for integration tests.
pub fn build_sse_router(state: SseState) -> Router {
    Router::new()
        .route("/mcp/health", get(handle_health))
        .route("/mcp/message", post(handle_message))
        .route("/mcp/events", get(handle_events))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_JSON_RPC_MESSAGE_BYTES))
}

async fn handle_health() -> &'static str {
    "ok"
}

async fn handle_message(
    State(state): State<SseState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Err(status) = state.authorize(&headers) {
        return status.into_response();
    }

    match state.server.handle_message(&body) {
        Some(resp) => (StatusCode::OK, resp).into_response(),
        None => (StatusCode::ACCEPTED, String::new()).into_response(),
    }
}

async fn handle_events(State(state): State<SseState>, headers: HeaderMap) -> Response {
    if let Err(status) = state.authorize(&headers) {
        return status.into_response();
    }

    let permit = match state.event_connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };

    // Heartbeat stream — a production implementation would fan-out
    // server-initiated JSON-RPC notifications to subscribed clients.
    let s = stream! {
        let _permit = permit;
        loop {
            yield Ok::<Event, Infallible>(Event::default().event("heartbeat").data("ok"));
            sleep(Duration::from_secs(30)).await;
        }
    };
    Sse::new(s)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

#[cfg(test)]
mod sse_tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    const TEST_SSE_TOKEN: &str = "test-sse-token";

    fn test_router() -> Router {
        test_router_with_event_limit(64)
    }

    fn test_router_with_event_limit(max_event_connections: usize) -> Router {
        let did = exo_core::Did::new("did:exo:test").expect("valid DID");
        let keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x4D; 32]).unwrap();
        let public_key = *keypair.public_key();
        let secret_key = keypair.secret_key().clone();
        let state = SseState::new(
            Arc::new(McpServer::with_authority(
                did.clone(),
                did,
                public_key,
                Arc::new(move |message: &[u8]| exo_core::crypto::sign(message, &secret_key)),
            )),
            Zeroizing::new(TEST_SSE_TOKEN.to_owned()),
            max_event_connections,
        );
        build_sse_router(state)
    }

    #[test]
    fn sse_transport_source_requires_loopback_auth_and_connection_limit() {
        let source = include_str!("mod.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(
            production.contains("EXO_MCP_SSE_TOKEN"),
            "SSE transport must require a configured bearer token"
        );
        assert!(
            production.contains("is_loopback"),
            "SSE transport must reject non-loopback plaintext binds"
        );
        assert!(
            production.contains("try_acquire_owned"),
            "SSE event stream must enforce a bounded connection semaphore"
        );
    }

    #[test]
    fn constant_time_eq_matches_only_equal_same_length_tokens() {
        assert!(constant_time_eq(b"token-123", b"token-123"));
        assert!(!constant_time_eq(b"token-123", b"token-124"));
        assert!(!constant_time_eq(b"token-123", b"token-1234"));
    }

    #[test]
    fn parse_sse_bind_addr_accepts_loopback_only_forms() {
        let literal = parse_sse_bind_addr("127.0.0.1:3030").unwrap();
        assert_eq!(literal, SocketAddr::from((Ipv4Addr::LOCALHOST, 3030)));

        let localhost = parse_sse_bind_addr("localhost:3031").unwrap();
        assert_eq!(localhost, SocketAddr::from((Ipv4Addr::LOCALHOST, 3031)));
    }

    #[test]
    fn parse_sse_bind_addr_rejects_remote_and_ambiguous_binds() {
        let remote = parse_sse_bind_addr("0.0.0.0:3030").unwrap_err();
        assert_eq!(remote.kind(), ErrorKind::PermissionDenied);
        assert!(remote.to_string().contains("loopback"));

        let ambiguous = parse_sse_bind_addr(":3030").unwrap_err();
        assert_eq!(ambiguous.kind(), ErrorKind::InvalidInput);

        let invalid_localhost = parse_sse_bind_addr("localhost:not-a-port").unwrap_err();
        assert_eq!(invalid_localhost.kind(), ErrorKind::InvalidInput);
        assert!(invalid_localhost.to_string().contains("invalid localhost"));
    }

    #[tokio::test]
    async fn sse_health_returns_ok() {
        let router = test_router();
        let req = Request::builder()
            .method("GET")
            .uri("/mcp/health")
            .body(Body::empty())
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), 200);
        let body_bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(&body_bytes[..], b"ok");
    }

    #[tokio::test]
    async fn sse_message_requires_bearer_token() {
        let router = test_router();
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.0"}}}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/message")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sse_message_rejects_wrong_bearer_token() {
        let router = test_router();
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.0"}}}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/message")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong-token")
            .body(Body::from(body))
            .unwrap();

        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sse_events_requires_bearer_token() {
        let router = test_router();
        let req = Request::builder()
            .method("GET")
            .uri("/mcp/events")
            .body(Body::empty())
            .unwrap();

        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sse_message_initialize() {
        let router = test_router();
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.0"}}}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/message")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {TEST_SSE_TOKEN}"))
            .body(Body::from(body))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), 200);
        let body_bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("exochain-mcp"),
            "expected serverInfo name in initialize response, got: {text}"
        );
    }

    #[tokio::test]
    async fn sse_message_tools_list() {
        let router = test_router();
        let body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/message")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {TEST_SSE_TOKEN}"))
            .body(Body::from(body))
            .unwrap();
        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), 200);
        let body_bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("\"tools\""),
            "expected tools array in tools/list response, got: {text}"
        );
    }

    #[tokio::test]
    async fn sse_message_rejects_oversized_body_before_handler() {
        let router = test_router();
        let oversized_client_name = "a".repeat(64 * 1024);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"{oversized_client_name}","version":"0.0.0"}}}}}}"#
        );
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/message")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {TEST_SSE_TOKEN}"))
            .body(Body::from(body))
            .unwrap();

        let res = router.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn sse_events_enforces_connection_limit() {
        let router = test_router_with_event_limit(1);
        let first_req = Request::builder()
            .method("GET")
            .uri("/mcp/events")
            .header("authorization", format!("Bearer {TEST_SSE_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let second_req = Request::builder()
            .method("GET")
            .uri("/mcp/events")
            .header("authorization", format!("Bearer {TEST_SSE_TOKEN}"))
            .body(Body::empty())
            .unwrap();

        let first = router.clone().oneshot(first_req).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = router.oneshot(second_req).await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        drop(first);
    }
}
