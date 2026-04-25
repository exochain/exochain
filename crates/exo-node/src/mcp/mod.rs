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

use std::{convert::Infallible, sync::Arc, time::Duration};

use async_stream::stream;
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
#[allow(unused_imports)]
pub use context::NodeContext;
use futures::stream::Stream;
pub use handler::McpServer;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    time::sleep,
};

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
    pub server: Arc<McpServer>,
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
    let state = SseState {
        server: Arc::new(server),
    };

    eprintln!("[exochain-mcp] Constitutional MCP server ready on SSE");
    eprintln!("[exochain-mcp] Actor: {}", state.server.actor_did());
    eprintln!("[exochain-mcp] Tools: {}", state.server.tool_count());
    eprintln!("[exochain-mcp] Listening on http://{bind}");

    let router = build_sse_router(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
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
}

async fn handle_health() -> &'static str {
    "ok"
}

async fn handle_message(State(state): State<SseState>, body: String) -> impl IntoResponse {
    match state.server.handle_message(&body) {
        Some(resp) => (StatusCode::OK, resp),
        None => (StatusCode::ACCEPTED, String::new()),
    }
}

async fn handle_events(
    State(_state): State<SseState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Heartbeat stream — a production implementation would fan-out
    // server-initiated JSON-RPC notifications to subscribed clients.
    let s = stream! {
        loop {
            yield Ok(Event::default().event("heartbeat").data("ok"));
            sleep(Duration::from_secs(30)).await;
        }
    };
    Sse::new(s).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

#[cfg(test)]
mod sse_tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    fn test_router() -> Router {
        let state = SseState {
            server: Arc::new(McpServer::new(
                exo_core::Did::new("did:exo:test").expect("valid DID"),
            )),
        };
        build_sse_router(state)
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
    async fn sse_message_initialize() {
        let router = test_router();
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.0"}}}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/message")
            .header("content-type", "application/json")
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
}
