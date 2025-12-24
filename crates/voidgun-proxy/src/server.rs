//! HTTP/WebSocket server using axum

use std::sync::Arc;

use axum::{
    extract::{State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::context::UserContextStore;
use crate::db::Database;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::proxy::RpcProxy;

pub struct Server {
    proxy: Arc<RpcProxy>,
}

impl Server {
    pub async fn new(
        upstream_url: String,
        chain_id: u64,
        database_url: &str,
    ) -> anyhow::Result<Self> {
        let db = Arc::new(Database::new(database_url).await?);
        let store = Arc::new(UserContextStore::new(db, upstream_url.clone()));

        let restored = store.restore_from_db(chain_id).await.unwrap_or(0);
        if restored > 0 {
            tracing::info!("Restored {} user contexts from database", restored);
        }

        let proxy = Arc::new(RpcProxy::new(store, upstream_url, chain_id));

        Ok(Self { proxy })
    }

    pub async fn new_in_memory(upstream_url: String, chain_id: u64) -> anyhow::Result<Self> {
        let db = Arc::new(Database::in_memory().await?);
        let store = Arc::new(UserContextStore::new(db, upstream_url.clone()));
        let proxy = Arc::new(RpcProxy::new(store, upstream_url, chain_id));

        Ok(Self { proxy })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/", post(handle_rpc))
            .route("/", get(handle_ws))
            .route("/health", get(health))
            .layer(CorsLayer::permissive())
            .layer(TraceLayer::new_for_http())
            .with_state(self.proxy.clone())
    }

    pub async fn run(self, addr: &str) -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Voidgun proxy listening on {}", addr);
        axum::serve(listener, self.router()).await?;
        Ok(())
    }

    pub fn proxy(&self) -> Arc<RpcProxy> {
        self.proxy.clone()
    }
}

async fn handle_rpc(
    State(proxy): State<Arc<RpcProxy>>,
    Json(request): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    let response = proxy.handle(request).await;
    Json(response)
}

async fn handle_ws(State(proxy): State<Arc<RpcProxy>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, proxy))
}

async fn handle_ws_connection(mut socket: axum::extract::ws::WebSocket, proxy: Arc<RpcProxy>) {
    use axum::extract::ws::Message;

    while let Some(msg) = socket.recv().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!("WebSocket error: {}", e);
                break;
            }
        };

        let request: JsonRpcRequest = match serde_json::from_str(&msg) {
            Ok(r) => r,
            Err(e) => {
                let error_response = JsonRpcResponse::error(
                    serde_json::Value::Null,
                    -32700,
                    format!("Parse error: {}", e),
                );
                let _ = socket
                    .send(Message::Text(
                        serde_json::to_string(&error_response).unwrap().into(),
                    ))
                    .await;
                continue;
            }
        };

        let response = proxy.handle(request).await;
        let response_json = serde_json::to_string(&response).unwrap();

        if socket
            .send(Message::Text(response_json.into()))
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}
