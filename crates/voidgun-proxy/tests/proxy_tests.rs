use std::sync::Arc;

use alloy_primitives::Address;
use axum::body::to_bytes;
use futures_util::{SinkExt, StreamExt};
use httpmock::prelude::*;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

use voidgun_proxy::context::UserContextStore;
use voidgun_proxy::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use voidgun_proxy::proxy::RpcProxy;
use voidgun_proxy::server::Server;

const TEST_CHAIN_ID: u64 = 1;

fn dummy_request(method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: json!(1),
    }
}

async fn init_proxy(upstream: &MockServer) -> RpcProxy {
    let store = Arc::new(UserContextStore::new(
        Arc::new(voidgun_proxy::db::Database::in_memory().await.unwrap()),
        upstream.url("/"),
    ));
    RpcProxy::new(store, upstream.url("/"), TEST_CHAIN_ID)
}

fn sample_address() -> Address {
    "0x1000000000000000000000000000000000000000"
        .parse()
        .unwrap()
}

fn sample_signature() -> Vec<u8> {
    vec![1u8; 64]
}

#[tokio::test]
async fn test_dispatch_routes_custom_and_forwarding() {
    let server = MockServer::start();

    let forward_mock = server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .json_body(json!({"jsonrpc": "2.0", "result": "0x123", "id": 1}));
    });

    let proxy = init_proxy(&server).await;

    // Custom method should not hit upstream and should return an error for missing params
    let custom_response = proxy.handle(dummy_request("voidgun_init", json!([]))).await;
    assert!(custom_response.error.is_some());
    forward_mock.assert_hits(0);

    // Unknown method should be forwarded
    let forwarded = proxy
        .handle(dummy_request("eth_blockNumber", json!([])))
        .await;
    assert_eq!(forwarded.result, Some(json!("0x123")));
    forward_mock.assert_hits(1);

    // Local chain id handling
    let chain_id = proxy
        .handle(dummy_request("eth_chainId", json!([])))
        .await
        .result
        .unwrap();
    assert_eq!(chain_id, json!("0x1"));
}

#[tokio::test]
async fn test_eth_get_balance_intercepts_initialized_wallet() {
    let server = MockServer::start();
    let proxy = init_proxy(&server).await;

    let addr = sample_address();
    proxy
        .store
        .init_from_signature(TEST_CHAIN_ID, addr, &sample_signature())
        .await
        .unwrap();

    let response = proxy
        .handle(dummy_request(
            "eth_getBalance",
            json!([format!("{:?}", addr)]),
        ))
        .await;

    assert_eq!(response.result, Some(json!("0x0")));
}

#[tokio::test]
async fn test_method_handlers_validate_and_forward() {
    let server = MockServer::start();
    let forward_mock = server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .json_body(json!({"jsonrpc": "2.0", "result": "0xbeef", "id": 1}));
    });

    let proxy = init_proxy(&server).await;

    // Not initialized wallet should error
    let balance_error = proxy
        .handle(dummy_request(
            "voidgun_shieldedBalance",
            json!([format!("{:?}", sample_address())]),
        ))
        .await;
    assert!(balance_error.error.is_some());

    // eth_sendTransaction without init forwards upstream
    let forwarded = proxy
        .handle(dummy_request(
            "eth_sendTransaction",
            json!([{"from": format!("{:?}", sample_address())}]),
        ))
        .await;
    assert_eq!(forwarded.result, Some(json!("0xbeef")));
    forward_mock.assert_hits(1);
}

#[tokio::test]
async fn test_personal_sign_initializes_store() {
    let server = MockServer::start();

    let signature_hex = format!("0x{}", hex::encode(sample_signature()));
    let signature_mock = server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .json_body(json!({"jsonrpc": "2.0", "result": signature_hex, "id": 1}));
    });

    let proxy = init_proxy(&server).await;
    let address = sample_address();

    let response = proxy
        .handle(dummy_request(
            "personal_sign",
            json!([
                railgun_lane::RAILGUN_DOMAIN_MESSAGE,
                format!("{:?}", address)
            ]),
        ))
        .await;

    assert_eq!(
        response.result,
        Some(json!(format!("0x{}", hex::encode(sample_signature()))))
    );
    signature_mock.assert_hits(1);

    let ctx = proxy
        .store
        .get(TEST_CHAIN_ID, address)
        .expect("context stored");
    assert!(ctx.is_initialized().await);
}

#[tokio::test]
async fn test_jsonrpc_types_roundtrip() {
    let id = json!(99);
    let success = JsonRpcResponse::success(id.clone(), json!({"ok": true}));
    assert!(success.error.is_none());
    assert_eq!(success.result.unwrap().get("ok"), Some(&json!(true)));

    let err = JsonRpcResponse::error(id.clone(), -32000, "boom");
    assert!(err.result.is_none());
    assert_eq!(err.error.unwrap().code, -32000);

    let array_request = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "test".into(),
        params: json!([1, 2, 3]),
        id: id.clone(),
    };
    assert_eq!(array_request.params_as_array().unwrap().len(), 3);

    let null_params = JsonRpcRequest {
        params: Value::Null,
        ..array_request.clone()
    };
    assert!(null_params.params_as_array().unwrap().is_empty());

    let invalid_params = JsonRpcRequest {
        params: json!({"not": "array"}),
        ..array_request
    };
    assert!(invalid_params.params_as_array().is_err());
}

#[tokio::test]
async fn test_user_context_store_operations() {
    let mut db_file = std::env::temp_dir();
    db_file.push(format!("proxy_test_{}.db", std::process::id()));
    let _ = std::fs::File::create(&db_file).unwrap();
    let db_path = format!("sqlite:{}", db_file.display());
    let db = Arc::new(voidgun_proxy::db::Database::new(&db_path).await.unwrap());
    let store = UserContextStore::new(db.clone(), "http://localhost".into());
    let address = sample_address();

    let ctx = store
        .init_from_signature(TEST_CHAIN_ID, address, &sample_signature())
        .await
        .unwrap();
    assert!(ctx.is_initialized().await);
    assert!(store.get(TEST_CHAIN_ID, address).is_some());

    // Build a fresh store from the same database and restore
    let restored_store = UserContextStore::new(db.clone(), "http://localhost".into());
    let restored = restored_store.restore_from_db(TEST_CHAIN_ID).await.unwrap();
    assert_eq!(restored, 1);
    assert!(restored_store.get(TEST_CHAIN_ID, address).is_some());
}

#[tokio::test]
async fn test_http_and_websocket_endpoints() {
    let upstream = MockServer::start();

    let server = Server::new_in_memory(upstream.url("/"), TEST_CHAIN_ID)
        .await
        .expect("server init");
    let _proxy = server.proxy();
    let router = server.router();

    // HTTP JSON-RPC
    let response = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&dummy_request("eth_chainId", json!([]))).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body();

    let response: JsonRpcResponse =
        serde_json::from_slice(&to_bytes(response, usize::MAX).await.unwrap()).unwrap();

    assert_eq!(response.result, Some(json!("0x1")));

    // WebSocket - spin up a server task
    let addr = "127.0.0.1:34567";
    tokio::spawn(server.run(addr));
    // Give the server a moment to start
    sleep(Duration::from_millis(100)).await;

    let (mut stream, _) = tokio_tungstenite::connect_async(format!("ws://{}/", addr))
        .await
        .expect("connect ws");

    let ws_request = dummy_request("eth_chainId", json!([]));
    stream
        .send(Message::Text(serde_json::to_string(&ws_request).unwrap()))
        .await
        .unwrap();

    if let Some(msg) = stream.next().await {
        let msg = msg.unwrap();
        let response: JsonRpcResponse = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        assert_eq!(response.result, Some(json!("0x1")));
    } else {
        panic!("no websocket response");
    }
}
