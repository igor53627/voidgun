//! JSON-RPC 2.0 types

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProxyError;

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    pub fn from_error(id: Value, err: ProxyError) -> Self {
        Self::error(id, err.code(), err.to_string())
    }
}

impl JsonRpcRequest {
    pub fn params_as_array(&self) -> Result<Vec<Value>, ProxyError> {
        match &self.params {
            Value::Array(arr) => Ok(arr.clone()),
            Value::Null => Ok(vec![]),
            _ => Err(ProxyError::InvalidRequest("params must be an array".into())),
        }
    }
}
