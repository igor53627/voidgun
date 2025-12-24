//! Error types for the proxy server

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("JSON-RPC error: {0}")]
    JsonRpc(String),

    #[error("Upstream RPC error: {0}")]
    UpstreamRpc(String),

    #[error("Lane error: {0}")]
    Lane(#[from] railgun_lane::lane::LaneError),

    #[error("Not initialized: wallet has not signed domain message")]
    NotInitialized,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
}

impl ProxyError {
    pub fn code(&self) -> i32 {
        match self {
            Self::MethodNotFound(_) => -32601,
            Self::InvalidRequest(_) => -32600,
            Self::InvalidAddress(_) | Self::InvalidSignature => -32602,
            Self::NotInitialized => -32000,
            Self::Lane(_) => -32001,
            Self::UpstreamRpc(_) => -32002,
            Self::Database(_) => -32003,
            Self::JsonRpc(_) => -32700,
            Self::Internal(_) => -32603,
            Self::TransactionFailed(_) => -32004,
        }
    }
}

pub type ProxyResult<T> = Result<T, ProxyError>;
