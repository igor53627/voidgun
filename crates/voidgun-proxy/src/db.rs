//! SQLite persistence for user contexts
//!
//! Stores wallet state to survive proxy restarts:
//! - Viewing key entropy (signature hash, not raw signature)
//! - Last synced block
//! - Cached notes (optional, for faster restart)

use alloy_primitives::Address;
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};

use crate::error::ProxyResult;

pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(database_url: &str) -> ProxyResult<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;

        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    pub async fn in_memory() -> ProxyResult<Self> {
        Self::new("sqlite:file::memory:?mode=memory&cache=shared").await
    }

    async fn run_migrations(&self) -> ProxyResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_contexts (
                chain_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                signature_entropy BLOB NOT NULL,
                last_synced_block INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY (chain_id, address)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cached_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                commitment BLOB NOT NULL,
                merkle_index INTEGER NOT NULL,
                token TEXT NOT NULL,
                value TEXT NOT NULL,
                is_spent INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (chain_id, address) REFERENCES user_contexts(chain_id, address)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_notes_user 
            ON cached_notes(chain_id, address, is_spent)
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn save_context(
        &self,
        chain_id: u64,
        address: Address,
        signature_entropy: &[u8],
        last_synced_block: u64,
    ) -> ProxyResult<()> {
        let address_str = format!("{:?}", address);
        let chain_id_i64 = chain_id as i64;
        let block_i64 = last_synced_block as i64;

        sqlx::query(
            r#"
            INSERT INTO user_contexts (chain_id, address, signature_entropy, last_synced_block)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chain_id, address) DO UPDATE SET
                signature_entropy = excluded.signature_entropy,
                last_synced_block = excluded.last_synced_block,
                updated_at = unixepoch()
            "#,
        )
        .bind(chain_id_i64)
        .bind(&address_str)
        .bind(signature_entropy)
        .bind(block_i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn load_context(
        &self,
        chain_id: u64,
        address: Address,
    ) -> ProxyResult<Option<(Vec<u8>, u64)>> {
        let address_str = format!("{:?}", address);
        let chain_id_i64 = chain_id as i64;

        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            r#"
            SELECT signature_entropy, last_synced_block
            FROM user_contexts
            WHERE chain_id = ? AND address = ?
            "#,
        )
        .bind(chain_id_i64)
        .bind(&address_str)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(entropy, block)| (entropy, block as u64)))
    }

    pub async fn update_synced_block(
        &self,
        chain_id: u64,
        address: Address,
        block: u64,
    ) -> ProxyResult<()> {
        let address_str = format!("{:?}", address);
        let chain_id_i64 = chain_id as i64;
        let block_i64 = block as i64;

        sqlx::query(
            r#"
            UPDATE user_contexts 
            SET last_synced_block = ?, updated_at = unixepoch()
            WHERE chain_id = ? AND address = ?
            "#,
        )
        .bind(block_i64)
        .bind(chain_id_i64)
        .bind(&address_str)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_contexts(&self, chain_id: u64) -> ProxyResult<Vec<(Address, u64)>> {
        let chain_id_i64 = chain_id as i64;

        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT address, last_synced_block
            FROM user_contexts
            WHERE chain_id = ?
            "#,
        )
        .bind(chain_id_i64)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::with_capacity(rows.len());
        for (addr_str, block) in rows {
            if let Ok(addr) = addr_str.parse() {
                result.push((addr, block as u64));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db_roundtrip() {
        let db = Database::in_memory().await.unwrap();
        let addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let entropy = vec![1u8, 2, 3, 4];

        db.save_context(1, addr, &entropy, 12345).await.unwrap();

        let loaded = db.load_context(1, addr).await.unwrap();
        assert!(loaded.is_some());
        let (loaded_entropy, loaded_block) = loaded.unwrap();
        assert_eq!(loaded_entropy, entropy);
        assert_eq!(loaded_block, 12345);
    }
}
