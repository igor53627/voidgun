//! Railgun circuit artifact management
//!
//! Handles downloading, caching, and loading of circuit artifacts (WASM, ZKEY, VKEY)
//! from IPFS for proof generation.
//!
//! Artifacts are organized by circuit variant (e.g., "01x01" = 1 nullifier, 1 commitment).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("Artifact not found: {0}")]
    NotFound(String),

    #[error("Download failed: {0}")]
    DownloadFailed(String),

    #[error("Invalid variant: {0}")]
    InvalidVariant(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
}

/// IPFS gateway for artifact downloads
pub const IPFS_GATEWAY: &str = "https://ipfs-lb.com";

/// IPFS hash for Railgun V2 artifacts
pub const MASTER_IPFS_HASH: &str = "QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU";

/// IPFS hash for POI artifacts
pub const POI_IPFS_HASH: &str = "QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr";

/// Circuit variant (nullifiers x commitments)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CircuitVariant {
    pub nullifiers: u8,
    pub commitments: u8,
}

impl CircuitVariant {
    pub fn new(nullifiers: u8, commitments: u8) -> Result<Self, ArtifactError> {
        // Validate based on Railgun's supported variants
        if nullifiers == 0 || nullifiers > 13 {
            return Err(ArtifactError::InvalidVariant(format!(
                "nullifiers must be 1-13, got {}",
                nullifiers
            )));
        }
        if commitments == 0 || commitments > 13 {
            return Err(ArtifactError::InvalidVariant(format!(
                "commitments must be 1-13, got {}",
                commitments
            )));
        }
        Ok(Self {
            nullifiers,
            commitments,
        })
    }

    /// String representation (e.g., "01x01")
    pub fn as_string(&self) -> String {
        format!("{:02}x{:02}", self.nullifiers, self.commitments)
    }

    /// Parse from string (e.g., "01x01")
    pub fn from_string(s: &str) -> Result<Self, ArtifactError> {
        let parts: Vec<&str> = s.split('x').collect();
        if parts.len() != 2 {
            return Err(ArtifactError::InvalidVariant(s.to_string()));
        }
        let nullifiers: u8 = parts[0]
            .parse()
            .map_err(|_| ArtifactError::InvalidVariant(s.to_string()))?;
        let commitments: u8 = parts[1]
            .parse()
            .map_err(|_| ArtifactError::InvalidVariant(s.to_string()))?;
        Self::new(nullifiers, commitments)
    }
}

/// Loaded circuit artifact
#[derive(Clone)]
pub struct CircuitArtifact {
    /// WASM binary for witness generation
    pub wasm: Option<Vec<u8>>,
    /// ZKEY binary for proving
    pub zkey: Vec<u8>,
    /// VKEY JSON for verification
    pub vkey: serde_json::Value,
}

impl std::fmt::Debug for CircuitArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitArtifact")
            .field("wasm_size", &self.wasm.as_ref().map(|w| w.len()))
            .field("zkey_size", &self.zkey.len())
            .field("vkey", &"<json>")
            .finish()
    }
}

/// Artifact store with caching
pub struct ArtifactStore {
    /// Base directory for artifact storage
    base_path: PathBuf,
    /// In-memory cache
    cache: Arc<RwLock<HashMap<String, CircuitArtifact>>>,
    /// Whether to use native (.dat) or WASM artifacts
    use_native: bool,
}

impl ArtifactStore {
    /// Create a new artifact store
    pub fn new(base_path: impl Into<PathBuf>, use_native: bool) -> Self {
        Self {
            base_path: base_path.into(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            use_native,
        }
    }

    /// Get artifacts for a circuit variant
    ///
    /// First checks cache, then disk, then downloads from IPFS
    pub async fn get_artifacts(
        &self,
        variant: &CircuitVariant,
    ) -> Result<CircuitArtifact, ArtifactError> {
        let key = variant.as_string();

        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(artifact) = cache.get(&key) {
                return Ok(artifact.clone());
            }
        }

        // Try to load from disk
        if let Ok(artifact) = self.load_from_disk(variant).await {
            let mut cache = self.cache.write().await;
            cache.insert(key.clone(), artifact.clone());
            return Ok(artifact);
        }

        // Download from IPFS
        self.download_artifacts(variant).await?;
        let artifact = self.load_from_disk(variant).await?;

        let mut cache = self.cache.write().await;
        cache.insert(key, artifact.clone());
        Ok(artifact)
    }

    /// Get the path to the ZKEY file for a variant
    pub fn zkey_path(&self, variant: &CircuitVariant) -> PathBuf {
        let key = variant.as_string();
        self.base_path.join(format!("{}.zkey", key))
    }

    /// Load artifacts from disk
    async fn load_from_disk(
        &self,
        variant: &CircuitVariant,
    ) -> Result<CircuitArtifact, ArtifactError> {
        let key = variant.as_string();
        let base = &self.base_path;

        let zkey_path = base.join(format!("{}.zkey", key));
        let vkey_path = base.join(format!("{}.vkey.json", key));
        let wasm_path = base.join(format!("{}.wasm", key));

        if !zkey_path.exists() {
            return Err(ArtifactError::NotFound(format!("{}.zkey", key)));
        }
        if !vkey_path.exists() {
            return Err(ArtifactError::NotFound(format!("{}.vkey.json", key)));
        }

        let zkey = tokio::fs::read(&zkey_path).await?;
        let vkey_str = tokio::fs::read_to_string(&vkey_path).await?;
        let vkey: serde_json::Value = serde_json::from_str(&vkey_str)
            .map_err(|e| ArtifactError::NotFound(format!("invalid vkey JSON: {}", e)))?;

        let wasm = if wasm_path.exists() {
            Some(tokio::fs::read(&wasm_path).await?)
        } else {
            None
        };

        Ok(CircuitArtifact { wasm, zkey, vkey })
    }

    /// Download artifacts from IPFS
    async fn download_artifacts(&self, variant: &CircuitVariant) -> Result<(), ArtifactError> {
        let key = variant.as_string();
        tokio::fs::create_dir_all(&self.base_path).await?;

        // Download VKEY (uncompressed JSON)
        let vkey_url = format!(
            "{}/ipfs/{}/circuits/{}/vkey.json",
            IPFS_GATEWAY, MASTER_IPFS_HASH, key
        );
        self.download_file(&vkey_url, &format!("{}.vkey.json", key), false)
            .await?;

        // Download ZKEY (brotli compressed)
        let zkey_url = format!(
            "{}/ipfs/{}/circuits/{}/zkey.br",
            IPFS_GATEWAY, MASTER_IPFS_HASH, key
        );
        self.download_file(&zkey_url, &format!("{}.zkey", key), true)
            .await?;

        // Download WASM (brotli compressed)
        if !self.use_native {
            let wasm_url = format!(
                "{}/ipfs/{}/prover/snarkjs/{}.wasm.br",
                IPFS_GATEWAY, MASTER_IPFS_HASH, key
            );
            self.download_file(&wasm_url, &format!("{}.wasm", key), true)
                .await?;
        }

        Ok(())
    }

    /// Download a single file, optionally decompressing brotli
    async fn download_file(
        &self,
        url: &str,
        filename: &str,
        is_brotli: bool,
    ) -> Result<(), ArtifactError> {
        let output_path = self.base_path.join(filename);

        tracing::info!("Downloading: {} -> {}", url, output_path.display());

        // Use reqwest for downloading
        let response = reqwest::get(url)
            .await
            .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ArtifactError::DownloadFailed(format!(
                "HTTP {}: {}",
                response.status(),
                url
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;

        let data = if is_brotli {
            // Decompress brotli
            let mut decompressed = Vec::new();
            let mut decoder = brotli::Decompressor::new(bytes.as_ref(), 4096);
            std::io::Read::read_to_end(&mut decoder, &mut decompressed)
                .map_err(|e| ArtifactError::DecompressionFailed(e.to_string()))?;
            decompressed
        } else {
            bytes.to_vec()
        };

        tokio::fs::write(&output_path, &data).await?;
        tracing::info!("Saved: {} ({} bytes)", output_path.display(), data.len());

        Ok(())
    }

    /// Check if artifacts exist for a variant
    pub fn has_artifacts(&self, variant: &CircuitVariant) -> bool {
        let key = variant.as_string();
        let zkey_path = self.base_path.join(format!("{}.zkey", key));
        let vkey_path = self.base_path.join(format!("{}.vkey.json", key));
        zkey_path.exists() && vkey_path.exists()
    }

    /// List available circuit variants on disk
    pub fn list_available(&self) -> Vec<CircuitVariant> {
        let mut variants = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&self.base_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".zkey") {
                    let key = name.trim_end_matches(".zkey");
                    if let Ok(variant) = CircuitVariant::from_string(key) {
                        if self.has_artifacts(&variant) {
                            variants.push(variant);
                        }
                    }
                }
            }
        }

        variants.sort_by(|a, b| (a.nullifiers, a.commitments).cmp(&(b.nullifiers, b.commitments)));
        variants
    }
}

/// Get the appropriate circuit variant for a transaction
pub fn select_circuit(
    num_nullifiers: usize,
    num_commitments: usize,
) -> Result<CircuitVariant, ArtifactError> {
    // Railgun uses specific circuit combinations
    // This selects the most efficient circuit that fits the transaction
    let nullifiers = num_nullifiers.min(13) as u8;
    let commitments = num_commitments.min(13) as u8;

    if nullifiers == 0 {
        return Err(ArtifactError::InvalidVariant(
            "Must have at least 1 nullifier".to_string(),
        ));
    }
    if commitments == 0 {
        return Err(ArtifactError::InvalidVariant(
            "Must have at least 1 commitment".to_string(),
        ));
    }

    CircuitVariant::new(nullifiers, commitments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_variant_parsing() {
        let v = CircuitVariant::from_string("01x02").unwrap();
        assert_eq!(v.nullifiers, 1);
        assert_eq!(v.commitments, 2);
        assert_eq!(v.as_string(), "01x02");
    }

    #[test]
    fn test_circuit_variant_validation() {
        assert!(CircuitVariant::new(0, 1).is_err());
        assert!(CircuitVariant::new(1, 0).is_err());
        assert!(CircuitVariant::new(14, 1).is_err());
        assert!(CircuitVariant::new(1, 14).is_err());
        assert!(CircuitVariant::new(1, 1).is_ok());
        assert!(CircuitVariant::new(13, 13).is_ok());
    }

    #[test]
    fn test_select_circuit() {
        let v = select_circuit(2, 3).unwrap();
        assert_eq!(v.nullifiers, 2);
        assert_eq!(v.commitments, 3);

        // Clamps to max
        let v = select_circuit(20, 20).unwrap();
        assert_eq!(v.nullifiers, 13);
        assert_eq!(v.commitments, 13);

        // Fails for 0
        assert!(select_circuit(0, 1).is_err());
    }
}
