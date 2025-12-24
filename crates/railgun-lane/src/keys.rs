//! Railgun wallet key management
//!
//! Implements Railgun's key derivation from either:
//! 1. BIP39 mnemonic (standard Railgun)
//! 2. Wallet signature (Voidgun bridge)
//!
//! ## Key Derivation Flow
//!
//! Railgun uses circomlib-compatible EdDSA on Baby Jubjub. The key derivation is:
//!
//! 1. BIP32 derivation produces a 32-byte chainKey
//! 2. The chainKey is passed to circomlib's `signPoseidon` / `prv2pub`
//! 3. Inside circomlib, `blake512(chainKey)[:32]` is computed and then "pruned"
//! 4. The pruned scalar is used for public key derivation and signing
//!
//! The "pruning" step:
//! - Clears bottom 3 bits (makes scalar divisible by 8)
//! - Clears bit 255 and sets bit 254
//!
//! This is critical for EdDSA verification: `S * Base8 == R8 + 8 * hm * A`

use ark_bn254::Fr as Field;
use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsAffine as BabyJubjubPoint, Fr as BabyJubjubScalar};
use ark_ff::{BigInteger, PrimeField};
use bip39::{Language, Mnemonic};
use blake2::{Blake2b512, Digest as Blake2Digest};
use ed25519_dalek::{SigningKey as Ed25519SecretKey, VerifyingKey as Ed25519PublicKey};
use sha3::Keccak256;
use thiserror::Error;

use crate::bip32::{spending_path, viewing_path, ExtendedKey};
use crate::poseidon::poseidon3;

use ark_ed_on_bn254::Fq as BabyJubjubFq;
use std::sync::OnceLock;

/// Curve coordinate transformation between circomlib and arkworks Baby Jubjub
///
/// Circomlib uses: A*x² + y² = 1 + D*x²*y²  where A = 168700, D = 168696
/// Arkworks uses:    x² + y² = 1 + d*x²*y²  where d = D/A = 168696/168700 mod p
///
/// The isomorphism is: (x_circ, y_circ) <-> (x_ark, y_ark) = (sqrt(A) * x_circ, y_circ)
/// sqrt(168700) mod p = 7214280148105020021932206872019688659210616427216992810330019057549499971851
static SQRT_A: OnceLock<BabyJubjubFq> = OnceLock::new();
static INV_SQRT_A: OnceLock<BabyJubjubFq> = OnceLock::new();

fn sqrt_a() -> BabyJubjubFq {
    *SQRT_A.get_or_init(|| {
        use ark_ff::BigInt;
        // sqrt(168700) mod p - using the "other" root for circomlib compatibility
        // p - sqrt = 14673962723734255200314198873237586429337747973199041533368185129026308523766
        // This choice ensures our coordinates match circomlib's expectations
        let sqrt_bigint = BigInt::<4>::new([
            0x541bf091de9bc6f6,
            0xdf2cc0efb7173e62,
            0xe70f25bb2bef9d9d,
            0x20712b27e5f8fc30,
        ]);
        BabyJubjubFq::from_bigint(sqrt_bigint).expect("valid sqrt(A)")
    })
}

fn inv_sqrt_a() -> BabyJubjubFq {
    *INV_SQRT_A.get_or_init(|| {
        use ark_ff::Field;
        sqrt_a().inverse().expect("sqrt(A) is invertible")
    })
}

/// Convert point from arkworks coordinates to circomlib coordinates
/// (x_ark, y_ark) -> (x_circ, y_circ) = (x_ark / sqrt(A), y_ark)
fn ark_to_circom_coords(x_ark: BabyJubjubFq, y_ark: BabyJubjubFq) -> (BabyJubjubFq, BabyJubjubFq) {
    (x_ark * inv_sqrt_a(), y_ark)
}

/// Convert point from circomlib coordinates to arkworks coordinates
/// (x_circ, y_circ) -> (x_ark, y_ark) = (x_circ * sqrt(A), y_circ)
#[allow(dead_code)]
fn circom_to_ark_coords(
    x_circ: BabyJubjubFq,
    y_circ: BabyJubjubFq,
) -> (BabyJubjubFq, BabyJubjubFq) {
    (x_circ * sqrt_a(), y_circ)
}

/// Cached Base8 point (8 * Generator) for Baby Jubjub
/// Used by circomlib EdDSA: https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js
///
/// IMPORTANT: The coordinates here are in ARKWORKS representation (a=1 curve).
/// Circomlib uses A=168700, D=168696 parameterization. The transformation is:
///   x_ark = sqrt(A) * x_circ, y_ark = y_circ
static BASE8_CACHE: OnceLock<BabyJubjubPoint> = OnceLock::new();

/// Get the Base8 point (8 * Generator) used in circomlib EdDSA
///
/// Circomlib Base8 coordinates (babyjub.js):
/// - x_circ: 5299619240641551281634865583518297030282874472190772894086521144482721001553
/// - y_circ: 16950150798460657717958625567821834550301663161624707787222815936182638968203
///
/// Transformed to arkworks (a=1) coordinates (x_ark = sqrt(A) * x_circ):
/// - x_ark: 15863623088992515880085393097393553694825975317405843389771115419751650972659
/// - y_ark: 16950150798460657717958625567821834550301663161624707787222815936182638968203
fn base8() -> BabyJubjubPoint {
    *BASE8_CACHE.get_or_init(|| {
        use ark_ff::BigInt;

        // Base8.x in ARKWORKS coordinates (after transformation)
        // x_ark = sqrt(168700) * x_circ mod p (using the "other" sqrt root)
        // This gives x_ark = 6024619782846759342161012647863721393722389083010190953927088766824157522958
        let x_bigint = BigInt::<4>::new([
            0x7fb6549d007bac0e,
            0xd8623449e6acddd7,
            0xe736093847a30c96,
            0x0d51d05f8a7751ba,
        ]);

        // Base8.y (same in both coordinate systems)
        let y_bigint = BigInt::<4>::new([
            0x4b3c257a872d7d8b,
            0xfce0051fb9e13377,
            0x25572e1cd16bf9ed,
            0x25797203f7a0b249,
        ]);

        let x = BabyJubjubFq::from_bigint(x_bigint).expect("valid x coordinate");
        let y = BabyJubjubFq::from_bigint(y_bigint).expect("valid y coordinate");
        let point = BabyJubjubPoint::new_unchecked(x, y);

        debug_assert!(
            point.is_on_curve(),
            "Base8 must be on arkworks Baby Jubjub curve"
        );

        point
    })
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("BIP32 derivation failed: {0}")]
    Bip32Error(#[from] crate::bip32::Bip32Error),

    #[error("Invalid mnemonic: {0}")]
    MnemonicError(String),

    #[error("Ed25519 key error")]
    Ed25519Error,
}

/// Spending key on Baby Jubjub curve
///
/// Uses circomlib-compatible EdDSA with Base8 point.
///
/// ## Key Derivation
///
/// The raw key bytes (from BIP32) are processed through circomlib's eddsa.js:
/// 1. `h = blake512(raw_key)` - hash the key with Blake2b-512
/// 2. `s = pruneBuffer(h[:32])` - take first 32 bytes and "prune":
///    - Clear bottom 3 bits (makes s divisible by 8)
///    - Clear bit 255, set bit 254
/// 3. `A = Base8 * (s >> 3)` - public key
///
/// The signature uses: S = r + hm * s (mod subOrder)
/// Verification: S * Base8 == R8 + 8 * hm * A
///
/// ## Important: Secret Scalar Storage
///
/// The secret scalar `s` is stored as raw bytes, NOT as a BabyJubjubScalar.
/// This is critical because circomlib treats `s` as a 256-bit integer that is
/// only reduced mod subOrder during signature computation. If we stored it as
/// BabyJubjubScalar, arkworks would reduce it mod the scalar field order,
/// potentially changing the bottom 3 bits and breaking the s = 8 * (s >> 3) identity.
#[derive(Clone)]
pub struct SpendingKey {
    /// Raw key bytes (before blake512 transformation)
    /// Stored for deterministic nonce derivation in signing
    pub raw_key: [u8; 32],
    /// Pruned secret bytes (32 bytes, little-endian)
    /// NOT reduced mod scalar field - kept as raw 256-bit value
    pub secret_bytes: [u8; 32],
    /// Blake512 hash output (64 bytes) - second half used for nonce derivation
    pub blake_hash: [u8; 64],
    /// Public point A = Base8 * (secret >> 3)
    pub public: BabyJubjubPoint,
}

impl SpendingKey {
    /// Prune buffer as per circomlib's eddsa.js pruneBuffer function
    ///
    /// This ensures the scalar is:
    /// - Divisible by 8 (bottom 3 bits cleared)
    /// - Has bit 254 set and bit 255 cleared (for cofactor handling)
    fn prune_buffer(buf: &mut [u8; 32]) {
        buf[0] &= 0xF8; // Clear bottom 3 bits
        buf[31] &= 0x7F; // Clear bit 255
        buf[31] |= 0x40; // Set bit 254
    }

    /// Create spending key from raw key bytes (as produced by BIP32 derivation)
    ///
    /// This applies the circomlib-compatible transformation:
    /// 1. Blake512 hash of raw key
    /// 2. Prune first 32 bytes
    /// 3. Derive public key from pruned scalar
    pub fn from_raw_bytes(raw_key: [u8; 32]) -> Self {
        use num_bigint::BigUint;

        // Step 1: Blake512 hash
        let mut hasher = Blake2b512::new();
        hasher.update(&raw_key);
        let hash_result = hasher.finalize();
        let mut blake_hash = [0u8; 64];
        blake_hash.copy_from_slice(&hash_result);

        // Step 2: Prune first 32 bytes
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&blake_hash[..32]);
        Self::prune_buffer(&mut secret_bytes);

        // Step 3: Compute public key A = Base8 * (s >> 3)
        // Use BigUint to avoid mod reduction, then shift by 3
        let s_biguint = BigUint::from_bytes_le(&secret_bytes);
        let s_shifted: BigUint = &s_biguint >> 3;

        // Convert shifted value to scalar for curve multiplication
        // This is safe because s >> 3 is always < subOrder (due to bit 254 set, bit 255 clear)
        let shifted_bytes = {
            let bytes = s_shifted.to_bytes_le();
            let mut padded = [0u8; 32];
            let len = bytes.len().min(32);
            padded[..len].copy_from_slice(&bytes[..len]);
            padded
        };
        let secret_shifted = BabyJubjubScalar::from_le_bytes_mod_order(&shifted_bytes);
        let public = (base8() * secret_shifted).into_affine();

        Self {
            raw_key,
            secret_bytes,
            blake_hash,
            public,
        }
    }

    /// Create spending key from scalar (DEPRECATED - use from_raw_bytes instead)
    ///
    /// This method is kept for backwards compatibility but does NOT match
    /// circomlib's key derivation. Use `from_raw_bytes` for circuit-compatible keys.
    #[deprecated(note = "Use from_raw_bytes for circomlib-compatible keys")]
    pub fn from_scalar(secret: BabyJubjubScalar) -> Self {
        use num_bigint::BigUint;

        // Convert scalar to bytes
        let secret_bytes_vec = secret.into_bigint().to_bytes_le();
        let mut secret_bytes = [0u8; 32];
        let len = secret_bytes_vec.len().min(32);
        secret_bytes[..len].copy_from_slice(&secret_bytes_vec[..len]);

        // Compute s >> 3 (divide by 8)
        let s_biguint = BigUint::from_bytes_le(&secret_bytes);
        let s_shifted: BigUint = &s_biguint >> 3;
        let shifted_bytes = {
            let bytes = s_shifted.to_bytes_le();
            let mut padded = [0u8; 32];
            let len = bytes.len().min(32);
            padded[..len].copy_from_slice(&bytes[..len]);
            padded
        };
        let secret_shifted = BabyJubjubScalar::from_le_bytes_mod_order(&shifted_bytes);

        // A = Base8 * (s >> 3)
        let public = (base8() * secret_shifted).into_affine();
        Self {
            raw_key: [0u8; 32],
            secret_bytes,
            blake_hash: [0u8; 64],
            public,
        }
    }

    /// Get public key coordinates as field elements (in CIRCOMLIB coordinates)
    ///
    /// The internal representation uses arkworks (a=1 curve), but circuits
    /// expect circomlib coordinates (A=168700 curve). This function converts.
    pub fn public_xy(&self) -> (Field, Field) {
        // Convert from arkworks to circomlib coordinates: x_circ = x_ark / sqrt(A)
        let (x_circ, y_circ) = ark_to_circom_coords(self.public.x, self.public.y);

        // Convert BabyJubjub Fq to BN254 Fr (same field, different type)
        let x_bytes = x_circ.into_bigint().to_bytes_be();
        let y_bytes = y_circ.into_bigint().to_bytes_be();
        (
            Field::from_be_bytes_mod_order(&x_bytes),
            Field::from_be_bytes_mod_order(&y_bytes),
        )
    }

    /// Sign a message using EdDSA on Baby Jubjub (circomlib-compatible)
    ///
    /// Returns (R8.x, R8.y, S) as field elements for the circuit.
    /// Uses the Poseidon-based EdDSA variant matching Railgun's circuits.
    ///
    /// Signature equation: S = r + hm * s (mod subOrder)
    /// Where:
    /// - r is the nonce derived deterministically: blake512(h[32:64] || msg) mod subOrder
    /// - hm = Poseidon(R8.x, R8.y, A.x, A.y, message)
    /// - s is the pruned secret scalar
    ///
    /// Verification: S * Base8 == R8 + 8 * hm * A
    pub fn sign(&self, message: Field) -> EddsaSignature {
        use num_bigint::BigUint;

        // Baby Jubjub subOrder = order >> 3
        // subOrder = 2736030358979909402780800718157159386076813972158567259200215660948447373041
        let sub_order = BigUint::parse_bytes(
            b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
            10,
        )
        .expect("valid subOrder");

        // Derive nonce r deterministically (like circomlib):
        // r = blake512(h[32:64] || msg) mod subOrder
        // where h = blake512(raw_key)
        let msg_bytes = message.into_bigint().to_bytes_le();
        let mut nonce_hasher = Blake2b512::new();
        nonce_hasher.update(&self.blake_hash[32..64]); // Second half of blake hash
        nonce_hasher.update(&msg_bytes);
        let nonce_hash = nonce_hasher.finalize();

        // Convert 64-byte hash to BigUint and reduce mod subOrder
        let r_biguint = BigUint::from_bytes_le(&nonce_hash);
        let r_mod = &r_biguint % &sub_order;

        // Convert to scalar (little-endian)
        let r_bytes_le = {
            let bytes = r_mod.to_bytes_le();
            let mut padded = [0u8; 32];
            let len = bytes.len().min(32);
            padded[..len].copy_from_slice(&bytes[..len]);
            padded
        };
        let r = BabyJubjubScalar::from_le_bytes_mod_order(&r_bytes_le);

        // R8 = r * Base8 (in arkworks coordinates)
        let r8_point_ark = (base8() * r).into_affine();

        // Convert R8 from arkworks to circomlib coordinates for the circuit
        let (r8_x_circ, r8_y_circ) = ark_to_circom_coords(r8_point_ark.x, r8_point_ark.y);

        // Convert to Field for Poseidon hashing
        let r8_x = Field::from_be_bytes_mod_order(&r8_x_circ.into_bigint().to_bytes_be());
        let r8_y = Field::from_be_bytes_mod_order(&r8_y_circ.into_bigint().to_bytes_be());

        // Get public key A as field elements
        let (ax, ay) = self.public_xy();

        // hm = Poseidon(R8.x, R8.y, A.x, A.y, message)
        let hm =
            crate::poseidon::poseidon_hash(&[r8_x, r8_y, ax, ay, message]).expect("5 inputs valid");

        // Convert hm to BigUint for mod subOrder arithmetic (little-endian like circomlib)
        let hm_biguint = BigUint::from_bytes_le(&hm.into_bigint().to_bytes_le());

        // Use secret_bytes directly (NOT reduced mod scalar field)
        let s_biguint = BigUint::from_bytes_le(&self.secret_bytes);

        // S = r + hm * s (mod subOrder)
        let s_sig_biguint = (&r_mod + (&hm_biguint * &s_biguint) % &sub_order) % &sub_order;

        // Convert S to Field (this needs to be in the correct format)
        let s_sig_bytes_le = {
            let bytes = s_sig_biguint.to_bytes_le();
            let mut padded = [0u8; 32];
            let len = bytes.len().min(32);
            padded[..len].copy_from_slice(&bytes[..len]);
            padded
        };
        let s_field = Field::from_le_bytes_mod_order(&s_sig_bytes_le);

        EddsaSignature {
            r8_x,
            r8_y,
            s: s_field,
        }
    }
}

/// EdDSA signature on Baby Jubjub curve
///
/// Circuit format: [R8.x, R8.y, S]
#[derive(Clone, Debug)]
pub struct EddsaSignature {
    /// R point x-coordinate
    pub r8_x: Field,
    /// R point y-coordinate
    pub r8_y: Field,
    /// Scalar s
    pub s: Field,
}

impl EddsaSignature {
    /// Convert to circuit input format [R8.x, R8.y, S]
    pub fn to_circuit_inputs(&self) -> [Field; 3] {
        [self.r8_x, self.r8_y, self.s]
    }
}

/// Viewing key using Ed25519
#[derive(Clone)]
pub struct ViewingKey {
    /// Private key (32 bytes)
    pub secret: Ed25519SecretKey,
    /// Public key (32 bytes compressed)
    pub public: Ed25519PublicKey,
}

impl ViewingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        let secret = Ed25519SecretKey::from_bytes(bytes);
        let public = Ed25519PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Get viewing private key as field element (for Poseidon hashing)
    pub fn secret_as_field(&self) -> Field {
        Field::from_be_bytes_mod_order(self.secret.as_bytes())
    }
}

/// Complete Railgun wallet with all derived keys
#[derive(Clone)]
pub struct RailgunWallet {
    /// Spending key (Baby Jubjub)
    pub spending: SpendingKey,

    /// Viewing key (Ed25519)
    pub viewing: ViewingKey,

    /// Nullifying key = Poseidon(viewing_secret)
    pub nullifying_key: Field,

    /// Master public key = Poseidon(spending_pub_x, spending_pub_y, nullifying_key)
    pub master_public_key: Field,

    /// Derivation index
    pub index: u32,
}

impl RailgunWallet {
    /// Derive wallet from standard wallet signature
    ///
    /// This bridges Voidgun's signature-based auth to Railgun's mnemonic system.
    /// The signature is hashed to produce entropy for a BIP39 mnemonic.
    pub fn from_wallet_signature(signature: &[u8]) -> Result<Self, KeyError> {
        if signature.len() < 64 {
            return Err(KeyError::InvalidSignature);
        }

        // Hash signature to get 128 bits of entropy
        let hash = Keccak256::digest(signature);
        let entropy: [u8; 16] = hash[..16]
            .try_into()
            .map_err(|_| KeyError::InvalidSignature)?;

        // Convert to 12-word mnemonic
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| KeyError::MnemonicError(e.to_string()))?;

        Self::from_mnemonic(&mnemonic, 0)
    }

    /// Derive wallet from BIP39 mnemonic (standard Railgun method)
    ///
    /// Uses circomlib-compatible key derivation:
    /// 1. BIP32 derivation with "babyjubjub seed" HMAC key
    /// 2. Raw chainKey bytes are passed to SpendingKey::from_raw_bytes
    /// 3. SpendingKey applies blake512 + pruneBuffer internally
    pub fn from_mnemonic(mnemonic: &Mnemonic, index: u32) -> Result<Self, KeyError> {
        let seed = mnemonic.to_seed("");

        // Derive master key using Baby Jubjub curve seed
        let master = ExtendedKey::master_from_seed(&seed)?;

        // Derive spending key: m/44'/1984'/0'/0'/{index}'
        let spending_node = master.derive_path(&spending_path(index))?;
        // Use raw bytes, NOT the scalar - circomlib applies blake512+prune internally
        let spending = SpendingKey::from_raw_bytes(spending_node.key);

        // Derive viewing key: m/420'/1984'/0'/0'/{index}'
        let viewing_node = master.derive_path(&viewing_path(index))?;
        let viewing = ViewingKey::from_bytes(&viewing_node.key)?;

        // Compute nullifying key = Poseidon(viewing_secret)
        let viewing_secret_field = viewing.secret_as_field();
        let nullifying_key = crate::poseidon::poseidon_hash(&[viewing_secret_field])
            .expect("single input always valid");

        // Compute master public key
        let (spend_x, spend_y) = spending.public_xy();
        let master_public_key = poseidon3(spend_x, spend_y, nullifying_key);

        Ok(Self {
            spending,
            viewing,
            nullifying_key,
            master_public_key,
            index,
        })
    }

    /// Generate 0zk address (Bech32m encoded)
    ///
    /// Format: 0zk{chain_prefix}1{bech32m_data}
    ///
    /// Data layout (73 bytes):
    /// - version: 1 byte (0x01)
    /// - master_public_key: 32 bytes (BE)
    /// - chain_id: 8 bytes (BE)
    /// - viewing_public_key: 32 bytes
    ///
    /// Chain prefixes:
    /// - Ethereum mainnet (1): "0zk"
    /// - Sepolia (11155111): "0zks"
    /// - Polygon (137): "0zkp"
    pub fn to_0zk_address(&self, chain_id: u64) -> String {
        use bech32::{Bech32m, Hrp};

        // Build data payload
        let mut data = Vec::with_capacity(73);

        // Version byte
        data.push(0x01);

        // Master public key (32 bytes BE)
        let mpk_bytes = self.master_public_key.into_bigint().to_bytes_be();
        data.extend_from_slice(&mpk_bytes);

        // Chain ID (8 bytes BE)
        data.extend_from_slice(&chain_id.to_be_bytes());

        // Viewing public key (32 bytes)
        data.extend_from_slice(self.viewing.public.as_bytes());

        // Determine HRP based on chain
        let hrp = match chain_id {
            1 => "0zk",
            11155111 => "0zks",
            137 => "0zkp",
            42161 => "0zka", // Arbitrum
            10 => "0zko",    // Optimism
            _ => "0zk",      // Default
        };

        let hrp = Hrp::parse(hrp).expect("valid HRP");
        bech32::encode::<Bech32m>(hrp, &data).expect("valid bech32m encoding")
    }

    /// Parse a 0zk address and extract components
    ///
    /// Returns (version, master_public_key, chain_id, viewing_public_key)
    pub fn parse_0zk_address(address: &str) -> Result<(u8, Field, u64, [u8; 32]), KeyError> {
        let (_hrp, data) =
            bech32::decode(address).map_err(|e| KeyError::MnemonicError(e.to_string()))?;

        if data.len() < 73 {
            return Err(KeyError::MnemonicError("Address too short".into()));
        }

        let version = data[0];
        if version != 0x01 {
            return Err(KeyError::MnemonicError(format!(
                "Unsupported version: {}",
                version
            )));
        }

        // Parse MPK
        let mpk = Field::from_be_bytes_mod_order(&data[1..33]);

        // Parse chain ID
        let chain_id = u64::from_be_bytes(data[33..41].try_into().unwrap());

        // Parse viewing public key
        let mut vpk = [0u8; 32];
        vpk.copy_from_slice(&data[41..73]);

        Ok((version, mpk, chain_id, vpk))
    }

    /// Compute note nullifier
    pub fn compute_nullifier(&self, note_commitment: Field) -> Field {
        crate::poseidon::poseidon2(note_commitment, self.nullifying_key)
    }
}

/// Shareable viewing key for view-only wallets
#[derive(Clone)]
pub struct ShareableViewingKey {
    /// Spending public key (Baby Jubjub point, packed)
    pub spending_public: BabyJubjubPoint,
    /// Viewing private key
    pub viewing_secret: [u8; 32],
}

impl ShareableViewingKey {
    /// Create from full wallet (for sharing)
    pub fn from_wallet(wallet: &RailgunWallet) -> Self {
        Self {
            spending_public: wallet.spending.public,
            viewing_secret: *wallet.viewing.secret.as_bytes(),
        }
    }

    /// Encode for sharing (msgpack format matching Railgun SDK)
    pub fn encode(&self) -> Vec<u8> {
        // Simplified encoding - in production use msgpack
        let mut bytes = Vec::with_capacity(96);

        // Pack spending public key (x, y as 32 bytes each)
        let x_bytes = self.spending_public.x.into_bigint().to_bytes_be();
        let y_bytes = self.spending_public.y.into_bigint().to_bytes_be();
        bytes.extend_from_slice(&x_bytes);
        bytes.extend_from_slice(&y_bytes);

        // Viewing secret
        bytes.extend_from_slice(&self.viewing_secret);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_base8_coordinates() {
        use ark_ec::AffineRepr;

        // Circomlib Base8 coordinates (from babyjub.js)
        let expected_x_circ =
            "5299619240641551281634865583518297030282874472190772894086521144482721001553";
        let expected_y_circ =
            "16950150798460657717958625567821834550301663161624707787222815936182638968203";

        let b8 = base8();

        // Base8 must be on the arkworks curve
        assert!(
            b8.is_on_curve(),
            "Base8 must be on arkworks Baby Jubjub curve"
        );

        // Convert from arkworks to circomlib coordinates
        let (x_circ, y_circ) = ark_to_circom_coords(b8.x, b8.y);
        let x_str = x_circ.into_bigint().to_string();
        let y_str = y_circ.into_bigint().to_string();

        // The circomlib coordinates should match
        assert_eq!(x_str, expected_x_circ, "Base8.x circomlib mismatch");
        assert_eq!(y_str, expected_y_circ, "Base8.y circomlib mismatch");
    }

    #[test]
    fn test_wallet_from_mnemonic() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let wallet = RailgunWallet::from_mnemonic(&mnemonic, 0).unwrap();

        // Keys should be non-zero
        assert!(!wallet.nullifying_key.is_zero());
        assert!(!wallet.master_public_key.is_zero());
    }

    #[test]
    fn test_wallet_deterministic() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();

        let wallet1 = RailgunWallet::from_mnemonic(&mnemonic, 0).unwrap();
        let wallet2 = RailgunWallet::from_mnemonic(&mnemonic, 0).unwrap();

        assert_eq!(wallet1.master_public_key, wallet2.master_public_key);
        assert_eq!(wallet1.nullifying_key, wallet2.nullifying_key);
    }

    #[test]
    fn test_different_indices() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();

        let wallet0 = RailgunWallet::from_mnemonic(&mnemonic, 0).unwrap();
        let wallet1 = RailgunWallet::from_mnemonic(&mnemonic, 1).unwrap();

        assert_ne!(wallet0.master_public_key, wallet1.master_public_key);
    }

    #[test]
    fn test_wallet_from_signature() {
        let fake_signature = [0x42u8; 65];
        let wallet = RailgunWallet::from_wallet_signature(&fake_signature).unwrap();

        assert!(!wallet.master_public_key.is_zero());

        // Should be deterministic
        let wallet2 = RailgunWallet::from_wallet_signature(&fake_signature).unwrap();
        assert_eq!(wallet.master_public_key, wallet2.master_public_key);
    }

    #[test]
    fn test_0zk_address_generation() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let wallet = RailgunWallet::from_mnemonic(&mnemonic, 0).unwrap();

        // Test mainnet address
        let addr = wallet.to_0zk_address(1);
        assert!(
            addr.starts_with("0zk1"),
            "Expected 0zk1 prefix, got: {}",
            addr
        );

        // Test Sepolia address
        let addr_sepolia = wallet.to_0zk_address(11155111);
        assert!(
            addr_sepolia.starts_with("0zks1"),
            "Expected 0zks1 prefix, got: {}",
            addr_sepolia
        );

        // Test roundtrip parsing
        let (version, mpk, chain_id, vpk) = RailgunWallet::parse_0zk_address(&addr).unwrap();
        assert_eq!(version, 0x01);
        assert_eq!(mpk, wallet.master_public_key);
        assert_eq!(chain_id, 1);
        assert_eq!(&vpk, wallet.viewing.public.as_bytes());
    }

    #[test]
    fn test_0zk_address_different_chains() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_MNEMONIC).unwrap();
        let wallet = RailgunWallet::from_mnemonic(&mnemonic, 0).unwrap();

        // Different chains should produce different addresses
        let addr_eth = wallet.to_0zk_address(1);
        let addr_polygon = wallet.to_0zk_address(137);
        let addr_sepolia = wallet.to_0zk_address(11155111);

        assert_ne!(addr_eth, addr_polygon);
        assert_ne!(addr_eth, addr_sepolia);
        assert_ne!(addr_polygon, addr_sepolia);

        // But they should all parse back correctly
        let (_, _, chain_eth, _) = RailgunWallet::parse_0zk_address(&addr_eth).unwrap();
        let (_, _, chain_polygon, _) = RailgunWallet::parse_0zk_address(&addr_polygon).unwrap();

        assert_eq!(chain_eth, 1);
        assert_eq!(chain_polygon, 137);
    }

    #[test]
    fn test_eddsa_signature_verification() {
        use ark_ec::AffineRepr;
        use num_bigint::BigUint;

        let sig = [0x42u8; 65];
        let wallet = RailgunWallet::from_wallet_signature(&sig).unwrap();

        // Random message to sign
        let message = Field::from(12345u64);

        // Sign the message
        let signature = wallet.spending.sign(message);

        // Baby Jubjub subOrder
        let sub_order = BigUint::parse_bytes(
            b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
            10,
        )
        .expect("valid subOrder");

        // Debug: print key info
        println!("=== EdDSA Debug ===");
        println!("raw_key: 0x{}", hex::encode(&wallet.spending.raw_key));
        println!(
            "blake_hash[0:32]: 0x{}",
            hex::encode(&wallet.spending.blake_hash[..32])
        );

        // Secret scalar (from raw bytes, NOT reduced mod scalar field)
        let secret_biguint = BigUint::from_bytes_le(&wallet.spending.secret_bytes);
        println!("secret (decimal): {}", secret_biguint);
        println!("secret mod subOrder: {}", &secret_biguint % &sub_order);
        println!("secret mod 8: {}", &secret_biguint % BigUint::from(8u64));

        // Secret >> 3 (what was used for public key derivation)
        let secret_shifted: BigUint = &secret_biguint >> 3;
        println!("secret >> 3 (decimal): {}", secret_shifted);

        println!(
            "public.x (ark): 0x{}",
            hex::encode(wallet.spending.public.x.into_bigint().to_bytes_le())
        );
        println!(
            "public.y (ark): 0x{}",
            hex::encode(wallet.spending.public.y.into_bigint().to_bytes_le())
        );
        println!("public on curve: {}", wallet.spending.public.is_on_curve());

        // Verify public key derivation: A = Base8 * (secret >> 3)
        let secret_shifted_scalar = BabyJubjubScalar::from_le_bytes_mod_order(&{
            let bytes = secret_shifted.to_bytes_le();
            let mut padded = [0u8; 32];
            let len = bytes.len().min(32);
            padded[..len].copy_from_slice(&bytes[..len]);
            padded
        });
        let expected_public = (base8() * secret_shifted_scalar).into_affine();
        println!(
            "expected public.x: 0x{}",
            hex::encode(expected_public.x.into_bigint().to_bytes_le())
        );
        println!(
            "expected public.y: 0x{}",
            hex::encode(expected_public.y.into_bigint().to_bytes_le())
        );
        assert_eq!(
            wallet.spending.public.x, expected_public.x,
            "Public key x mismatch"
        );
        assert_eq!(
            wallet.spending.public.y, expected_public.y,
            "Public key y mismatch"
        );
        println!("[OK] Public key derivation verified");

        println!("\n=== Signature Values ===");
        println!(
            "signature.r8_x: 0x{}",
            hex::encode(signature.r8_x.into_bigint().to_bytes_be())
        );
        println!(
            "signature.r8_y: 0x{}",
            hex::encode(signature.r8_y.into_bigint().to_bytes_be())
        );
        println!(
            "signature.s: 0x{}",
            hex::encode(signature.s.into_bigint().to_bytes_le())
        );

        let s_sig_biguint = BigUint::from_bytes_le(&signature.s.into_bigint().to_bytes_le());
        println!("signature.s (decimal): {}", s_sig_biguint);

        // Verify the signature using the same formula as the circuit:
        // S * Base8 == R8 + 8 * hm * A
        // where hm = Poseidon(R8.x, R8.y, A.x, A.y, message)

        let (ax, ay) = wallet.spending.public_xy();
        println!("\n=== Public Key (circomlib coords) ===");
        println!(
            "ax (Field): 0x{}",
            hex::encode(ax.into_bigint().to_bytes_le())
        );
        println!(
            "ay (Field): 0x{}",
            hex::encode(ay.into_bigint().to_bytes_le())
        );

        // Compute hm = Poseidon(R8.x, R8.y, A.x, A.y, message)
        let hm = crate::poseidon::poseidon_hash(&[signature.r8_x, signature.r8_y, ax, ay, message])
            .expect("5 inputs valid");
        println!("\n=== Hash ===");
        println!("hm: 0x{}", hex::encode(hm.into_bigint().to_bytes_le()));
        let hm_biguint = BigUint::from_bytes_le(&hm.into_bigint().to_bytes_le());
        println!("hm (decimal): {}", hm_biguint);

        // Convert to scalars for arithmetic
        // NOTE: signature.s is stored as BN254 Field, need to convert to Baby Jubjub scalar
        let s_scalar =
            BabyJubjubScalar::from_le_bytes_mod_order(&signature.s.into_bigint().to_bytes_le());
        let hm_scalar = BabyJubjubScalar::from_le_bytes_mod_order(&hm.into_bigint().to_bytes_le());

        println!("\n=== Verification ===");

        // Compute left side: S * Base8
        let left = (base8() * s_scalar).into_affine();
        println!("left = S * Base8: ({}, {})", left.x, left.y);
        println!("left on curve: {}", left.is_on_curve());

        // Compute R8 point from coordinates
        // NOTE: signature R8 is stored in CIRCOMLIB coordinates, need to convert to arkworks
        let r8_x_circ =
            BabyJubjubFq::from_be_bytes_mod_order(&signature.r8_x.into_bigint().to_bytes_be());
        let r8_y_circ =
            BabyJubjubFq::from_be_bytes_mod_order(&signature.r8_y.into_bigint().to_bytes_be());
        // Convert from circomlib to arkworks coordinates
        let (r8_x_ark, r8_y_ark) = circom_to_ark_coords(r8_x_circ, r8_y_circ);
        let r8 = BabyJubjubPoint::new_unchecked(r8_x_ark, r8_y_ark);
        println!("r8 (arkworks): ({}, {})", r8.x, r8.y);
        println!("r8 on curve: {}", r8.is_on_curve());

        // Compute 8 * hm * A
        // First compute 8 * hm
        let eight = BabyJubjubScalar::from(8u64);
        let eight_hm = eight * hm_scalar;
        println!(
            "8 * hm (scalar): 0x{}",
            hex::encode(eight_hm.into_bigint().to_bytes_le())
        );

        // Compute 8 * hm * A (using arkworks public key)
        let eight_hm_a = (wallet.spending.public.into_group() * eight_hm).into_affine();
        println!("8 * hm * A: ({}, {})", eight_hm_a.x, eight_hm_a.y);

        // Compute R8 + 8 * hm * A
        let right = (r8.into_group() + eight_hm_a.into_group()).into_affine();
        println!("right = R8 + 8*hm*A: ({}, {})", right.x, right.y);
        println!("right on curve: {}", right.is_on_curve());

        // Also verify the algebraic relationship:
        // S * Base8 should equal r * Base8 + hm * s * Base8
        // = R8 + hm * s * Base8
        // = R8 + hm * (8 * (s >> 3)) * Base8
        // = R8 + 8 * hm * ((s >> 3) * Base8)
        // = R8 + 8 * hm * A
        println!("\n=== Algebraic Check ===");

        // Compute hm * s * Base8 directly (need to use secret_bytes mod subOrder for scalar mult)
        let secret_scalar =
            BabyJubjubScalar::from_le_bytes_mod_order(&wallet.spending.secret_bytes);
        let hm_s = hm_scalar * secret_scalar;
        let hm_s_base8 = (base8() * hm_s).into_affine();
        println!("hm * s * Base8: ({}, {})", hm_s_base8.x, hm_s_base8.y);

        // This should equal 8 * hm * A
        println!("8 * hm * A:     ({}, {})", eight_hm_a.x, eight_hm_a.y);

        // Check if hm * s == 8 * hm * (s >> 3)
        let s_mod = &secret_biguint % &sub_order;
        let shifted_mod = &secret_shifted % &sub_order;
        println!("\nChecking: s == 8 * (s >> 3)?");
        println!("s mod subOrder:             {}", s_mod);
        println!(
            "8 * (s >> 3) mod subOrder:  {}",
            (BigUint::from(8u64) * &shifted_mod) % &sub_order
        );

        // The key insight: s is pruned so bottom 3 bits are 0
        // Therefore s = 8 * (s >> 3) exactly (no mod needed for equality)
        let s_from_shift = BigUint::from(8u64) * &secret_shifted;
        println!("8 * (s >> 3) (no mod):      {}", s_from_shift);
        println!("s (no mod):                 {}", secret_biguint);
        assert_eq!(
            secret_biguint, s_from_shift,
            "s should equal 8 * (s >> 3) due to pruning"
        );
        println!("[OK] s == 8 * (s >> 3) verified");

        // Verify left == right
        assert_eq!(left.x, right.x, "EdDSA verification failed: x mismatch");
        assert_eq!(left.y, right.y, "EdDSA verification failed: y mismatch");
        println!("[OK] EdDSA signature verified correctly!");
    }

    #[test]
    fn test_coordinate_roundtrip() {
        // Test that coordinate transformation is its own inverse
        use ark_ec::AffineRepr;

        let b8 = base8();
        assert!(b8.is_on_curve(), "Base8 not on arkworks curve");

        // arkworks -> circomlib -> arkworks
        let (x_circ, y_circ) = ark_to_circom_coords(b8.x, b8.y);
        let (x_ark2, y_ark2) = circom_to_ark_coords(x_circ, y_circ);

        assert_eq!(b8.x, x_ark2, "x coordinate roundtrip failed");
        assert_eq!(b8.y, y_ark2, "y coordinate roundtrip failed");
        println!("[OK] Coordinate roundtrip test passed");
    }

    #[test]
    fn test_scalar_mul_consistency() {
        // Test that scalar multiplication is consistent with coordinate transformation
        use ark_ec::AffineRepr;

        let b8 = base8();
        let scalar = BabyJubjubScalar::from(12345u64);

        // Compute P = scalar * Base8 in arkworks
        let p_ark = (b8 * scalar).into_affine();
        assert!(p_ark.is_on_curve(), "Result not on curve");

        // Convert to circomlib and back
        let (px_circ, py_circ) = ark_to_circom_coords(p_ark.x, p_ark.y);
        let (px_ark2, py_ark2) = circom_to_ark_coords(px_circ, py_circ);
        let p_ark2 = BabyJubjubPoint::new_unchecked(px_ark2, py_ark2);

        assert_eq!(p_ark, p_ark2, "Scalar mul + roundtrip failed");
        println!("[OK] Scalar multiplication consistency test passed");
    }
}
