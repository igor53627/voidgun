# EdDSA Implementation for Circomlib Compatibility

This document describes the EdDSA signature implementation in `railgun-lane` that is compatible with circomlib's Poseidon-based EdDSA variant used in Railgun circuits.

## Overview

Railgun uses EdDSA signatures on the Baby Jubjub curve with Poseidon hashing. The implementation must match circomlib's `eddsa.js` exactly for circuit compatibility.

## Key Derivation

### From Raw Key Bytes

```
raw_key (32 bytes)
    │
    ▼
blake512(raw_key) → h (64 bytes)
    │
    ▼
pruneBuffer(h[0:32]) → s (pruned secret)
    │
    ├──────────────────────────────────┐
    ▼                                  ▼
s >> 3 → shifted                    s (for signing)
    │
    ▼
Base8 * shifted → A (public key)
```

### Pruning Rules

The `pruneBuffer` function ensures the secret scalar has specific properties:

```rust
fn prune_buffer(buf: &mut [u8; 32]) {
    buf[0] &= 0xF8;  // Clear bottom 3 bits (divisible by 8)
    buf[31] &= 0x7F; // Clear bit 255
    buf[31] |= 0x40; // Set bit 254
}
```

This guarantees:
- `s mod 8 = 0` (bottom 3 bits are zero)
- `s = 8 * (s >> 3)` exactly (no modular arithmetic needed)
- The scalar is in a safe range for cofactor handling

## Signature Generation

### Equation

```
S = r + hm * s (mod subOrder)
```

Where:
- `r` = deterministic nonce from `blake512(h[32:64] || message) mod subOrder`
- `hm` = `Poseidon(R8.x, R8.y, A.x, A.y, message)`
- `s` = full pruned secret (NOT reduced mod scalar field)
- `subOrder` = Baby Jubjub subgroup order = `2736030358979909402780800718157159386076813972158567259200215660948447373041`

### R8 Computation

```
R8 = r * Base8
```

The R8 point coordinates are output in **circomlib format** for the circuit.

## Signature Verification

### Equation (used by circuit)

```
S * Base8 == R8 + 8 * hm * A
```

This works because:
1. `S * Base8 = (r + hm * s) * Base8 = r * Base8 + hm * s * Base8`
2. `= R8 + hm * s * Base8`
3. Since `s = 8 * (s >> 3)`: `= R8 + hm * 8 * (s >> 3) * Base8`
4. Since `A = (s >> 3) * Base8`: `= R8 + 8 * hm * A`

## Curve Coordinate Transformation

### The Problem

Circomlib and arkworks use different Baby Jubjub parameterizations:

| Library   | Curve Equation                    | Parameters |
|-----------|-----------------------------------|------------|
| circomlib | `A*x² + y² = 1 + D*x²*y²`        | A=168700, D=168696 |
| arkworks  | `x² + y² = 1 + d*x²*y²`          | d = D/A |

### The Solution

The curves are isomorphic via:

```
circomlib → arkworks:  (x_c, y_c) → (sqrt(A) * x_c, y_c)
arkworks → circomlib:  (x_a, y_a) → (x_a / sqrt(A), y_a)
```

Where `sqrt(168700) mod p = 7214280148105020021932206872019688659210616427216992810330019057549499971851`

### Implementation

```rust
fn ark_to_circom_coords(x_ark: Fq, y_ark: Fq) -> (Fq, Fq) {
    (x_ark * inv_sqrt_a(), y_ark)
}

fn circom_to_ark_coords(x_circ: Fq, y_circ: Fq) -> (Fq, Fq) {
    (x_circ * sqrt_a(), y_circ)
}
```

## Critical Implementation Detail: Secret Storage

### The Bug (Fixed)

The original implementation stored the secret as a `BabyJubjubScalar`:

```rust
// WRONG - reduces mod scalar field order
let secret = BabyJubjubScalar::from_le_bytes_mod_order(&s_bytes);
```

This reduced the pruned value modulo the scalar field order, potentially changing the bottom 3 bits and breaking the `s = 8 * (s >> 3)` identity.

### The Fix

Store the secret as raw bytes:

```rust
pub struct SpendingKey {
    pub secret_bytes: [u8; 32],  // Raw pruned bytes, NOT reduced
    // ...
}
```

Use `BigUint` for arithmetic, only converting to scalar for curve operations:

```rust
let s_biguint = BigUint::from_bytes_le(&self.secret_bytes);
let s_sig = (&r_mod + (&hm_biguint * &s_biguint) % &sub_order) % &sub_order;
```

## Test Vectors

The implementation is verified against:
1. `test_eddsa_signature_verification` - Rust verification of the EdDSA equation
2. `test_proof_verification` - R1CS constraint satisfaction with circuit WASM
3. `test_e2e_auto_vnet` - On-chain verification against deployed Railgun contracts

## References

- [circomlibjs eddsa.js](https://github.com/iden3/circomlibjs/blob/main/src/eddsa.js)
- [circomlibjs babyjub.js](https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js)
- [Railgun circuits-v2](https://github.com/Railgun-Community/circuits-v2)
