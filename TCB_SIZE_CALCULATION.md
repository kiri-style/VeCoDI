# Trust Computation Base (TCB) Size Calculation

## Overview
The TCB consists of all cryptographic parameters, sealing data, and authorization state stored in the **Secure partition** (TF-M) that must be protected to ensure end-to-end integrity of the VeCoDI authentication protocol.

---

## 1. Session & Authentication State (Secure Partition)

### 1.1 ECDH Session Key
```c
secure_session_key[32]              // 32 bytes
Session encryption key derived from ECDH handshake
Purpose: Decrypt M_update messages, secure key material exchange
```
**Size: 32 bytes**

### 1.2 ECDH Session State Flags
```c
secure_session_key_set       // 1 byte (bool)
```
**Size: 1 byte**

---

## 2. Authorization State (M_update)

### 2.1 Provider Authorization (s_pk_v, s_model_id, s_cert)
```c
s_pk_v[64]                   // 64 bytes - ECDSA P-256 provider public key
s_model_id                   // 4 bytes  - Model ID bound to this authorization
s_cert[128]                  // 128 bytes - Provider certificate (encrypted/signed)
s_cert_len                   // 4 bytes  - Certificate length
s_auth_valid                 // 1 byte (bool) - Authorization state flag
```
**Size: 64 + 4 + 128 + 4 + 1 = 201 bytes**

### 2.2 Counter Authorization
```c
last_accepted_counter_limit  // 4 bytes - Anti-replay for M_update (strictly increasing)
```
**Size: 4 bytes**

---

## 3. Model Identity Context (Secure)

### 3.1 Model Cryptographic Material
```c
current_model_pub[32]        // 32 bytes - Model public key component
current_model_secret[32]     // 32 bytes - Model secret (derived from early weights hash)
current_code_hash[32]        // 32 bytes - SHA-256 of inference code
current_model_id             // 4 bytes  - Model identifier
current_model_info_valid     // 1 byte (bool)
current_model_secret_valid   // 1 byte (bool)
```
**Size: 32 + 32 + 32 + 4 + 1 + 1 = 102 bytes**

---

## 4. EnclaveInfo & Boot Trust

### 4.1 Runtime EnclaveInfo
```c
current_enclave_info[32]     // 32 bytes - SHA-256 hash of (model_id||code||weights)
current_enclave_info_valid   // 1 byte (bool)
```
**Size: 32 + 1 = 33 bytes**

### 4.2 Boot-Time Sealed EnclaveInfo
```c
boot_enclave_info[32]        // 32 bytes - Reference hash for attestation validation
boot_enclave_info_valid      // 1 byte (bool)
```
**Size: 32 + 1 = 33 bytes**

---

## 5. Enclave Lifecycle State

### 5.1 Counter Management
```c
inference_counter_secure            // 4 bytes - Current inference count (protected)
max_inferences_per_enclave_secure   // 4 bytes - Policy limit (from M_update)
enclave_created_secure              // 1 byte (bool) - Enclave valid flag
```
**Size: 4 + 4 + 1 = 9 bytes**

---

## 6. Device Cryptographic Keys & Transactions

### 6.1 Device Signing Key (PSA Crypto Handle)
```c
s_device_sign_key_id         // 4 bytes - Internal PSA key handle (not directly stored)
s_device_pubkey[65]          // 65 bytes - ECDSA P-256 uncompressed point (04 || x || y)
s_device_key_ready           // 1 byte (bool)
```
**Size: 4 + 65 + 1 = 70 bytes**
*(Note: actual key material is managed by PSA Crypto service, handle is reference only)*

### 6.2 Inference Transaction State
```c
s_tx_active                  // 1 byte (bool) - Transaction window open
s_tx_id                      // 4 bytes - Transaction identifier
s_tx_nonce[32]               // 32 bytes - Transaction nonce for PoX signing
s_tx_model_id                // 4 bytes - Model bound to current transaction
```
**Size: 1 + 4 + 32 + 4 = 41 bytes**

---

## 7. SAU (Secure Attribution Unit) Window Registration

### 7.1 ROM Model Window
```c
sau_rom_base                 // 4 bytes - Base address of model ROM
sau_rom_size                 // 4 bytes - Size of model ROM
sau_rom_registered           // 1 byte (bool)
```
**Size: 4 + 4 + 1 = 9 bytes**

### 7.2 Code Window
```c
sau_code_base                // 4 bytes - Base address of inference code
sau_code_size                // 4 bytes - Size of inference code
sau_code_registered          // 1 byte (bool)
```
**Size: 4 + 4 + 1 = 9 bytes**

---

## 8. Model Identity Defaults & State Flags

### 8.1 Default Configuration
```c
default_model_id             // 4 bytes - Fallback model ID (const)
```
**Size: 4 bytes**

---

## TOTAL TCB CALCULATION

| Component | Size (bytes) | Justification |
|-----------|-------------|---|
| **1. ECDH Session** | 33 | Session key + flag |
| **2. M_update Auth State** | 205 | Provider key, cert, counter anti-replay |
| **3. Model Identity Context** | 102 | Model secret, code hash, validation flags |
| **4. EnclaveInfo & Boot Trust** | 66 | Runtime + boot seals, validity flags |
| **5. Enclave Lifecycle** | 9 | Counter + policy limits + enclave flag |
| **6. Device Keys & Transactions** | 111 | Device pubkey, transaction state |
| **7. SAU Window Registration** | 18 | ROM + code window metadata |
| **8. Defaults & Configuration** | 4 | Model ID fallback |
| | | |
| **TOTAL SECURE PARTITION TCB** | **548 bytes** | Direct protected state only |

---

## Non-Secure TCB Components

Additional items stored in **Non-Secure RAM** that bind to Secure state:

| Component | Size (bytes) | Purpose |
|-----------|-------------|---|
| ECDH ephemeral keys (temporary) | ~100 | Handshake only, not persistent |
| M_update plaintext (temporary) | ~50 | Decrypted during validation only |
| PoX structure buffer | 100 | Transaction-local proof |
| **NS TCB Metadata (persistent)** | ~20 | Protocol state flags |
| | |
| **Subtotal (Non-Secure Persistent only)** | ~20 | |

---

## Extended TCB: Cryptographic Material in PSA Crypto Service

The PSA Crypto library may also manage:
- Device private signing key (32 bytes) - ECC P-256
- ECDH ephemeral private key (32 bytes) - temporary, cleared after handshake
- PSA key material storage (~256 bytes estimated) - implementation-dependent

**Estimated extended TCB with crypto service: +256 bytes**

---

## Total VeCoDI TCB Size Summary

```
┌─────────────────────────────────────────┐
│ SECURE PARTITION (confirmed)    548 B   │
│ NON-SECURE PERSISTENT metadata  ~20 B   │
│ PSA CRYPTO SERVICE (estimated) ~256 B   │
├─────────────────────────────────────────┤
│ TOTAL TCB (dynamic)            ~824 B   │
│ TOTAL TCB (with PSA overhead)  ~1 KB    │
└─────────────────────────────────────────┘
```

---

## Critical Observations

### 1. **Largest Contributors**
   - M_update auth state: 205 bytes (37% of Secure TCB)
   - Device pubkey: 65 bytes (12%)
   - Session key + model material: 65 bytes (12%)

### 2. **Anti-Replay Protection**
   - `last_accepted_counter_limit`: Enforces strictly increasing c_limit
   - Prevents replaying old M_update messages

### 3. **Model Binding**
   - `current_model_secret` + `current_enclave_info`: Binds specific model to authorization
   - `current_code_hash`: Detects code tampering

### 4. **Transaction Isolation**
   - `s_tx_*` state: Prevents concurrent inference transactions
   - Nonce-based replay protection for PoX signatures

### 5. **Memory Hotspots**
   - Most TCB is small structs/flags (4-64 bytes each)
   - No large buffers in persistent TCB (temporary buffers are cleared)
   - Fits entirely in STM32L552 Secure RAM (64 KB available)

---

## Verification Checklist

- [x] ECDH session key isolated in Secure partition?
- [x] M_update policy strictly validated before acceptance?
- [x] Model secret bound to EnclaveInfo attestation?
- [x] Counter limits strictly increasing (anti-replay)?
- [x] Device key uniquely identifies enclave device?
- [x] SAU windows registered for integrity binding?
- [x] Transaction nonce prevents PoX replay?
- [x] All TCB fits in secure SRAM without overflow?

