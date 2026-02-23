#+#+#+#+
# Dummy Partition (TF-M Secure Service)

## Overview
This TF-M secure partition provides cryptographic services for the Non-Secure (NS) app. In the current flow it **decrypts encrypted late-layer weights** and writes them into an NS RAM buffer via PSA IPC.

## Key Paths (Secure World)
- `dummy_partition/dummy_partition.c`: command dispatcher + AES-CTR decryption implementation
- `dummy_partition/secure_nsc_interface.c`: Secure→Non-Secure bridge for debugging enclave transitions (CMSE NSC entry point)
- `dummy_partition/tfm_dummy_partition.yaml`: TF-M service manifest (SID, IPC model)
- `dummy_partition/tfm_manifest_list.yaml.in`: manifest list included by build system

## Service Identity
Defined in [tfm_dummy_partition.yaml](tfm_dummy_partition.yaml):

- **SID**: `0xFFFFF002`
- **Version**: `1`
- **Connection-based**: yes

## Commands
Defined in [dummy_partition.c](dummy_partition.c):

**Cryptographic Services:**
- `DP_CMD_SECRET_DIGEST = 0` (legacy SHA-256 digest)
- `DP_CMD_DECRYPT_MODEL = 2` (deprecated, returns NOT_SUPPORTED)
- `DP_CMD_DECRYPT_LATE_WEIGHTS = 3` (AES-CTR decrypt late weights)

**Secure Counter Management (NEW):**
- `DP_CMD_GET_MAX_INFERENCES = 4` (returns MAX_INFERENCES_PER_ENCLAVE policy)
- `DP_CMD_CHECK_INFERENCE_ALLOWED = 5` (returns 1 if allowed, 0 if limit reached)
- `DP_CMD_INCREMENT_COUNTER = 6` (increments inference_counter_secure)
- `DP_CMD_RESET_COUNTER = 7` (resets counter to 0 during enclave creation)

**Security Policy:**
- `MAX_INFERENCES_PER_ENCLAVE = 3` (immutable, Secure-side constant)
- `inference_counter_secure = 0` (protected counter in Secure world)

## Current Flow (Late Weights + Counter + Hash)

### 1. Decryption Flow (cmd=3)
NS calls `psa_call()` with:

```
in_vec[0] = cmd (DP_CMD_DECRYPT_LATE_WEIGHTS)
in_vec[1] = encrypted late weights (flash)
in_vec[2] = IV (16 bytes)
out_vec[0] = NS RAM buffer (decrypted output)
```

The secure partition:
1. Sets up **AES-128-CTR** with PSA Crypto
2. Applies the IV from `in_vec[2]`
3. Decrypts in chunks using `psa_cipher_update()`
4. Writes plaintext into the NS output buffer

**Post-decryption (NS side):**
5. NS calls `precompute_late_weights_hash()` to compute SHA-256 of:
   - Code pointers (early weight addresses)
   - Decrypted late weights (wt_conv2d_7, wt_conv2d_8, wt_fc)
6. Stores 32-byte hash for reuse in per-inference integrity verification

### 2. Counter Management Flow (cmd=4,5,6,7)

**Get Policy (cmd=4):**
```
in_vec[0] = cmd (DP_CMD_GET_MAX_INFERENCES)
out_vec[0] = max_inferences (uint32_t, returns 3)
```

**Check Allowed (cmd=5):**
```
in_vec[0] = cmd (DP_CMD_CHECK_INFERENCE_ALLOWED)
out_vec[0] = allowed (uint32_t, 1=allowed, 0=denied)
```
Secure logic: `allowed = (inference_counter_secure < MAX_INFERENCES_PER_ENCLAVE) ? 1 : 0`

**Increment Counter (cmd=6):**
```
in_vec[0] = cmd (DP_CMD_INCREMENT_COUNTER)
```
Secure logic: `inference_counter_secure++` (no output)

**Reset Counter (cmd=7):**
```
in_vec[0] = cmd (DP_CMD_RESET_COUNTER)
```
Secure logic: `inference_counter_secure = 0` (called during enclave creation)

**Security Properties:**
- Counter state protected in Secure world
- All operations logged to Secure console
- NS cannot bypass limit checks
- Automatic enclave refresh via destroy→recreate pattern

## End-to-End Path (What Runs)
1. NS app calls `create_enclave()` in `src/create_enclave.cpp`.
2. NS packages `{cmd, encrypted_weights, iv}` and calls PSA IPC.
3. TF-M routes the request to `dummy_partition.c` (this file).
4. AES-CTR decrypts encrypted weights and writes plaintext to the NS buffer.
5. **[NEW]** NS calls `precompute_late_weights_hash()` to compute SHA-256(code_ptrs || late_weights) → stores 32-byte hash.
6. NS runs `run_split_inference()` in `src/split_inference.cpp` using the decrypted weights.
7. **[NEW]** For each test image, `compute_integrity_hash()` computes SHA-256(input || early_wt || late_hash).

### Integrity Hash Architecture Integration

**Phase 1: Setup (after decryption)**
```
Secure World (TF-M)                NS World (Zephyr)
─────────────────                  ────────────────
                                   create_enclave()
                                     │
AES-CTR decrypt ◄────PSA IPC────────┤
writes to NS RAM                     │
                                     ├─► set_late_weights_buffer()
                                     │
                                     └─► precompute_late_weights_hash()
                                          SHA-256(code_ptrs || late_wt)
                                          → late_weights_hash[32]
```

**Phase 2: Inference (per image)**
```
NS World (Zephyr)
────────────────
run_split_inference()
  │
  ├─► compute_integrity_hash()
  │     SHA-256(input || early_wt || late_hash)
  │     → inference_hash[32]
  │
  ├─► early layers (CMSIS-NN)
  └─► late layers (CMSIS-NN, using decrypted weights)
```

**Security benefit:** Late weights (40KB) are hashed once after secure decryption, then the 32-byte hash is reused for all subsequent inferences. This ensures:
- Complete coverage: input + code + early weights + late weights
- Performance: 49% hash time reduction vs. naive approach
- Tamper detection: Any modification to decrypted weights changes the hash

## Architecture (Current with Hash Integration)
```
Non-Secure app                              Secure world (TF-M)
┌────────────────────────────┐             ┌────────────────────────────┐
│ psa_call(SID=0xFFFFF002)   │  IPC        │ tfm_dp_req_mngr_init()      │
│  in_vec[0]=cmd (u32)        │───────────► │  └─ tfm_dp_secret_digest_ipc│
│  in_vec[1]=payload #1       │             │     ├─ secret digest       │
│  in_vec[2]=payload #2       │             │     └─ AES-CTR decrypt     │
│  out_vec[0]=output buffer   │◄────────────┤        (writes to out_vec) │
│                            │             └────────────────────────────┘
│ [After decryption]          │
│ precompute_late_weights_hash() → Phase 1: SHA-256(code+late) → 32 bytes│
│                            │
│ run_split_inference()      │
│  └─ compute_integrity_hash() → Phase 2: SHA-256(input+early+late_hash) │
└────────────────────────────┘
```

The partition only waits on `TFM_DP_SECRET_DIGEST_SIGNAL` and routes all
commands through `tfm_dp_secret_digest_ipc()`. 

After secure decryption, the NS side computes a **two-phase integrity hash**:
- **Phase 1 (once):** Hash code addresses and decrypted late weights
- **Phase 2 (per inference):** Hash input, early weights, and pre-computed late hash 

After secure decryption, the NS side computes a **two-phase integrity hash**:
- **Phase 1 (once):** Hash code addresses and decrypted late weights
- **Phase 2 (per inference):** Hash input, early weights, and pre-computed late hash

## IPC Protocol (Current)

### Common
- `in_vec[0]`: `cmd` (`uint32_t`) - always required
- `in_vec[1]`: payload buffer (meaning depends on `cmd`)
- `in_vec[2]`: payload buffer (only used by decrypt flow; 16-byte IV)
- `out_vec[0]`: output buffer (meaning depends on `cmd`)
- All lengths are taken from `msg->in_size[]` / `msg->out_size[]`

### Counter Management Commands

#### `DP_CMD_GET_MAX_INFERENCES` (4)
- **Purpose**: Get maximum inferences per enclave policy
- **Input**: `in_vec[0]` = cmd (4)
- **Output**: `out_vec[0]` = max_inferences (`uint32_t`, returns 3)
- **Notes**: Policy is immutable, defined as `MAX_INFERENCES_PER_ENCLAVE = 3`

#### `DP_CMD_CHECK_INFERENCE_ALLOWED` (5)
- **Purpose**: Check if current counter allows inference
- **Input**: `in_vec[0]` = cmd (5)
- **Output**: `out_vec[0]` = allowed (`uint32_t`, 1=allowed, 0=denied)
- **Logic**: Returns 1 if `counter < max`, else 0
- **Logging**: "[SECURE] Check inference allowed: counter=X, max=3, allowed=Y"

#### `DP_CMD_INCREMENT_COUNTER` (6)
- **Purpose**: Increment counter after successful inference
- **Input**: `in_vec[0]` = cmd (6)
- **Output**: None (void operation)
- **Logic**: `inference_counter_secure++`
- **Logging**: "[SECURE] Inference counter incremented: X"

#### `DP_CMD_RESET_COUNTER` (7)
- **Purpose**: Reset counter to 0 during enclave creation
- **Input**: `in_vec[0]` = cmd (7)
- **Output**: None (void operation)
- **Logic**: `inference_counter_secure = 0`
- **Logging**: "[SECURE] Inference counter reset to 0"

### `DP_CMD_SECRET_DIGEST`
- **Purpose**: SHA-256 digest of a fixed secret.
- **Input**:
	- `in_vec[0]`: `cmd` (`DP_CMD_SECRET_DIGEST`)
	- `in_vec[1]`: `secret_index` (`uint32_t`, 0..4)
- **Output**:
	- `out_vec[0]`: 32-byte digest buffer
- **Notes**:
	- The partition temporarily reconfigures SAU to allow NS access to SRAM1.
	- The first digest byte is overwritten with `0x75` before returning.

### `DP_CMD_DECRYPT_LATE_WEIGHTS` (current flow)
- **Purpose**: AES-128-CTR decrypt encrypted late weights into NS RAM.
- **Input**:
	- `in_vec[0]`: `cmd` (`DP_CMD_DECRYPT_LATE_WEIGHTS`)
	- `in_vec[1]`: ciphertext (late weights)
	- `in_vec[2]`: IV (16 bytes)
- **Output**:
	- `out_vec[0]`: plaintext buffer

### `DP_CMD_DECRYPT_MODEL` (deprecated)
- **Purpose**: legacy full-model decrypt.
- **Current behavior**: always returns `PSA_ERROR_NOT_SUPPORTED`.

## Crypto Details
- **Algorithm**: AES-128-CTR
- **Key**: static 16-byte key in `dummy_partition.c` (demo-only)
- **IV**: provided by NS via `late_wt_iv[]`

> For production: move keys to secure storage (ITS/PS), add integrity (AEAD/HMAC), and rotate keys.

## Files
- [dummy_partition.c](dummy_partition.c): command routing + AES-CTR decrypt
- [secure_nsc_interface.c](secure_nsc_interface.c): Secure→NS bridge using CMSE (debug/bring-up helper)
- [tfm_dummy_partition.yaml](tfm_dummy_partition.yaml): TF-M service manifest
- [tfm_manifest_list.yaml.in](tfm_manifest_list.yaml.in): manifest list for build

## Notes
- Legacy model decryption is removed; `DP_CMD_DECRYPT_MODEL` returns `PSA_ERROR_NOT_SUPPORTED`.
- The secure partition focuses on **decryption only**; integrity verification is handled by NS hash computation.
- For production: Consider adding **HMAC verification** in secure partition before decryption to ensure encrypted weights haven't been tampered with.

## Hash System Integration

The dummy partition's decryption service is **phase 0** in the complete integrity verification flow:

**Phase 0 (Secure):** Decrypt late weights via AES-CTR (this partition)  
**Phase 1 (NS):** Hash code + decrypted late weights → `late_weights_hash[32]`  
**Phase 2 (NS):** Hash input + early weights + late_hash → `inference_hash[32]`

This architecture ensures:
1. **Separation of concerns:** Secure world handles decryption, NS handles hash measurement
2. **Performance:** Large weights (40KB) hashed once after decryption
3. **Flexibility:** NS can implement different hash policies without secure partition changes

For complete hash architecture details, see [HASH_ARCHITECTURE.md](../HASH_ARCHITECTURE.md).

## Notes
Legacy model decryption is removed; `DP_CMD_DECRYPT_MODEL` returns `PSA_ERROR_NOT_SUPPORTED`.

