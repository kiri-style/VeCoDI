# Dummy Partition (TF-M Secure Service)

## Version Information

```
Zephyr:     commit 61a8648c2cc6bbec9af368a96ecae87d6798e7fe (HEAD -> main)
TF-M:       commit 04aa7243e04946b5422b124bea9c0675ab6b120f (HEAD, manifest-rev)
Updated:    5 March 2026
Platform:   STM32L552ZE-Q with ARM Cortex-M33 TrustZone
```

## ✅ VERIFICATION STATUS: **ALL FEATURES VERIFIED ON HARDWARE**

**Date**: 27 February 2026  
**Platform**: STM32L552ZE-Q  
**See**: [../md/VERIFICATION_REPORT.md](../md/VERIFICATION_REPORT.md) for complete test results

---

## Overview
This TF-M secure partition provides cryptographic services for the Non-Secure (NS) app:
- **Encrypted weight decryption** (AES-CTR)
- **Secure counter management** (inference authorization)
- **EnclaveInfo computation** (SHA-256) ✅ Verified
- **M_update validation** (AES-256-GCM decrypt + verify) ✅ Verified
- **Benchmark services** (DWT cycle counting)

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

**Secure Counter Management (ATOMIC - Verified 27 Feb 2026):**
- `DP_CMD_GET_MAX_INFERENCES = 4` (returns **dynamic** max_inferences_per_enclave) ✅
- `DP_CMD_CHECK_INFERENCE_ALLOWED = 5` (returns 1 if allowed, 0 if limit reached)
- `DP_CMD_INCREMENT_COUNTER = 6` (increments inference_counter_secure)
- `DP_CMD_RUN_INFERENCE = 9` **(NEW ATOMIC OPERATION)**: atomically checks counter < **max_inferences_per_enclave** and increments in one Secure call
- `DP_CMD_RESET_COUNTER = 7` (resets counter to 0 during enclave creation)

**Enclave Authorization Protocol (Verified 27 Feb 2026):**
- `DP_CMD_COMPUTE_ENCLAVE_INFO = 10` ✅ (SHA-256 hash of Model_pub || Model_secret || code || model_ID)
- `DP_CMD_VALIDATE_M_UPDATE = 11` ✅ (AES-256-GCM decrypt, EnclaveInfo verify, anti-replay, atomic policy update)

**Benchmark & Diagnostics (NEW):**
- `DP_CMD_GET_BENCHMARK = 8` (retrieves Secure-side performance metrics and memory usage)

**Security Policy:**
- `max_inferences_per_enclave` is **dynamic** (starts at 0, updated on valid M_update)
- `inference_counter_secure = 0` (protected counter in Secure world)
- Counter incremented **BEFORE** inference execution (atomic operation)

## Benchmark System (Dual-World DWT Monitoring)

### Secure-Side Metrics (4 measurements)
Via `DP_CMD_GET_BENCHMARK` command:

1. **AES-CTR Decryption**: Cycles to decrypt late weights
2. **Counter Management**: Cycles for atomic check+increment operation
3. **Memory Usage**: RAM and Flash consumption in Secure partition

### ARM Cortex-M33 DWT Integration
Both NS and Secure worlds use ARM's Data Watchpoint and Trace (DWT) cycle counter:
```
- DEMCR register: TRCENA bit enables DWT
- DWT_CTRL: CYCCNTENA bit enables cycle counter
- DWT_CYCCNT: 32-bit counter @ 110 MHz (wraps at ~39 seconds)
- Conversion: cycles / 110MHz = time in seconds; divide by 1000 for ms
```

### Secure-Side Implementation Details
- **File**: `dummy_partition/secure_benchmark.c/h`
- **Memory Calculation**: Hardcoded from linker output (linker symbols unavailable in TF-M)
  - Secure RAM: 52,732 bytes (from build log analysis)
  - Secure Flash: 119,532 bytes (from TFM partition layout)
- **Start/Stop Pattern**: Save DWT_CYCCNT at operation start, read at end, compute difference
- **All Timing**: Includes PSA call overhead (minimal in Secure world)

## Current Flow (Late Weights + Counter + Benchmark)

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

### 2. Counter Management Flow (cmd=4,5,6,7)

**Get Policy (cmd=4):**
```
in_vec[0] = cmd (DP_CMD_GET_MAX_INFERENCES)
out_vec[0] = max_inferences (uint32_t, returns dynamic value)
```

**Check Allowed (cmd=5):**
```
in_vec[0] = cmd (DP_CMD_CHECK_INFERENCE_ALLOWED)
out_vec[0] = allowed (uint32_t, 1=allowed, 0=denied)
```
Secure logic: `allowed = (inference_counter_secure < max_inferences_per_enclave) ? 1 : 0`

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
5. NS runs `run_split_inference()` in `src/split_inference.cpp` using the decrypted weights.

## Architecture (Current)
```
Non-Secure app                              Secure world (TF-M)
┌────────────────────────────┐             ┌────────────────────────────┐
│ psa_call(SID=0xFFFFF002)   │  IPC        │ tfm_dp_req_mngr_init()      │
│  in_vec[0]=cmd (u32)        │───────────► │  └─ tfm_dp_secret_digest_ipc│
│  in_vec[1]=payload #1       │             │     ├─ secret digest       │
│  in_vec[2]=payload #2       │             │     └─ AES-CTR decrypt     │
│  out_vec[0]=output buffer   │◄────────────┤        (writes to out_vec) │
│                            │             └────────────────────────────┘
│ run_split_inference()      │
│  └─ early + late layers    │
└────────────────────────────┘
```

The partition only waits on `TFM_DP_SECRET_DIGEST_SIGNAL` and routes all
commands through `tfm_dp_secret_digest_ipc()`.

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
- The secure partition focuses on **decryption and policy checks**; it does not execute NS-side integrity-hash functions.
- For production: Consider adding **HMAC verification** in secure partition before decryption to ensure encrypted weights haven't been tampered with.

