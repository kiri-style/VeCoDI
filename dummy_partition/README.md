# Dummy Partition (TF-M Secure Service)

## Version Information

```
Zephyr:     commit 61a8648c2cc6bbec9af368a96ecae87d6798e7fe (HEAD -> main)
TF-M:       commit 04aa7243e04946b5422b124bea9c0675ab6b120f (HEAD, manifest-rev)
Updated:    5 March 2026
Platform:   STM32L552ZE-Q with ARM Cortex-M33 TrustZone
```

## Verification
The current source implements the authorization and inference message handling described below. A hardware verification report is not included in this repository.

---

## Overview
This TF-M secure partition provides cryptographic services for the Non-Secure (NS) app:
- **Encrypted weight decryption** (AES-CTR)
- **Secure counter management** (inference authorization)
- **EnclaveInfo computation** (SHA-256) ✅ Verified
- **M_update authorization** (plaintext ECDSA-signed request verification)
- **Benchmark services** (DWT cycle counting)
- **Boot-time EnclaveInfo sealing** and **current-vs-boot integrity validation** before enclave creation

## Key Paths (Secure World)
- `dummy_partition.c`: command dispatcher, authorization checks, and AES-CTR weight decryption
- `secure_nsc_interface.c`: Secure→Non-Secure bridge for enclave transitions (CMSE NSC entry point)
- `tfm_dummy_partition.yaml`: TF-M service manifest (SID, IPC model)
- `tfm_manifest_list.yaml.in`: manifest list included by build system

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
- `DP_CMD_DECRYPT_LATE_WEIGHTS = 3` (internal helper used by create flow; command endpoint not exposed)

**Secure Counter / Lifecycle Management:**
- `DP_CMD_GET_MAX_INFERENCES = 4` (returns **dynamic** max_inferences_per_enclave) ✅
- `DP_CMD_CHECK_INFERENCE_ALLOWED = 5` (legacy endpoint, currently NOT_SUPPORTED)
- `DP_CMD_INCREMENT_COUNTER = 6` (legacy endpoint, currently NOT_SUPPORTED)
- `DP_CMD_RESET_COUNTER = 7` (legacy endpoint, currently NOT_SUPPORTED)
- `DP_CMD_RUN_INFERENCE = 9` (active two-phase verified inference request and commit)
- `DP_CMD_CREATE_ENCLAVE = 22` (decrypt/register/reset; leaves the enclave RAM window open)
- `DP_CMD_FINALIZE_CREATE_ENCLAVE = 24` (closes the enclave RAM window after NS setup)
- `DP_CMD_DESTROY_ENCLAVE = 23` (reset secure state, RAM window reopened for NS zeroization)

**Verified Inference Transaction (Current):**
- `DP_CMD_RUN_INFERENCE = 9` (two phases: verify plaintext M_inf and open the SAU window; then commit output and return PoX)
- `DP_CMD_INF_START = 25` and `DP_CMD_INF_COMPLETE = 26` are separate lifecycle helpers; they do not decrypt or verify M_inf and are not used for successful UART inference transactions. The UART path calls `DP_CMD_INF_COMPLETE` after execution failure to close the transaction, but that handler also increments the secure inference counter, so this failure path currently consumes quota.
- `DP_CMD_GET_DEVICE_PUBKEY = 27` (return secure-owned `pk_d`)
- `DP_CMD_SIGN_ATTEST_MSG = 28` (sign SHA256(nonce||enclave_info) in Secure)

**Enclave Authorization Protocol:**
- `DP_CMD_COMPUTE_ENCLAVE_INFO = 10` (SHA-256 hash of Model_pub || Model_secret || code || model_ID)
- `DP_CMD_VALIDATE_AUTHORIZE = 11` (validate plaintext M_update signature, enforce increasing quota, update secure policy)
- `DP_CMD_VALIDATE_BOOT_ENCLAVE_INFO = 17` ✅ (recompute current EnclaveInfo from registered artifacts and compare with boot-time sealed value)
- `DP_CMD_SAU_REGISTER_ROM = 18` ✅ (register early-model ROM window used for `model_pub` hashing)
- `DP_CMD_SAU_REGISTER_CODE = 19` ✅ (register inference code window used for `code_hash` hashing)
- `DP_CMD_SET_LATE_SECRET_HASH = 20` ✅ (hash encrypted late weights into `model_secret`)

**Benchmark & Diagnostics (NEW):**
- `DP_CMD_GET_BENCHMARK = 8` (retrieves Secure-side performance metrics and memory usage)

**Security Policy:**
- `max_inferences_per_enclave` is **dynamic** (starts at 0, updated on valid M_update)
- `inference_counter_secure = 0` (protected counter in Secure world)
- On successful M_inf processing, `RUN_INFERENCE` phase 1 increments the Secure counter before PoX generation finishes. The UART error-cleanup call to `INF_COMPLETE` also increments it after an execution failure. In either case, Secure may consume quota without incrementing the NS shadow count, so the UART count/remaining responses can disagree with Secure policy state.

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
- **Files**: `secure_benchmark.c` and `secure_benchmark.h`
- **Memory Calculation**: Hardcoded from linker output (linker symbols unavailable in TF-M)
  - Secure RAM: 52,732 bytes (from build log analysis)
  - Secure Flash: 119,532 bytes (from TFM partition layout)
- **Start/Stop Pattern**: Save DWT_CYCCNT at operation start, read at end, compute difference
- **All Timing**: Includes PSA call overhead (minimal in Secure world)

## Current Flow (Late Weights + Authorization + Verified Inference)

### 0. Boot-time EnclaveInfo sealing
NS bootstrap registers the relevant flash windows and sends the encrypted late-weight blob to Secure.

Secure then computes:

- `model_pub = SHA256(early ROM window)`
- `model_secret = SHA256(encrypted late blob)`
- `code_hash = SHA256(inference code window)`
- `EnclaveInfo = SHA256(model_pub || model_secret || code_hash || model_id_LE)`

The result is stored in Secure as the boot-time reference and never depends on host-provided model bytes.

### 1. Create flow (cmd=22)
NS calls `psa_call()` with:

```
in_vec[0] = cmd (DP_CMD_CREATE_ENCLAVE)
in_vec[1] = encrypted late weights (flash)
in_vec[2] = IV + enclave RAM metadata
out_vec[0] = NS RAM buffer (decrypted output)
```

The secure partition:
1. Sets up **AES-128-CTR** with PSA Crypto
2. Applies the IV from `in_vec[2]`
3. Decrypts in chunks using `psa_cipher_update()`
4. Writes plaintext into the NS output buffer
5. Registers the enclave RAM window and leaves it open until `DP_CMD_FINALIZE_CREATE_ENCLAVE` (24) is called after NS setup

### 2. Authorization and verified inference

The UART host sends both authorization and inference requests as plaintext binary payloads. ECDSA signatures provide message authenticity; these requests do not use an AES-GCM nonce, ciphertext, or tag.

**Authorize (UART command `0x02`, Secure command `DP_CMD_VALIDATE_AUTHORIZE = 11`):**

`M_update = pk_u[64] | c_limit[4, little-endian] | EnclaveInfo[32] | T_o[64]`

`T_o` is an ECDSA P-256 signature over the preceding 100 bytes. Secure verifies it, rejects a quota that is not greater than the previously accepted limit, and stores the authorization key and limit. The NS UART layer requires an exact 164-byte request.

**Run inference (UART command `0x04`, Secure command `DP_CMD_RUN_INFERENCE = 9`):**

`M_inf = model_id[4, little-endian] | code_hash[32] | signature[64]`

The 100-byte plaintext M_inf signature covers `model_id || code_hash`. In phase 0, Secure checks authorization, quota, model/code identity, and the signature, then opens the SAU window and returns a transaction ID. NS executes the inference. In phase 1, NS submits `tx_id[4] | output_class[1]`; Secure closes the window and increments the Secure counter before building and signing the PoX. The UART response contains `output_class[1] | PoX_signature[64]` only if PoX generation succeeds. A later PoX failure therefore leaves Secure's counter incremented.

**Get Policy (cmd=4):**
```
in_vec[0] = cmd (DP_CMD_GET_MAX_INFERENCES)
out_vec[0] = max_inferences (uint32_t, returns dynamic value)
```

The active verified UART flow uses `DP_CMD_RUN_INFERENCE` (9) for both phases. `DP_CMD_INF_START` (25) does not accept or verify M_inf and is not used by this UART flow. On NS execution failure, the UART handler calls `DP_CMD_INF_COMPLETE` (26) to close the transaction; that helper also increments the Secure counter.

**Security Properties:**
- Request signature verification and PoX signing happen in Secure world
- Counter state protected in Secure world
- Verified inference request path cannot use legacy unverified mode
- Explicit enclave lifecycle via create/finalize/destroy commands

### 3. Pre-create integrity gate
- Before NS creates an enclave, it asks Secure to recompute current `EnclaveInfo` from the registered ROM/code windows and encrypted late blob digest.
- Secure compares that value against the boot-time sealed reference.
- If they differ, Secure returns failure and NS must not create the enclave.

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
- **Output**: `out_vec[0]` = current `max_inferences_per_enclave_secure` (`uint32_t`)
- **Notes**: Starts at 0 and changes after successful authorization; it is not a fixed value of 3.

#### `DP_CMD_CHECK_INFERENCE_ALLOWED` (5)
- **Current behavior**: Returns `PSA_ERROR_NOT_SUPPORTED`.

#### `DP_CMD_INCREMENT_COUNTER` (6)
- **Current behavior**: Returns `PSA_ERROR_NOT_SUPPORTED`. The active inference path commits the counter in the `DP_CMD_RUN_INFERENCE` phase-1 handler.

#### `DP_CMD_RESET_COUNTER` (7)
- **Current behavior**: Returns `PSA_ERROR_NOT_SUPPORTED`. Counter reset is handled by enclave creation and destruction.

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

### `DP_CMD_DECRYPT_LATE_WEIGHTS` (internal helper)
- **Purpose**: AES-128-CTR decrypt encrypted late weights into NS RAM during enclave creation; the command endpoint is not exposed.
- **Input**:
	- `in_vec[0]`: `cmd` (`DP_CMD_DECRYPT_LATE_WEIGHTS`)
	- `in_vec[1]`: ciphertext (late weights)
	- `in_vec[2]`: IV (16 bytes)
- **Output**:
	- `out_vec[0]`: plaintext buffer

### `DP_CMD_DECRYPT_MODEL` (deprecated)
- **Purpose**: legacy full-model decrypt.
- **Current behavior**: always returns `PSA_ERROR_NOT_SUPPORTED`.

## Weight-Decryption Crypto Details
- **Algorithm**: AES-128-CTR
- **Key**: static 16-byte key in `dummy_partition.c` (demo-only)
- **IV**: provided by NS via `late_wt_iv[]`

> For production: move keys to secure storage (ITS/PS), add integrity (AEAD/HMAC), and rotate keys.

## Files
- [dummy_partition.c](dummy_partition.c): command routing, authorization/inference verification, and AES-CTR weight decryption
- [secure_nsc_interface.c](secure_nsc_interface.c): Secure→NS bridge using CMSE
- [tfm_dummy_partition.yaml](tfm_dummy_partition.yaml): TF-M service manifest
- [tfm_manifest_list.yaml.in](tfm_manifest_list.yaml.in): manifest list for build

## Notes
- Legacy model decryption is removed; `DP_CMD_DECRYPT_MODEL` returns `PSA_ERROR_NOT_SUPPORTED`.
- The secure partition is the authority for integrity checks: it computes all security-relevant hashes and performs the current-vs-boot comparison internally.
- For production: Consider adding **HMAC verification** in secure partition before decryption to ensure encrypted weights haven't been tampered with.

