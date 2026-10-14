# Source Code (Non-Secure Application)

## Version Information

```
Zephyr:     commit 61a8648c2cc6bbec9af368a96ecae87d6798e7fe (HEAD -> main)
TF-M:       commit 04aa7243e04946b5422b124bea9c0675ab6b120f (HEAD, manifest-rev)
Updated:    5 March 2026
Architecture: Split Inference with Secure/Non-Secure (NS/S) integration
NS Flash:   176,160 / 262,144 bytes (67.2%)
NS RAM:     121,788 / 131,072 bytes (92.9%)
```

## Verification
The current source implements the UART authorization and verified-inference flows described below. Hardware test reports are not included in this repository.

---

## Overview
This folder contains the Non-Secure (NS) application that drives the split inference flow. The NS app:
- Creates the enclave environment.
- Requests **secure decryption of late-layer weights** into NS RAM.
- Runs CMSIS-NN split inference (early + late) using the decrypted weights.
- Registers ROM/code windows used by Secure to bind `EnclaveInfo` to real artifacts.
- Refuses enclave creation if Secure says current `EnclaveInfo` no longer matches the boot-time sealed reference.

## Architecture (NS + Secure Interaction)
```
		  Non-Secure (Zephyr)                               Secure (TF-M)
┌──────────────────────────────────┐            ┌───────────────────────────┐
│ src/main.cpp                      │            │ dummy_partition.c         │
│  └─ create_enclave()              │            │  └─ AES-CTR decrypt        │
│     ├─ set_late_weights_buffer()  │   PSA IPC  │     (PSA Crypto)          │
│     └─ psa_call(DECRYPT_LATE) ────┼──────────► │  └─ write to NS outvec     │
│  └─ enter_enclave()               │            └───────────────────────────┘
│     └─ run_enclave()              │
│        └─ run_split_inference()   │
│            ├─ early layers (CMSIS-NN)
│            └─ late layers (CMSIS-NN)
└──────────────────────────────────┘
```

## Key Paths (NS World)
- `src/main.cpp`: entry point; orchestrates the high-level flow
- `src/create_enclave.cpp`: allocates NS buffer, calls PSA decrypt, sets late-weights buffer
- `src/run_enclave.cpp`: runs inference inside the enclave thread
- `src/split_inference.cpp`: CMSIS-NN early/late inference implementation
- `src/split_inference.h`: late-weights buffer API (`set/get`)
- Host uploads input image over UART (`CMD_RUN_INFERENCE_WITH_IMAGE`)

## Where the Data Lives
- **Encrypted late weights in flash**: `split_inference/late/L_nn_wt_encrypted_data.c`
- **Late weights sizes + IV**: `split_inference/late/L_nn_wt_encrypted.h`
- **Late biases**: `split_inference/late/L_nn_biases.h`
- **Early weights/params**: `split_inference/early/E_nn_wt.h`, `split_inference/early/E_nn_params.h`

## Key Files

### Application entry
- **main.cpp**: high-level flow; calls `create_enclave()` then `enter_enclave()`.
- **create_enclave.cpp**: bootstraps Secure EnclaveInfo material, validates boot-time integrity before creation, allocates the NS buffer used for late weights, invokes PSA decrypt, and manages enclave state.
- **run_enclave.cpp**: executes split inference in NS when called from the verified UART handler; it does not issue the two PSA transaction phases.

### Split inference
- **split_inference.cpp / split_inference.h**: CMSIS-NN early/late execution for host-provided image input, buffer reuse, and prediction printing.

### Benchmarking & Performance Monitoring
- **benchmark.h**: NS-side benchmark API with DWT cycle counter support (ARM Cortex-M33)
- **benchmark.cpp**: Implementation of DWT register access, cycle measurements, memory usage calculation via linker symbols
- **secure_benchmark_ns.h/cpp**: NS wrapper to retrieve Secure-side metrics via PSA IPC (calls `DP_CMD_GET_BENCHMARK`)

## Authorization and Quota
`uart_protocol.cpp` accepts plaintext signed `M_update` (164 bytes) and `M_inf` (100 bytes), then forwards them to Secure verification. `M_inf` is verified in phase 0 of `DP_CMD_RUN_INFERENCE`; NS executes the inference after receiving a transaction ID; phase 1 closes the SAU window and produces PoX. The configured limit is dynamic: it starts at 0 and is set by a valid `M_update`.

On the normal success path, Secure increments its counter during phase 1 and the NS shadow counter increments after the phase-1 PSA call succeeds. There are two failure-path caveats in the current code: if NS execution fails, the UART handler calls `DP_CMD_INF_COMPLETE`, which closes the transaction but also increments the Secure counter; and the normal phase-1 handler increments Secure's counter before PoX hashing/signing has completed. In either case, the NS shadow counter may not increment even though Secure has consumed quota, so the UART count/remaining queries can diverge from Secure policy state.

## Secure EnclaveInfo lifecycle

### Boot-time materialization
- `uart_protocol_init()` triggers `initialize_secure_enclave_info_boot()`.
- NS registers:
   - early model ROM window (`.model_ro`)
   - inference code window (`.inference_ro`)
- NS sends encrypted late weights to Secure so Secure computes `model_secret = SHA256(ciphertext)`.
- Secure seals a boot-time reference:

   `EnclaveInfo = SHA256(model_pub || model_secret || code_hash || model_id_LE)`

### Pre-create validation
- At the start of `create_enclave()`, NS asks Secure to recompute the current value from registered artifacts.
- Secure compares `current_enclave_info` against `boot_enclave_info`.
- If the comparison fails, `create_enclave()` aborts before decrypting late weights or marking the enclave as created.

## Performance Metrics

### Hardware Configuration
- **CPU**: STM32L552 ARM Cortex-M33 @ 110 MHz
- **Cycle Time**: ~9.09 nanoseconds per cycle (1/110MHz)
- **DWT Counter**: 32-bit cycle counter with automatic wrapping

### Measured Performance
```
Inference Execution (per image):
  ├─ Early Layers:         390.8 ms (42,984,997 cycles @ 110 MHz)
  ├─ Late Layers:           72.0 ms (7,922,258 cycles)
  ├─ Inference Total:      468.7 ms (51,553,622 cycles)
  └─ Enclave Create:        72.6 ms (7,980,975 cycles)

Secure Cryptographic Operations:
  ├─ AES-CTR Decrypt:       69.7 ms (7,662,219 cycles)
  └─ Counter Management:    <1 µs (548-29 cycles)

Memory Usage (ELF Binary Analysis):
  ├─ NS RAM:               121,788 / 131,072 bytes (92.9%)
  │   ├─ BSS (buffers):    117,809 bytes (115.0 KB)
  │   └─ DATA (globals):     3,976 bytes (3.9 KB)
  ├─ NS Flash:             176,160 / 262,144 bytes (67.2%)
  │   ├─ rodata (weights): 138,252 bytes (135.0 KB)
  │   └─ text (code):       ~38 KB
  ├─ Secure RAM:            52,732 / 65,536 bytes (80.5%)
  └─ Secure Flash:         119,532 / 134,144 bytes (89.1%)
```

### Dynamic Memory Breakdown (Top 10 symbols)
1. `enclave_memory`: 39,552 bytes (decrypted late weights)
2. `late_wt_encrypted`: 39,552 bytes (encrypted in ROM)
3. `wt_conv2d_6`: 18,432 bytes (early layer weights)
4. `early_buf0/1/2`: 16,384 bytes each (inference buffers)
5. `wt_conv2d_4`: 9,216 bytes (early layer weights)
6. `early_skip`: 8,192 bytes (skip connection buffer)
7. `early_ctx_buf`: 8,192 bytes (context for early layers)
8. `wt_conv2d_3`: 4,608 bytes (early layer weights)
9. `early_output`: 4,096 bytes (output buffer)
10. `late_ctx_buf`: 4,096 bytes (context for late layers)

### Benchmark Data Points (NS metrics)
1. `enclave_create_cycles`: Enclave creation overhead
2. `enclave_destroy_cycles`: Enclave teardown
3. `aes_decrypt_cycles`: AES-CTR decryption for late weights
4. `early_layers_cycles`: CIFAR-10 early layers execution
5. `late_layers_cycles`: CMSIS-NN late layers execution
6. `total_inference_cycles`: Sum of inference phases
7. `run_enclave_cycles`: Total enclave execution
8. `inference_count`: Counter tracking inferences run
9. `ns_ram_used`: Non-Secure RAM in bytes
10. `ns_ram_total`: Total NS RAM available
11. `ns_flash_used`: Non-Secure Flash consumed
12. `ns_flash_total`: Total NS Flash available
13. `heap_free`: Remaining heap memory
14. `stack_used`: Stack depth during execution

- Host-side image upload is required for case-study inference requests.

### Model source
- Early-layer weights and parameters: `../split_inference/early/E_nn_wt.h`, `../split_inference/early/E_nn_params.h`.
- Late-layer weights, parameters, and biases: `../split_inference/late/L_nn_wt.h`, `../split_inference/late/L_nn_params.h`, `../split_inference/late/L_nn_biases.h`.
- Encrypted late-weight data: `../split_inference/late/L_nn_wt_encrypted_data.c`.

### UART Protocol (Host ↔ STM32)
- **uart_protocol.h**: Protocol command definitions, including diagnostic and test commands
- **uart_protocol.cpp**: Binary protocol handlers
   - CMD_COMPUTE_ENCLAVE_INFO (0x01): Generate EnclaveInfo hash
   - CMD_VALIDATE_AUTHORIZE (0x02): Validate plaintext M_update and apply quota
   - CMD_GET_MAX_INFERENCES (0x03): Return total authorized quota
   - CMD_RUN_INFERENCE (0x04): Verify plaintext M_inf, execute inference, and return PoX
   - CMD_GET_INFERENCE_COUNT (0x05): Return consumed quota
   - CMD_GET_REMAINING_INFERENCES (0x06): Return available quota
   - CMD_GET_BENCHMARK (0x08): Return NS benchmark structure
   - CMD_GET_SECURE_BENCHMARK (0x09): Return Secure benchmark structure
   - CMD_GET_INFERENCE_RESULT (0x0A): Return last prediction/expected
   - CMD_SET_MAX_INFERENCES (0x0B): Manual max setting
   - CMD_GET_DEVICE_PUBKEY (0x0C): Return device public key `pk_d`
   - CMD_GET_SAU_STATE (0x0D): Return SAU state (`state+base+size`, best-effort on hardened policy)
   - CMD_RUN_INFERENCE_NO_SAU (0x0E): Dangerous test path (inference without explicit create)
   - CMD_READ_PROTECTED_MEM (0x0F): Dangerous test path (direct read in protected enclave region)
   - CMD_GET_ENCLAVE_STATE (0x10): Return enclave lifecycle state (`created(1)`)
   - CMD_CREATE_ENCLAVE (0x11): Explicit enclave create lifecycle command
   - CMD_DESTROY_ENCLAVE (0x12): Explicit enclave destroy lifecycle command
   - CMD_UPDATE_RATE_LIMIT (0x13): Secure API to update max inferences

## UART Authorization and Inference (Host ↔ STM32)

### Overview
The host authorizes inference with signed plaintext M_update and submits a signed plaintext M_inf for each inference. The device verifies both messages in Secure world; neither request is wrapped in AES-GCM.

### Communication Flow
```
┌──────────────────────────┐         USB/UART @ 115200        ┌─────────────────────────┐
│   Mac (Provider)         │ ◄──────────────────────────────► │  STM32L552 (Device)     │
│                          │                                   │                         │
│  Host                   │   Binary Protocol                │  uart_protocol.cpp      │
│  - Sign M_update/M_inf  │   ──────────────────────►        │  - Forward for secure   │
│  - Verify device PoX    │   ◄──────────────────────        │    signature checks     │
│                         │      Response packets            │  - Quota + inference    │
└──────────────────────────┘                                   └─────────────────────────┘
```

### EnclaveInfo Computation (CMD 0x01)

**Purpose**: Generate deterministic 32-byte digest representing enclave identity.

**Mac → Device**:
- Data: `nonce[32]` (attested mode)

**Device Processing**:
- EnclaveInfo is computed and cached in Secure world only (`dummy_partition`).
- Signature device-side: `sig_d = Sign(sk_d, SHA256(nonce || enclave_info))`.

**Device → Mac**:
- Status: `0x00` (OK)
- Data: `enclave_info[32] || sig_d[64]` (encrypted if a session is active)

**Usage**: the host verifies the attestation with `pk_d`, then embeds `enclave_info` in `M_update`.

---

### M_update Authorization (CMD 0x02)

**Request payload** (host → device, 164 bytes, plaintext):
`pk_u[64] | c_limit[4, little-endian] | EnclaveInfo[32] | T_o[64]`

`T_o` is an ECDSA P-256 signature (`r || s`) over the preceding 100 bytes. The NS UART handler forwards the payload unchanged to `DP_CMD_VALIDATE_AUTHORIZE`; Secure verifies the signature, rejects a non-increasing limit, and stores the authorization key and quota. There is no nonce, ciphertext, or GCM tag in this request.

**Device → Mac**:
- Status: `0x00` (validated) or `0xFF` (failed)
- Data: None

**Security Properties**:
- **Request authenticity**: ECDSA signatures on M_update and M_inf detect unauthorized changes; these request payloads are not encrypted
- **Anti-replay**: Strictly increasing c_limit enforcement
- **PSA Crypto**: Signature verification runs in Secure World (TF-M)

---

### Quota Management (CMD 0x03-0x06)

The device reports the quota and inference count after successful M_update authorization:

| Command | Metric | Variable | Description |
|---------|--------|----------|-------------|
| **0x03** | Max | `mock_max_inferences` | Total authorized quota |
| **0x05** | Count | `mock_inference_count` | Consumed quota |
| **0x06** | Remaining | `max - count` | Available quota |

`CMD_RUN_INFERENCE` (`0x04`) accepts a 100-byte plaintext M_inf: `model_id[4, little-endian] | code_hash[32] | signature[64]`. Secure verifies the signature over the first 36 bytes and checks the model/code identity and quota. On success, Secure increments its counter in phase 1 and the NS shadow counter increments after the PSA call succeeds. On execution failure, the UART handler calls `DP_CMD_INF_COMPLETE`, which also increments the Secure counter; phase 1 likewise increments before PoX generation finishes. In either failure case, the NS count/remaining queries can disagree with Secure's quota. The UART response contains the predicted class and 64-byte PoX signature only on successful completion.

**Example Flow**:
```
1. Initial state: max=0, count=0, remaining=0
   → CMD 0x04 returns 0xFF (blocked)

2. Host sends plaintext M_update (c_limit=20)
   → CMD 0x02 validates signature → max=20, count=0, remaining=20

3. Execute 3 inferences
   → CMD 0x04 × 3 → max=20, count=3, remaining=17

4. Query quota
   → CMD 0x03 returns 20 (max)
   → CMD 0x05 returns 3 (count)
   → CMD 0x06 returns 17 (remaining)
```

---

### Message Protection

- M_update and M_inf request payloads are plaintext and protected by their ECDSA signatures, not AES-GCM encryption.
- Host-side PoX verification uses `CMD_GET_DEVICE_PUBKEY` (`0x0C`) to obtain `pk_d`.

---

### UART Configuration

**Device side**:
- UART: `lpuart1` (ST-LINK VCP)
- Baud rate: `115200` (8N1)
- Polling loop in interactive mode

**Host side**:
- Port: `/dev/tty.usbmodem*`
- Python dependencies: `pyserial`, `cryptography`

---

### Performance Notes

Latency depends on command type:
- Metadata and counter commands are typically sub-millisecond.
- Cryptographic paths (M_update and M_inf signature verification, PoX signing) are higher and depend on payload size and platform state.

---

### Testing Tools

- Available benchmark and case-study scripts are in the repository's `tools/` directory.

---

Last updated: 13 March 2026


