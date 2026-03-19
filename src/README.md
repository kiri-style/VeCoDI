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

## ✅ VERIFICATION STATUS: **COMPLETE END-TO-END PROTOCOL VERIFIED**

**Date**: 27 February 2026  
**See**: [../md/VERIFICATION_REPORT.md](../md/VERIFICATION_REPORT.md)

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
- `src/test_images.c`: CIFAR-10 sample inputs

## Where the Data Lives
- **Encrypted late weights in flash**: `split_inference/late/L_nn_wt_encrypted_data.c`
- **Late weights sizes + IV**: `split_inference/late/L_nn_wt_encrypted.h`
- **Late biases**: `split_inference/late/L_nn_biases.h`
- **Early weights/params**: `split_inference/early/E_nn_wt.h`, `split_inference/early/E_nn_params.h`

## Key Files

### Application entry
- **main.cpp**: high-level flow; calls `create_enclave()` then `enter_enclave()`.
- **create_enclave.cpp**: bootstraps Secure EnclaveInfo material, validates boot-time integrity before creation, allocates the NS buffer used for late weights, invokes PSA decrypt, and manages enclave state.
- **run_enclave.cpp**: executes split inference inside the enclave thread. **[MODIFIED]** Uses `DP_CMD_RUN_INFERENCE` in two phases (`precheck` then `commit`) so counter increments only after successful inference.

### Split inference
- **split_inference.cpp / split_inference.h**: CMSIS-NN early/late execution, buffer reuse, and prediction printing.

### Benchmarking & Performance Monitoring
- **benchmark.h**: NS-side benchmark API with DWT cycle counter support (ARM Cortex-M33)
- **benchmark.cpp**: Implementation of DWT register access, cycle measurements, memory usage calculation via linker symbols
- **secure_benchmark_ns.h/cpp**: NS wrapper to retrieve Secure-side metrics via PSA IPC (calls `DP_CMD_GET_BENCHMARK`)

## Counter Management (Dynamic Policy - Verified 27 Feb 2026)
**Location**: `src/run_enclave.cpp` + `dummy_partition/dummy_partition.c`

The counter policy is **Secure-side verified**, **dynamically configured**, and used with a two-phase inference gate:

```cpp
// In run_enclave.cpp (phase 0 = precheck, phase 1 = commit):
uint32_t cmd = DP_CMD_RUN_INFERENCE;
uint8_t phase = 0U; // precheck
psa_invec in_vec[2] = { { &cmd, sizeof(cmd) }, { &phase, sizeof(phase) } };
psa_outvec out_vec = { &allowed, sizeof(allowed) };
psa_call(handle, PSA_IPC_CALL, in_vec, 2, &out_vec, 1);
```

**Dynamic Policy** ✅ Verified: 
- Initial state: `max_inferences_per_enclave = 0` (all inferences blocked)
- After valid M_update: `max_inferences_per_enclave = c_limit` (from Model Provider)
- Once limit reached: inference execution **blocked** (no auto-recreation)
- Verification and quota enforcement happen in Secure world

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

See [DEVICE_BENCHMARK.md](../md/DEVICE_BENCHMARK.md) for benchmark collection, metrics, and report workflow.
- **test_images.c / test_images.h**: CIFAR-10 sample inputs and labels.

### Model + artifacts
- **cifar_resnet_int8.tflite**: quantized CIFAR-10 model (reference).
- **cifar_resnet_lite_int8_data.cc/h**: embedded model array (legacy path).
- **model_encrypted*.h**: legacy encrypted model headers (not used by split flow).

### UART Protocol (Mac ↔ STM32)
- **uart_protocol.h**: Protocol command definitions (0x01-0x13)
- **uart_protocol.cpp**: Binary protocol handlers
   - CMD_COMPUTE_ENCLAVE_INFO (0x01): Generate EnclaveInfo hash
   - CMD_VALIDATE_M_UPDATE (0x02): AES-256-GCM decrypt and apply quota
   - CMD_GET_MAX_INFERENCES (0x03): Return total authorized quota
   - CMD_RUN_INFERENCE (0x04): Execute inference (consumes quota)
   - CMD_GET_INFERENCE_COUNT (0x05): Return consumed quota
   - CMD_GET_REMAINING_INFERENCES (0x06): Return available quota
   - CMD_ECDH_HANDSHAKE (0x07): Derive dynamic session key
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

### Provider/Verifier Host Tool
- **tools/mac_provider.py**: Interactive Model Provider/Verifier used for hardware tests
   - Generate M_update packets with configurable c_limit
   - ECDH/HKDF dynamic session key flow
   - PoX verification (valid + negative checks)
   - Security test suite (unitary/combinable)
   - Session status now shows whether the enclave is currently created on-device

### Protocol Testing
- **test_enclave_auth.c**: Test harness for authorization protocol
  - Phase 1: EnclaveInfo computation
  - Phase 2: M_update validation
  - Phase 3: Counter verification
- **test_inference_protocol.cpp**: End-to-end inference protocol test
  - M_inf message generation/validation
  - Proof-of-Execution (PoX) generation

### Interactive Security Tests (option 18 in mac_provider)
- **T1** fake EnclaveInfo in M_update → rejection expected
- **T2** replay same M_update → replay rejection expected
- **T3** tampered AES-GCM tag in M_update → rejection expected
- **T4** invalid verifier signature in M_inf → rejection expected
- **T5** rejected inference must not create SAU-open side effect
- **T6** PoX negative check: wrong-message verify must fail, correct-message verify must pass

### Security/IPC glue
- **ns_irq.c / ns_irq.h**: NS interrupt setup for TrustZone.

## UART Protocol Architecture (Mac ↔ STM32)

### Overview
The UART protocol enables **Mac-side authorization** of device inferences via encrypted M_update packets. This replaces the need for on-device Provider simulation in production deployments.

### Communication Flow
```
┌──────────────────────────┐         USB/UART @ 115200        ┌─────────────────────────┐
│   Mac (Provider)         │ ◄──────────────────────────────► │  STM32L552 (Device)     │
│                          │                                   │                         │
│  tools/mac_provider.py   │   Binary Protocol                │  src/uart_protocol.cpp  │
│  - Generate M_update     │   ──────────────────────►        │  - PSA Crypto decrypt   │
│  - AES-256-GCM encrypt   │   ◄──────────────────────        │  - Quota management     │
│  - Verify PoX + tests    │      Response packets            │  - Attested EnclaveInfo │
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

### M_update Validation (CMD 0x02)

**Purpose**: Decrypt AES-256-GCM encrypted authorization packet and apply inference quota.

**Packet Structure** (Mac → Device):
```
┌─────────────┬──────────────────┬──────────┐
│  Nonce (12) │  Ciphertext (n)  │ Tag (16) │
└─────────────┴──────────────────┴──────────┘
```

**M_update Plaintext** (before encryption on Mac):
```c
struct M_update_plaintext {
    uint32_t c_limit;         // Inference quota (4 bytes)
    uint8_t pk_v[64];         // Verifier public key
    uint8_t enclave_info[32]; // From CMD_COMPUTE_ENCLAVE_INFO
    uint32_t cert_len;        // Certificate length
    uint8_t cert[n];          // Certificate data
};
```

**Device Processing**:
1. **AES-256-GCM Decrypt** via PSA Crypto API:
   ```c
   psa_aead_decrypt(
       key_handle,           // Session key (256-bit, hardcoded)
       PSA_ALG_GCM,          // AES-GCM algorithm
       nonce,                // 12 bytes from packet
       12,                   // Nonce length
       NULL, 0,              // No additional data
       ciphertext_with_tag,  // Ciphertext || Tag
       ciphertext_len + 16,  // Total length
       plaintext,            // Output buffer
       sizeof(plaintext),    // Max output size
       &plaintext_len        // Actual output length
   );
   ```

2. **Extract c_limit**:
   ```c
   uint32_t c_limit = plaintext[0] | (plaintext[1] << 8) 
                    | (plaintext[2] << 16) | (plaintext[3] << 24);
   ```

3. **Anti-replay Check**:
   ```c
   if (c_limit <= mock_max_inferences) {
       return RESP_ERROR;  // Reject quota downgrades
   }
   ```

4. **Update Quota**:
   ```c
   mock_max_inferences = c_limit;
   mock_inference_count = 0;  // Reset counter
   ```

**Device → Mac**:
- Status: `0x00` (validated) or `0xFF` (failed)
- Data: None

**Security Properties**:
- **Authenticated Encryption**: AES-GCM tag prevents tampering
- **Anti-replay**: Strictly increasing c_limit enforcement
- **PSA Crypto**: Hardware-accelerated in Secure World (TFM)

---

### Quota Management (CMD 0x03-0x06)

The device maintains a **3-metric quota system** after M_update validation:

| Command | Metric | Variable | Description |
|---------|--------|----------|-------------|
| **0x03** | Max | `mock_max_inferences` | Total authorized quota |
| **0x05** | Count | `mock_inference_count` | Consumed quota |
| **0x06** | Remaining | `max - count` | Available quota |

**CMD 0x04 (RUN_INFERENCE) Gating**:
```c
if (mock_max_inferences == 0) {
    return RESP_ERROR;  // No M_update applied yet
}
if (mock_inference_count >= mock_max_inferences) {
    return RESP_ERROR;  // Quota exhausted
}
mock_inference_count++;
return RESP_OK;
```

**Example Flow**:
```
1. Initial state: max=0, count=0, remaining=0
   → CMD 0x04 returns 0xFF (blocked)

2. Mac sends M_update (c_limit=20)
   → CMD 0x02 validates → max=20, count=0, remaining=20

3. Execute 3 inferences
   → CMD 0x04 × 3 → max=20, count=3, remaining=17

4. Query quota
   → CMD 0x03 returns 20 (max)
   → CMD 0x05 returns 3 (count)
   → CMD 0x06 returns 17 (remaining)
```

---

### Session Key Management

- Session establishment is done through `CMD_ECDH_HANDSHAKE` (`0x07`).
- Command and response payloads are encrypted with AES-GCM when session mode is active.
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
- Cryptographic paths (`M_update` decrypt/validate, secure inference request processing, PoX flow) are higher and depend on payload size and platform state.

Refer to `../md/DEVICE_BENCHMARK.md` for measured values and benchmark workflow.

---

### Testing Tools

- `tools/mac_provider.py`: main interactive Provider/Verifier workflow (including T1..T6 security tests and danger options 19/20).
- `tools/step1_protocol_test.py`: basic protocol smoke checks.
- `tools/test_uart.py`: quick UART command validation helper.

---

Last updated: 13 March 2026


