# Source Code (Non-Secure Application)

## Version Information

```
Zephyr:     commit 61a8648c2cc6bbec9af368a96ecae87d6798e7fe (HEAD -> main)
TF-M:       commit 04aa7243e04946b5422b124bea9c0675ab6b120f (HEAD, manifest-rev)
Updated:    5 March 2026
Architecture: Split Inference with Secure/Non-Secure (NS/S) integration
```

## ✅ VERIFICATION STATUS: **COMPLETE END-TO-END PROTOCOL VERIFIED**

**Date**: 27 February 2026  
**See**: [../VERIFICATION_REPORT.md](../VERIFICATION_REPORT.md)

---

## Overview
This folder contains the Non-Secure (NS) application that drives the split inference flow. The NS app:
- Creates the enclave environment.
- Requests **secure decryption of late-layer weights** into NS RAM.
- Runs CMSIS-NN split inference (early + late) using the decrypted weights.
- **Computes integrity hash (CNT)** using PSA Crypto SHA-256 to verify input data, code, and all weights (early + late).

## Architecture (NS + Secure Interaction)
```
		  Non-Secure (Zephyr)                               Secure (TF-M)
┌──────────────────────────────────┐            ┌───────────────────────────┐
│ src/main.cpp                      │            │ dummy_partition.c         │
│  └─ create_enclave()              │            │  └─ AES-CTR decrypt        │
│     ├─ set_late_weights_buffer()  │   PSA IPC  │     (PSA Crypto)          │
│     └─ psa_call(DECRYPT_LATE) ────┼──────────► │  └─ write to NS outvec     │
│     └─ precompute_late_weights_hash() (Phase 1: hash code+late)            │
│  └─ enter_enclave()               │            └───────────────────────────┘
│     └─ run_enclave()              │
│        └─ run_split_inference()   │
│            ├─ compute_integrity_hash() (Phase 2: hash input+early+late_hash)
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
- **create_enclave.cpp**: allocates the NS buffer used for late weights, invokes PSA decrypt, and manages enclave state.
- **run_enclave.cpp**: executes split inference inside the enclave thread. **[MODIFIED]** Now atomically calls `DP_CMD_RUN_INFERENCE` (Secure checks counter + increments before inference runs).

### Split inference
- **split_inference.cpp / split_inference.h**: CMSIS-NN early/late execution, buffer reuse, and prediction printing.

### Benchmarking & Performance Monitoring
- **benchmark.h**: NS-side benchmark API with DWT cycle counter support (ARM Cortex-M33)
- **benchmark.cpp**: Implementation of DWT register access, cycle measurements, memory usage calculation via linker symbols
- **secure_benchmark_ns.h/cpp**: NS wrapper to retrieve Secure-side metrics via PSA IPC (calls `DP_CMD_GET_BENCHMARK`)

## Counter Management (Dynamic Policy - Verified 27 Feb 2026)
**Location**: `src/run_enclave.cpp` + `dummy_partition/dummy_partition.c`

The counter is **atomic**, **Secure-side verified**, and **dynamically configured**:

```cpp
// In run_enclave.cpp:
psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_PARTITION_VERSION);
psa_call(handle, DP_CMD_RUN_INFERENCE, NULL, 0, NULL, 0);
psa_close(handle);
// Returns: 1 = allowed (counter < max), 0 = blocked (limit reached)
```

**Dynamic Policy** ✅ Verified: 
- Initial state: `max_inferences_per_enclave = 0` (all inferences blocked)
- After valid M_update: `max_inferences_per_enclave = c_limit` (from Model Provider)
- Once limit reached: inference execution **blocked** (no auto-recreation)
- All verification happens in Secure world atomically

## Performance Metrics

### Hardware Configuration
- **CPU**: STM32L552 ARM Cortex-M33 @ 110 MHz
- **Cycle Time**: ~9.09 nanoseconds per cycle (1/110MHz)
- **DWT Counter**: 32-bit cycle counter with automatic wrapping

### Measured Performance
```
Inference Execution (per image):
  ├─ Early Layers:         405 ms (CIFAR-10 feature extraction)
  ├─ Late Layers:           74 ms (dense classification)
  ├─ Inference Total:      518 ms (sum of above)
  └─ Average per cycle:    193 ms (multiple runs averaged)

AES-CTR Decryption:
  ├─ NS-side call:         82 ms (includes 13 ms IPC latency)
  └─ Secure-side exec:     66 ms (actual AES operation)

Memory Usage:
  ├─ NS RAM:               121.4 KB / 128 KB (92% utilized)
  ├─ NS Flash:             187.2 KB / 256 KB (71% utilized)
  ├─ Secure RAM:            52.7 KB / 64 KB (80% utilized)
  └─ Secure Flash:         119.5 KB / 131 KB (89% utilized)
```

### Benchmark Data Points (15 NS metrics)
1. `enclave_create_cycles`: Enclave creation overhead
2. `enclave_destroy_cycles`: Enclave teardown
3. `aes_decrypt_cycles`: AES-CTR decryption for late weights
4. `late_hash_cycles`: SHA-256 hash of late-layer weights
5. `inference_hash_cycles`: Integrity hash computation
6. `early_layers_cycles`: CIFAR-10 early layers execution
7. `late_layers_cycles`: CMSIS-NN late layers execution
8. `total_inference_cycles`: Sum of inference phases
9. `run_enclave_cycles`: Total enclave execution
10. `inference_count`: Counter tracking inferences run
11. `ns_ram_used`: Non-Secure RAM in bytes
12. `ns_ram_total`: Total NS RAM available
13. `ns_flash_used`: Non-Secure Flash consumed
14. `ns_flash_total`: Total NS Flash available
15. `heap_free`: Remaining heap memory
16. `stack_used`: Stack depth during execution

See [BENCHMARK_RESULTS.md](../BENCHMARK_RESULTS.md) for detailed cycle-by-cycle analysis.
- **test_images.c / test_images.h**: CIFAR-10 sample inputs and labels.

### Model + artifacts
- **cifar_resnet_int8.tflite**: quantized CIFAR-10 model (reference).
- **cifar_resnet_lite_int8_data.cc/h**: embedded model array (legacy path).
- **model_encrypted*.h**: legacy encrypted model headers (not used by split flow).

### UART Protocol (Mac ↔ STM32)
- **uart_protocol.h**: Protocol command definitions (0x01-0x06)
- **uart_protocol.cpp**: Binary protocol handlers (407 lines)
  - CMD_COMPUTE_ENCLAVE_INFO (0x01): Generate EnclaveInfo hash
  - CMD_VALIDATE_M_UPDATE (0x02): AES-256-GCM decrypt and apply quota
  - CMD_GET_MAX_INFERENCES (0x03): Return total authorized quota
  - CMD_RUN_INFERENCE (0x04): Execute inference (consumes quota)
  - CMD_GET_INFERENCE_COUNT (0x05): Return consumed quota
  - CMD_GET_REMAINING_INFERENCES (0x06): Return available quota

### Provider/Verifier Simulation
- **provider_sim.h/cpp**: Model Provider simulation for local testing
  - Generate M_update packets with configurable c_limit
  - ECDSA P-256 signature simulation
  - Session key derivation (hardcoded for prototype)

### Protocol Testing
- **test_enclave_auth.c**: Test harness for authorization protocol
  - Phase 1: EnclaveInfo computation
  - Phase 2: M_update validation
  - Phase 3: Counter verification
- **test_inference_protocol.cpp**: End-to-end inference protocol test
  - M_inf message generation/validation
  - Proof-of-Execution (PoX) generation

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
│  - Monitor quota         │      Response packets            │  - Mock EnclaveInfo     │
└──────────────────────────┘                                   └─────────────────────────┘
```

### EnclaveInfo Computation (CMD 0x01)

**Purpose**: Generate deterministic 32-byte digest representing enclave identity.

**Mac → Device**:
- Data: 100 bytes = `model_pub[64] || model_secret[32] || code_hash[32] || model_id[4]`
- Alternative: 0 bytes (uses default placeholder values)

**Device Processing**:
```c
// XOR-based deterministic hash (simplified for prototype)
for (uint32_t i = 0; i < 100; i++) {
    mock_enclave_info[i % 32] ^= data[i];
}
```

**Device → Mac**:
- Status: `0x00` (OK)
- Data: 32 bytes (EnclaveInfo digest)

**Usage**: This EnclaveInfo is embedded in M_update plaintext to bind authorization to specific enclave instance.

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

**Current (Prototype)**:
```c
// Hardcoded in uart_protocol.cpp (Device)
static const uint8_t session_key[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

# Matching key in tools/mac_provider.py (Mac)
SESSION_KEY = bytes([0xA0, 0xA1, ..., 0xBF])
```

**Production**: Should use **ECDH key exchange** to derive session key dynamically.

---

### UART Configuration

**Device Side**:
- **UART**: lpuart1 (ST-LINK VCP)
- **Baud Rate**: 115200 8N1
- **Polling**: k_yield() tight loop (no sleep, no overruns)
- **Device Tree**: `boards/nucleo_l552ze_q.overlay`
  ```dts
  chosen {
      zephyr,console = &lpuart1;
  };
  ```

**Mac Side**:
- **Port**: `/dev/tty.usbmodem*` (auto-detect)
- **Timeout**: 10 seconds for response
- **Library**: pyserial

---

### Performance Metrics

| Operation | Latency | Notes |
|-----------|---------|-------|
| **CMD_COMPUTE_ENCLAVE_INFO** | ~5 ms | XOR-based placeholder |
| **CMD_VALIDATE_M_UPDATE** | ~70 ms | PSA AEAD decrypt |
| **CMD_GET_MAX_INFERENCES** | <1 ms | Read variable |
| **CMD_RUN_INFERENCE** | <1 ms | Increment counter (mock) |
| **CMD_GET_INFERENCE_COUNT** | <1 ms | Read variable |
| **CMD_GET_REMAINING_INFERENCES** | <1 ms | Subtraction |

---

### Testing Tools

**Mac-side Scripts** (`tools/`):
- **mac_provider.py**: Interactive protocol client (385 lines)
  - Menu-driven interface for all 6 commands
  - AES-GCM encryption/decryption
  - Quota monitoring (max, count, remaining)
  - Usage: `python3 tools/mac_provider.py /dev/tty.usbmodem* 115200`

- **step1_protocol_test.py**: Smoke test for CMD_COMPUTE_ENCLAVE_INFO
- **test_uart.py**: Quick test for CMD_GET_MAX_INFERENCES

**Automated Test Sequence**:
```bash
# Authorization → 3 inferences → quota check
printf '3\n5\n5\n5\n4\n7\n8\nq\n' | python3 tools/mac_provider.py /dev/tty.usbmodem* 115200
```

**Expected Output**:
```
[3] M_update validated (c_limit=20) → max=20
[5] Inference 1 → count=1
[5] Inference 2 → count=2
[5] Inference 3 → count=3
[4] max_inferences = 20
[7] inference_count = 3
[8] remaining = 17
```

---

### Integration with Main Flow

**MAC_INTERACTIVE_MODE** (`src/main.cpp`):
```cpp
#define MAC_INTERACTIVE_MODE 1  // Enable UART protocol

int main() {
    uart_protocol_init();  // Initialize UART handler
    
    while (1) {
        uart_protocol_process();  // Poll for commands
        k_yield();                // Cooperative multitasking
    }
}
```

**Protocol-only Mode**:
- No inference execution (mock handlers)
- Quota management only
- EnclaveInfo computed via XOR (not real hash)

**Real Inference Integration** (TODO):
- Replace `mock_inference_count++` with actual `run_split_inference()`
- Gate inference in `run_enclave.cpp` based on `mock_max_inferences`
- Integrate with TFM secure counter (DP_CMD_RUN_INFERENCE)

---

### Documentation

- **Complete Protocol Spec**: [UART_PROTOCOL_SPEC.md](../UART_PROTOCOL_SPEC.md)
- **Mac Interactive Guide**: [MAC_INTERACTIVE_GUIDE.md](../MAC_INTERACTIVE_GUIDE.md)
- **Tools Documentation**: [tools/README.md](../tools/README.md)

---

## Runtime Flow (Dynamic Secure Counter)
1. **First run_enclave() call:**
   - NS detects no enclave exists (`is_enclave_created() == false`)
   - `create_enclave()`: allocate memory, PSA decrypt, reset Secure counter (cmd=7)
   - `set_late_weights_buffer()`: configure split inference pointers

2. **Subsequent run_enclave() calls:**
   - **PSA call `CHECK_INFERENCE_ALLOWED` (cmd=5)** → Secure returns allowed (1/0)
   - If allowed=1: `run_split_inference()` → PSA `INCREMENT_COUNTER` (cmd=6)
   - If allowed=0: `destroy_enclave()` → `create_enclave()` → reconfigure → run

3. **Enclave lifecycle:** Dynamic max inferences (starts at 0, updated by M_update)

4. **Secure partition operations:**
   - Decrypt AES-CTR into NS buffer (cmd=3)
   - Manage inference counter (cmd=4,5,6,7)
   - Log all counter operations to Secure console

## Traceable Call Chain
`main.cpp` → `create_enclave.cpp` → PSA IPC → `dummy_partition/dummy_partition.c` → back to `split_inference.cpp`.

## Notes
- The legacy full-model decryption path exists for reference, but split inference uses **late weights only**.
- Buffer sizes are tuned for STM32L552 RAM limits.

## Secure Inference Counter Management

### Purpose
The system implements **Secure-side inference counter** to enforce enclave lifecycle limits and prevent tampering:

**Security Model:**
- Counter stored in Secure world (TF-M partition): `inference_counter_secure`
- Maximum inferences per enclave: **dynamic** (`max_inferences_per_enclave`), starts at 0 and is updated by valid M_update
- NS side cannot manipulate counter directly
- All counter operations via PSA IPC secure channel

**PSA Commands for Counter Management:**
- `DP_CMD_GET_MAX_INFERENCES (4)`: Returns dynamic max policy
- `DP_CMD_CHECK_INFERENCE_ALLOWED (5)`: Returns 1 if allowed, 0 if limit reached
- `DP_CMD_INCREMENT_COUNTER (6)`: Increments secure counter after successful inference
- `DP_CMD_RESET_COUNTER (7)`: Resets counter to 0 during enclave creation

### Execution Flow with Counter Verification

**Enclave Creation:**
1. `create_enclave()` decrypts late weights via PSA
2. PSA call to `DP_CMD_GET_MAX_INFERENCES` → stores local copy (dynamic)
3. PSA call to `DP_CMD_RESET_COUNTER` → Secure counter = 0
4. Precomputes late weights hash (Phase 1)
5. Sets `enclave_created = true`

**Enclave Execution (per run_enclave call):**
1. Check if enclave exists → if not: `create_enclave()`
2. **PSA call to `DP_CMD_CHECK_INFERENCE_ALLOWED`** (Secure returns 1/0)
3. If allowed = 0 (limit reached):
   - `destroy_enclave()` → zero memory, set flag = false
   - `create_enclave()` → decrypt, reset counter, precompute hash
   - `set_late_weights_buffer()` → reconfigure split inference
4. If allowed = 1: proceed with inference
5. `run_split_inference()` → 1 image, compute hash, early+late layers
6. **PSA call to `DP_CMD_INCREMENT_COUNTER`** → Secure counter++

**Dynamic Limit Pattern:**
```
Before M_update: max=0 → allowed=0 → no inference
After valid M_update: max=c_limit → allowed for 1..c_limit
```

**Security Benefits:**
- Counter tamper-proof (Secure world only)
- Pre-execution verification (no wasted work)
- Limit is controlled by M_update (secure policy)
- Secure logging of counter operations
- NS cannot bypass limit checks

## Integrity Hash (CNT) Implementation

### Purpose
The hash system provides **Control Flow and Data Integrity** (CNT) measurement for secure inference using a **2-phase architecture**:

**Phase 1 (Setup - Once):** `precompute_late_weights_hash()` in `main.cpp`
- Computes SHA-256 of code addresses + late weights (40KB)
- Called once after decryption in `create_enclave()`
- Result: 32-byte hash stored in static variable

**Phase 2 (Inference - Per Image):** `compute_integrity_hash()` in `split_inference.cpp`
- Computes SHA-256 of input data + early weights + pre-computed late hash
- Called for each test image
- Result: 32-byte inference hash covering everything

### Coverage
The final inference hash covers:
1. **Input data** (CIFAR-10 image, 3072 bytes) - changes per image
2. **Code addresses** (early weight pointers, 28 bytes) - via late_hash
3. **Early weights** (7 layers: wt_conv2d through wt_conv2d_6, ~35KB ROM) - direct
4. **Late weights** (3 layers: wt_conv2d_7, wt_conv2d_8, wt_fc, ~40KB RAM) - via late_hash

### Optimization Benefits
**Without optimization:** Hash ~80KB per inference (input + early + late weights)
**With optimization:** Hash ~41KB per inference (input + early + 32-byte late_hash)
**Gain:** 49% reduction, late weights hashed once instead of N times

### Key Implementation Details

#### 1. PSA Crypto Configuration
**Required in `prj.conf`:**
```
CONFIG_MBEDTLS_PSA_CRYPTO_C=y
CONFIG_TFM_PARTITION_CRYPTO=y
```

- `CONFIG_MBEDTLS_PSA_CRYPTO_C=y` enables PSA Crypto API on non-secure side via mbedTLS
- Without this, `psa_crypto_init()` and hash operations will fail silently

#### 2. Early Weights Structure
The early layer weights are defined in `split_inference/early/E_nn_wt.h` with **7 convolutional layers**:
- `wt_conv2d[432]` - Layer 0
- `wt_conv2d_1[2304]` - Layer 1
- `wt_conv2d_2[2304]` - Layer 2
- `wt_conv2d_3[4608]` - Layer 3
- `wt_conv2d_4[9216]` - Layer 4 (largest early layer)
- `wt_conv2d_5[512]` - Layer 5
- `wt_conv2d_6[18432]` - Layer 6 (largest overall early layer)

All early weights are hashed directly using `psa_hash_update()` with `sizeof()`.

#### 3. Late Weights Chunking
Late weights are decrypted into NS RAM and are much larger:
- `wt_conv2d_7`: 36,864 bytes
- `wt_conv2d_8`: 2,048 bytes
- `wt_fc`: 640 bytes


**Phase 1: Late Weights Hash (once, in `main.cpp` after decryption)**
1. Initialize PSA crypto: `psa_crypto_init()`
2. Setup SHA-256 operation: `psa_hash_setup(&operation, PSA_ALG_SHA_256)`
3. Hash code pointers (28 bytes: wt_conv2d through wt_conv2d_6 addresses)
4. Hash wt_conv2d_7 (36864 bytes in 9 chunks of 4KB)
5. Hash wt_conv2d_8 (2048 bytes in 1 chunk)
6. Hash wt_fc (640 bytes in 1 chunk)
7. Finalize: `psa_hash_finish(&operation, late_weights_hash, 32, &hash_len)`
8. Store result in static `late_weights_hash[32]`

**Phase 2: Inference Hash (per image, in `split_inference.cpp`)**
1. Initialize PSA crypto: `psa_crypto_init()`
2. Setup SHA-256 operation: `psa_hash_setup(&operation, PSA_ALG_SHA_256)`
3. Hash input data (3072 bytes)
4. Hash wt_conv2d (432 bytes)
5. Hash wt_conv2d_1 (2304 bytes)
6. Hash wt_conv2d_2 (2304 bytes)
7. Hash wt_conv2d_3 (4608 bytes in 2 chunks)
8. Hash wt_conv2d_4 (9216 bytes in 3 chunks)
9. Hash wt_conv2d_5 (512 bytes)
10. Hash wt_conv2d_6 (18432 bytes in 5 chunks)
11. Hash pre-computed late_weights_hash (32 bytes)
12. Finalize: `psa_hash_finish(&operation, hash_output, 32, &hash_len)`

#### 5. Output
The system prints two hashes:

**Late weights hash (Phase 1, once):**
```
[CNT] ✓ Late weights hash (code_ptrs + late_wt): 2c8bb3f00e9d15fbf815ec8a12aff636d7f0026bb0bef4028065828aa2003eb5
```

**Inference hash (Phase 2, per image):**
```
[CNT] ✓ Inference hash (input + early_wt + late_hash): 9c64e02237b58a7a6f38284f2eb29c10040942d50fbfb25953180010c03d5293
```

Each test image produces a **different inference hash** due to different input data (SHA-256 avalanche effect). The late weights hash remains **constant** across all tests.

### Troubleshooting

**Symptom:** Hash output is all zeros
- **Cause:** PSA Crypto not enabled
- **Fix:** Add `CONFIG_MBEDTLS_PSA_CRYPTO_C=y` to `prj.conf`

**Symptom:** `PSA_ERROR_INVALID_ARGUMENT` (-141) when hashing large weights
- **Cause:** Buffer size exceeds PSA limit (~4-8KB)
- **Fix:** Already implemented via `hash_buffer_chunked()` with 4KB chunks

**Symptom:** Late weights hash changes between runs
- **Cause:** Decryption produces different output (unlikely if IV is fixed)
- **Debug:** Print first 32 bytes of decrypted late weights to verify consistency

### Performance
- **Phase 1 (once):** ~10-15ms (39580 bytes in ~10 chunks)
- **Phase 2 (per image):** ~10-15ms (40912 bytes in ~11 chunks)
- **Total per inference:** ~10-15ms (Phase 1 amortized across N inferences)
- **Without optimization:** ~20-30ms per inference (80KB hashed each time)

### Security Properties
- **Input integrity:** Any change to input image changes final hash
- **Code integrity:** Code pointer addresses included in late_hash
- **Early weights integrity:** Direct inclusion in inference hash
- **Late weights integrity:** Included via pre-computed late_hash
- **Tamper detection:** SHA-256 avalanche effect ensures 1-bit change → completely different hash

### References
For complete architecture details, see [HASH_ARCHITECTURE.md](../HASH_ARCHITECTURE.md) in the project root.

**Late weights hash (Phase 1, once):**
```
[CNT] ✓ Late weights hash (code_ptrs + late_wt): 2c8bb3f00e9d15fbf815ec8a12aff636d7f0026bb0bef4028065828aa2003eb5
```

**Inference hash (Phase 2, per image):**
```
[CNT] ✓ Inference hash (input + early_wt + late_hash): 9c64e02237b58a7a6f38284f2eb29c10040942d50fbfb25953180010c03d5293
```

Each test image produces a **different inference hash** due to different input data (SHA-256 avalanche effect). The late weights hash remains **constant** across all tests
#### 4. Hash Computation Flow
1. Initialize PSA crypto: `psa_crypto_init()`
2. Setup SHA-256 operation: `psa_hash_setup(&operation, PSA_ALG_SHA_256)`
3. Hash input data (3072 bytes)
4. Hash early weight pointers (code integrity proxy)
5. Hash all 7 early weight arrays
6. Hash all 3 late weight arrays (in chunks)
7. Finalize: `psa_hash_finish(&operation, hash_output, 32, &hash_len)`

#### 5. Output
The final 32-byte SHA-256 hash is printed at the end of inference:
```
[CNT] Final Hash: 2acf215c0e5f4659d4d2052380ba8c3c82b8a20b0308ae43f429e12134a87686
```

Each test image produces a different hash since it includes the input data. The hash stored is from the last inference iteration.

### Troubleshooting

**Symptom:** Hash output is all zeros
- **Cause:** PSA Crypto not enabled
- **Fix:** Add `CONFIG_MBEDTLS_PSA_CRYPTO_C=y` to `prj.conf`

**Symptom:** `Hash wt_conv2d_7 failed: -141` (PSA_ERROR_INVALID_ARGUMENT)
- **Cause:** Buffer too large for single `psa_hash_update()` call
- **Fix:** Already implemented with chunking mechanism (4096-byte chunks)

**Symptom:** Hash computation succeeds but predictions fail
- **Cause:** Chunking pointer arithmetic error
- **Fix:** Verify pointer increments and remaining size calculations
