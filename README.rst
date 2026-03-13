=============================================================================
Secure CIFAR-10 Split Inference with TF-M and Encrypted Late Weights
=============================================================================

**Quick Start (Current Validated Flow, March 2026)**

::

  west build -d build
  west flash
  ./.venv/bin/python tools/mac_provider.py /dev/tty.usbmodem11203 115200

**Manual sequence (host menu)**

1. ``1`` ECDH handshake
2. ``2`` Compute EnclaveInfo
3. ``3`` Send M_update (**must use c_limit > current max**, anti-replay)
4. ``9`` Verified inference (requires 1 + successful 3)
5. ``15`` Deterministic SAU status (UNREGISTERED / OPEN / CLOSED)

**Current protocol notes**

- ``CMD_GET_SAU_STATE (0x0D)`` is available and returns ``state(1) + base(4) + size(4)``.
- ``M_update`` rejection with ``RESP_ERROR`` is expected if ``c_limit`` is not strictly increasing.
- SAU can be ``UNREGISTERED`` before enclave creation; after first enclave lifecycle it typically reports ``CLOSED``.

Overview
========

This project demonstrates a **secure split inference architecture** for CIFAR-10 classification
on ARM Cortex-M33 with TrustZone, combining:

- **ARM Trusted Firmware-M (TF-M)**: Secure partition for cryptographic operations
- **CMSIS-NN**: Optimized neural network kernels for embedded devices
- **Split Inference**: Model split into early (unprotected) and late (weight-protected) layers
- **AES-CTR Encryption**: Late layer weights encrypted in ROM, decrypted at runtime by secure world
- **DWT Benchmark System**: Cycle-accurate performance measurement (NS + Secure worlds)
- **Counter Management**: Strict inference limiting with PSA-backed security

Performance Summary
===================

**Non-Secure (NS) Inference Pipeline**

- **Early Layers**: 390.8 ms (42,984,997 cycles)
- **Late Layers**: 72.0 ms (7,922,258 cycles)
- **Total Inference**: 468.7 ms (51,553,622 cycles)
- **Enclave Create**: 72.6 ms (7,980,975 cycles)

**Secure (S) Cryptographic Operations**

- **AES Decrypt**: 69.7 ms (7,662,219 cycles @ 110 MHz) [1 operation]
- **Counter Management**: <1 µs per operation (548-29 cycles)
- **IPC Latency Overhead**: Included in NS measurements

**Memory Footprint**

- **Non-Secure**: 176,160 / 262,144 bytes Flash (67.2%), 121,788 / 131,072 bytes RAM (92.9%)
- **Secure**: 119,532 / 134,144 bytes Flash (89.1%), 52,732 / 65,536 bytes RAM (80.5%)
- **Total**: 295,692 / 396,288 bytes Flash (74.6%), 174,520 / 196,608 bytes RAM (88.8%)

**ELF Binary Analysis** (from build/zephyr/zephyr.elf)

Flash (ROM) Sections:

- **rodata** (Constants + Encrypted Weights): 138,252 bytes (135.0 KB)
  
  - Encrypted late layer weights: 39,552 bytes (encrypted in ROM)
  - Early layer weights (plain ROM): ~37 KB (conv2d_0 to conv2d_6)
  - Constants & tensors: ~58 KB

- **text** (Code): ~38 KB (derived from total)

RAM (SRAM) Sections:

- **bss** (Zero-initialized Buffers): 117,809 bytes (115.0 KB)
  
  - Early inference buffers (buf0/1/2): 16 KB × 3 = 48 KB
  - Context buffers: 8 KB + 4 KB = 12 KB
  - Enclave memory (decrypted weights): 39,552 bytes (38.6 KB)
  - Main stack: 4 KB
  - Other buffers/padding: ~14 KB

- **data** (Initialized Globals): 3,976 bytes (3.9 KB)

Three-Layer Security Model
--------------------------

1. **Secure World (TF-M)**
   
   - Custom secure partition: ``dummy_partition``
   - AES-128-CTR decryption engine
   - PSA IPC interface for NS requests
   - No model execution, only cryptographic services

2. **Non-Secure World (Zephyr RTOS)**
   
   - Enclave memory management (39552 bytes for late weights)
   - Split inference orchestration
   - PSA client for secure service requests

3. **Split Inference Model**
   
   - **Early layers** (conv2d_0 → conv2d_6): Weights in plain ROM
   - **Late layers** (conv2d_7, conv2d_8, fc): Weights AES-encrypted in ROM

Memory Layout
-------------

::

    ┌─────────────────────────────────────┐
    │     Secure Flash (TF-M)             │
    │  - BL2 bootloader                   │  128 KB
    │  - TF-M secure partition            │
    │  - Dummy partition (crypto)         │
    └─────────────────────────────────────┘
    
    ┌─────────────────────────────────────┐
    │   Non-Secure Flash (Zephyr + App)   │
    │  - Zephyr RTOS kernel               │  256 KB
    │  - NS application code              │
    │  - Early layer weights (plain)      │
    │  - Late layer weights (encrypted)   │  39552 bytes
    └─────────────────────────────────────┘
    
    ┌─────────────────────────────────────┐
    │      Non-Secure RAM                 │
    │  - Application stack/heap           │  128 KB
    │  - Tensor buffers (early/late)      │
    │  - Enclave region (decrypted wts)   │  39552 bytes @ 0x20000fc0
    └─────────────────────────────────────┘

Execution Flow
==============

Initialization Phase
--------------------

1. **Enclave Creation** (``create_enclave()``)
   
   - Reserve 39552-byte RAM region for late weights
   - Call secure partition via PSA IPC
   - Command: ``DP_CMD_DECRYPT_LATE_WEIGHTS``
   - Secure world decrypts AES-CTR weights into NS RAM

2. **Split Inference Configuration**
   
   - Main retrieves enclave region: ``get_enclave_region()``
   - Configures split inference: ``set_late_weights_buffer(buf, size)``
   - Establishes pointers: ``wt_conv2d_7``, ``wt_conv2d_8``, ``wt_fc``

Inference Phase
---------------

3. **Early Layers** (``run_early_layers()``)
   
   - Input: CIFAR-10 image (32x32x3, int8)
   - Layers: conv2d_0 → conv2d_1 → ... → conv2d_6
   - Weights: Plain ROM data (no encryption)
   - Outputs:
     - ``early_output``: Main path feature map
     - ``early_skip``: Residual connection from conv2d_5

4. **Inference Counter Management** (``DP_CMD_RUN_INFERENCE``)
   
   - Secure world atomically checks and increments counter
   - **Limit**: 3 inferences per enclave
   - **Behavior**: 
     - Inferences 1-3: ✅ Allowed
     - Inference 4+: ✅ BLOCKED (no auto-recreation)
   - Response: 1 (allowed) or 0 (denied)

5. **Benchmark Reporting** (``benchmark_print_report()``)
   
   - NS metrics: 15 different timing measurements
   - Secure metrics: Crypto operations + counter management
   - Memory usage: RAM/Flash percentages for both worlds
   - Formatted output: Box-drawing characters for readability

Benchmark System
================

Architecture
------------

**Dual-World Performance Measurement**

::

    ┌─────────────────────────────────────┐
    │  Non-Secure (Zephyr)                │
    │  ├─ DWT Cycle Counter (ARM Cortex)  │
    │  ├─ 15 Metrics                      │
    │  └─ Enclave + Crypto + Inference    │
    └─────────────────────────────────────┘
    
    ┌─────────────────────────────────────┐
    │  Secure (TF-M)                      │
    │  ├─ DWT Cycle Counter (ARM Cortex)  │
    │  ├─ 4 Metrics                       │
    │  └─ AES + Counter Ops               │
    └─────────────────────────────────────┘

**NS-Side Metrics (src/benchmark.h/cpp)**

- ``enclave_create_cycles``: Enclave lifecycle (134 ms)
- ``enclave_destroy_cycles``: Cleanup (4 ms)
- ``aes_decrypt_cycles``: AES decrypt via PSA call (82 ms)
- ``late_hash_cycles``: Late weights hash (8 ms)
- ``inference_hash_cycles``: Integrity hash (11 ms)
- ``early_layers_cycles``: Early inference (405 ms)
- ``late_layers_cycles``: Late inference (74 ms)
- ``total_inference_cycles``: End-to-end (518 ms)
- ``run_enclave_cycles``: Full enclave execution (774 ms)
- ``ram_used_bytes``: NS RAM usage (121.4 KB)
- ``flash_used_bytes``: NS Flash usage (187.2 KB)

**Secure-Side Metrics (dummy_partition/secure_benchmark.h/c)**

- ``aes_decrypt_cycles``: Actual AES execution (132 ms total, 66 ms/op)
- ``digest_compute_cycles``: SHA-256 operations (0 ms - NS-side only)
- ``get_max_cycles``: Counter query (~1 µs)
- ``check_allowed_cycles``: Limit check (~2 µs)
- ``increment_cycles``: Counter increment (~0.1 µs)
- ``ram_used_bytes``: Secure RAM (52.7 KB, 80%)
- ``flash_used_bytes``: Secure Flash (119.5 KB, 89%)

**PSA IPC Commands**

::

    DP_CMD_DECRYPT_LATE_WEIGHTS (3)
    ├─ Input: Encrypted weights, IV
    └─ Output: Decrypted weights in NS enclave

    DP_CMD_RUN_INFERENCE (NEW - atomic check + increment)
    ├─ Checks: inference_counter < max_inferences_per_enclave (dynamic)
    ├─ Action: Increments counter if allowed
    └─ Response: 1 (allowed) or 0 (blocked)

    DP_CMD_GET_BENCHMARK (8)
    ├─ Action: Reads linker symbols for memory usage
    └─ Output: Complete secure_benchmark_metrics_t structure

Counter Management
==================

**Policy: Strict Blocking with Dynamic Limit (No Auto-Recreation)**

::

    Enclave 1 (Dynamic limit)
    ├─ Initial state: max_inferences_per_enclave = 0 → ✅ BLOCKED
    ├─ After valid M_update: max_inferences_per_enclave = c_limit
    ├─ Inference 1..c_limit: ✅ Execute
    └─ Inference (c_limit + 1): ✅ BLOCKED

    Result: Application must handle limit (no automatic enclave recycling)

**Flow Diagram**

::

    NS run_enclave() call
           ↓
    [Create enclave? → Yes → Secure decrypt late weights]
           ↓
    Call DP_CMD_RUN_INFERENCE (Secure)
           ↓
        ┌──────────────────────────┐
        │ Secure World             │
        │ ├─ Check counter < max?  │
        │ ├─ If yes: increment+1   │
        │ │         return 1       │
        │ └─ If no:  return 0      │
        └──────────────────────────┘
           ↓
        (response: 0 or 1)
           ↓
        ┌──────────────┐
        │ If 0: BLOCK  │  ← Application must handle
        │ If 1: Execute│
        └──────────────┘

Architecture
============
   - Layers: conv2d_7, conv2d_8, add_2, avgpool, fc, softmax
   - Weights: Decrypted late weights from enclave RAM
   - Output: Class prediction (0-9)

5. **Integrity Hash Computation** (``compute_integrity_hash()``)
   
   - Algorithm: SHA-256 via PSA Crypto API
   - Hash inputs:
     - Input data (CIFAR-10 image, 3072 bytes)
     - Early weight pointers (code integrity proxy)
     - All 7 early weight arrays (wt_conv2d through wt_conv2d_6)
     - All 3 late weight arrays (wt_conv2d_7, wt_conv2d_8, wt_fc) in 4KB chunks
   - Output: 32-byte SHA-256 hash displayed at end of inference
   - Purpose: Control Flow and Data Integrity (CNT) verification

PSA IPC Protocol
================

Secure Service Definition
--------------------------

- **Service ID (SID)**: ``0xFFFFF002``
- **Version**: ``1``
- **Signal**: ``DUMMY_PARTITION_SIGNAL``

Decrypt Late Weights Command
-----------------------------

**Request** (NS → Secure)::

    Command ID: DP_CMD_DECRYPT_LATE_WEIGHTS (3)
    
    Input vectors:
      [0] uint32_t cmd = 3
      [1] const uint8_t late_wt_encrypted[39552]  // AES-CTR ciphertext
      [2] const uint8_t late_wt_iv[16]            // IV for CTR mode
    
    Output vector:
      [0] uint8_t decrypted_weights[39552]        // Plaintext weights

**Response** (Secure → NS)::

    psa_status_t status:
      PSA_SUCCESS (0)     → Decryption successful
      PSA_ERROR_*         → Failure (invalid params, crypto error)

Secure Partition Implementation
--------------------------------

Located in ``dummy_partition/dummy_partition.c``:

1. Message loop waits for ``DUMMY_PARTITION_SIGNAL``
2. Reads command ID from ``in_vec[0]``
3. For ``DP_CMD_DECRYPT_LATE_WEIGHTS``:
   
   - Extracts ciphertext (``in_vec[1]``) and IV (``in_vec[2]``)
   - Calls ``psa_cipher_decrypt()`` with AES-128-CTR
   - Writes plaintext to ``out_vec[0]``
   - Returns ``PSA_SUCCESS``

Key Components
==============

Source Files
------------

**Non-Secure Application**:

- ``src/main.cpp``: Entry point, orchestrates enclave creation and inference
- ``src/create_enclave.cpp``: Enclave memory management, PSA client
- ``src/split_inference.cpp``: CMSIS-NN inference engine
- ``src/run_enclave.cpp``: Enclave execution wrapper
- ``src/test_images.c``: CIFAR-10 test samples

**Secure Partition**:

- ``dummy_partition/dummy_partition.c``: TF-M partition, AES decryption service
- ``dummy_partition/tfm_dummy_partition.yaml``: Partition manifest

**Model Weights**:

- ``split_inference/early/``: Plain early layer weights (ROM)
- ``split_inference/late/L_nn_wt_encrypted_data.c``: Encrypted late weights (ROM)
- ``split_inference/late/L_nn_params.h``: Quantization parameters

Configuration
-------------

**CMakeLists.txt**:

- TF-M extra partition integration
- CMSIS-NN library inclusion
- C++17 requirement for TensorFlow Lite Micro

**prj.conf**:

- ``CONFIG_BUILD_WITH_TFM=y``: Enable TF-M integration
- ``CONFIG_TFM_PARTITION_CRYPTO=y``: Enable crypto partition
- ``CONFIG_MBEDTLS_PSA_CRYPTO_C=y``: Enable PSA Crypto for NS side (required for hash)
- ``CONFIG_MAIN_STACK_SIZE=2048``: Sufficient for inference

Enclave Authorization Protocol
===============================

**New Feature (Phase A)**: Cryptographic Authorization with Provider Simulation

Overview
--------

This phase implements a **Provider-Device Enclave Authorization Protocol** ensuring that only authorized updates can modify enclave execution parameters. The protocol uses:

- **EnclaveInfo Computation**: SHA-256 hash of model identity (``H(Model_pub || Model_secret || code || model_ID)``)
- **M_update Message Generation**: Provider generates cryptographically signed update messages
- **AES-256-GCM Encryption**: Secure encryption of M_update payload with authentication
- **Predefined Session Key**: AES-256 key stored in Secure Flash for M_update decryption

**Security Flow**

::

    Provider (Simulation)
    ├─ Generate M_update payload (c_limit, verifier_pk, enclave_info, cert)
    ├─ Serialize to binary format (120 bytes)
    ├─ Encrypt with AES-256-GCM (session_key, random nonce)
    ├─ Extract 16-byte authentication tag
    └─ Output: ciphertext(120) || nonce(12) || tag(16) = 148 bytes
           ↓
    Device (Enclave Authorization)
    ├─ PHASE 1: Compute EnclaveInfo in Secure world
    │   ├─ Input: model_pub(32) || model_secret(32) || code(32) || model_id(4)
    │   ├─ Operation: SHA-256 hash (100-byte input)
    │   └─ Output: enclave_info(32 bytes)
    │
    ├─ PHASE 2: Generate M_update in Non-Secure (simulated Provider)
    │   ├─ Input: c_limit(10), enclave_info(from Phase 1), cert(16 bytes)
    │   ├─ Encrypt payload with session_key (AES-256-GCM)
    │   └─ Output: Message structure (ciphertext + nonce + tag)
    │
    └─ Future: Device-side M_update validation & counter limit update

**Cryptographic Artifacts**

- **AES-256 Session Key**: Predefined in Secure Flash (32 bytes)
  
  * Value: 0xA0, 0xA1, ..., 0xBF (hardcoded for simulation)
  * Purpose: Encrypt M_update messages from Provider
  * Storage: Immutable ROM in secure partition

- **EnclaveInfo Formula** (Exact):
  
  ::
  
    EnclaveInfo = SHA-256(
        Model_pub(32 bytes)     ||
        Model_secret(32 bytes)  ||
        code(32 bytes)          ||
        model_ID(4 bytes, LE)
    )
    Result: 32-byte SHA-256 hash

- **M_update Encryption** (AES-256-GCM):
  
  ::
  
    Plaintext (120 bytes):
      c_limit(4) || pk_v(64) || enclave_info(32) || cert_len(4) || cert(16)
    
    Ciphertext output:
      AES-256-GCM(plaintext, key=session_key, nonce=random 12B)
      → 120 bytes ciphertext + 16 bytes auth tag
    
    Final message (148 bytes):
      ciphertext(120) || nonce(12) || tag(16)

**PSA IPC Commands (New)**

::

    DP_CMD_COMPUTE_ENCLAVE_INFO (10)
    ├─ Input:  3 buffers
    │   ├─ in[0]: cmd(4 bytes) = 10
    │   ├─ in[1]: combined_data(96 bytes) = model_pub||model_secret||code
    │   └─ in[2]: model_id(4 bytes)
    ├─ Output: enclave_info(32 bytes)
    └─ Notes:  PSA_MAX_IOVEC=4 limit requires buffer packing

**Implementation Status**

✅ **Completed**:

- ``src/provider_sim.h``: Provider API header (structures, function declarations)
- ``src/provider_sim.cpp``: Provider simulator implementation (~350 lines)
  
  * Hardcoded ECDSA P-256 keys (provider_sk/pk, verifier_sk/pk)
  * Hardcoded session_key (32 bytes, shared with Secure)
  * ``serialize_m_update_payload()``: Binary serialization
  * ``provider_sim_generate_m_update()``: Encryption pipeline
  * Comprehensive debug output at each step

- ``src/test_enclave_auth.c``: Test harness (~200 lines)
  
  * Phase 1: EnclaveInfo computation via PSA IPC
  * Phase 2: M_update generation with encryption
  * Detailed validation and formatted output

- ``dummy_partition/dummy_partition.c``: Secure partition
  
  * ``m_update_aes256_key[32]``: Predefined session key
  * ``compute_enclave_info()``: SHA-256 hash function
  * ``DP_CMD_COMPUTE_ENCLAVE_INFO`` handler (lines ~478-521)

- ``main.cpp``: Integration with single inference
- ``CMakeLists.txt``: Compilation of new files

✅ **Tested on Hardware**:

- STM32L552 firmware successfully built (198.8 KB FLASH, 127.96 KB RAM)
- Device flash successful, application running
- **Phase 1 Output**: EnclaveInfo computed correctly
  
  ::
  
    55 B3 A7 16 BF 87 9B D9 CB 16 2D E7 16 F8 4E AC 
    F0 13 00 CC 72 D7 12 06 19 34 4C 7E 99 8F 92 04

- **Phase 2 Output**: M_update encrypted successfully
  
  ::
  
    Nonce:    B8 36 45 BF 14 E8 40 71 3F 18 78 3C
    Auth Tag: 34 1D C3 1A 2C 9D 5C 0E 47 68 06 BD 70 07 98 03

⏳ **Planned (Phase B)**:

- Device-side M_update validation (decrypt, verify tag, extract c_limit)
- Atomic counter limit update from M_update
- Full protocol round-trip with verifier ECDSA signature

**Known Constraints**

- PSA_MAX_IOVEC = 4 (total input + output vectors)
  
  * Solution: Pack model_pub, model_secret, code into 96-byte combined_data buffer
  * Result: 3 input vectors + 1 output vector = within limit

- Provider simulation uses hardcoded keys (not real cryptography for this phase)
- Single inference per test (as configured for clarity)

Inference Protocol (M_inf / PoX)
=================================

**New Feature (Phase B)**: Cryptographic Inference Request/Response Protocol

Overview
--------

This phase implements a **Verifier-to-Device Inference Protocol** with cryptographically signed requests and proof-of-execution responses. The protocol ensures:

- **Authenticity**: Verifier-signed inference requests (M_inf)
- **Non-repudiation**: Device-signed proof of execution (PoX)
- **Integrity**: ECDSA P-256 signatures on all messages
- **Anti-replay**: Fresh random nonce per request

**Protocol Flow**

::

    Verifier                          Device
    --------                          ------
    Gen keypair (P-256)               Gen keypair (P-256)
        |                                 |
        ├─ Generate M_inf:            ├─ Verify M_inf signature ✓
        │  - Random nonce (12B)       │
        │  - Input data (64B test)    ├─ Execute inference → result=6
        │  - Model ID (4B)            │
        │  - ECDSA sig over above      └─ Generate PoX:
        │  - Total: 144 bytes            - Echo nonce
        │                                - Echo input
        └─ Verify PoX signature ←────    - Output (1B)
           ✓ Execution verified          - Cert (16B)
                                         - ECDSA sig over above
                                         - Total: 161 bytes

**Message Formats**

M_inf (Verifier Request):

::

    Structure (144 bytes total):
      nonce       [12 bytes]  - Random nonce per request
      input       [64 bytes]  - Inference input (test size, scalable to 3072)
      model_id    [4 bytes]   - Model identifier
      signature   [64 bytes]  - ECDSA P-256: Sign(sk_v, nonce || input || model_id)

PoX (Device Proof of Execution):

::

    Structure (161 bytes total):
      model_id    [4 bytes]   - Model identifier
      cert        [16 bytes]  - Provider certificate
      nonce       [12 bytes]  - Nonce echoed from M_inf
      input       [64 bytes]  - Input echoed from M_inf
      output      [1 byte]    - Inference result (0-9 for CIFAR-10)
      signature   [64 bytes]  - ECDSA P-256: Sign(sk_d, above fields)

**Cryptography**

- **Algorithm**: ECDSA P-256 (secp256r1)
- **Hash Function**: SHA-256
- **Key Size**: 256 bits (32 bytes)
- **Nonce Generation**: Cryptographically secure random
- **Implementation**: PSA Crypto API (via TF-M)

**Implementation Status**

✅ **Completed**:

- ``src/inference_protocol.h``: Protocol structures and API definitions
- ``src/inference_protocol.cpp``: PSA Crypto implementation (~400 lines)
  
  * M_inf generation with ECDSA P-256 signing
  * PoX generation with ECDSA P-256 signing
  * Signature verification functions

- ``src/test_inference_protocol.cpp``: Complete test harness (~250 lines)
  
  * PSA-generated keypairs (verifier, device)
  * Full 5-step protocol execution:
    1. Generate Verifier keypair
    2. Generate Device keypair
    3. Verifier creates signed M_inf
    4. Device executes inference
    5. Device creates signed PoX

- ``main.cpp``: Integration as Phase 2 (after Enclave Authorization)
- ``CMakeLists.txt``: Compilation of new files

✅ **Tested on Hardware**:

- STM32L552 firmware built successfully (201.4 KB FLASH, 128.0 KB RAM - 97.67%)
- Device flashed and executing all protocol steps
- **Test Output**: All 5 phases complete successfully
  
  ::
  
    [TEST] ===== STEP 1: GENERATE VERIFIER KEYPAIR =====
    [TEST] ✓ Verifier keypair generated
    
    [TEST] ===== STEP 2: GENERATE DEVICE KEYPAIR =====
    [TEST] ✓ Device keypair generated
    
    [TEST] ===== STEP 3: VERIFIER GENERATES M_INF =====
    [TEST] ✓ M_inf generated and signed (144 bytes total)
    [PROTO] Nonce: E5 C7 F7 21 44 A7 B5 49 FF 99 D4 6F
    [PROTO] Signature (first 16B): FD 01 5F 14 47 7C 55 09 A4 E6 D4 4C 63 70 44 2E
    
    [TEST] ===== STEP 4: DEVICE EXECUTES INFERENCE =====
    [DEVICE] Inference result: 6
    
    [TEST] ===== STEP 5: DEVICE GENERATES PoX =====
    [TEST] ✓ PoX generated and signed (161 bytes total)
    [PROTO] Output: 6
    [PROTO] Signature (first 16B): 59 84 E7 7A AD EA 03 55 43 67 85 42 F0 88 8F 30
    
    ╔════════════════════════════════════════════════════════╗
    ║         INFERENCE PROTOCOL TEST PASSED ✓               ║
    ║                                                        ║
    ║  ✓ Verifier keypair generated                         ║
    ║  ✓ Device keypair generated                           ║
    ║  ✓ M_inf generated and signed                         ║
    ║  ✓ Device executed inference                          ║
    ║  ✓ PoX generated and signed                           ║
    ╚════════════════════════════════════════════════════════╝

**Integration with Other Phases**

- **Phase 1 (Enclave Authorization)**: EnclaveInfo + M_update (AES-256-GCM)
- **Phase 2 (Inference Protocol)**: M_inf + PoX (ECDSA P-256) ← **You are here**
- **Phase 3 (CIFAR-10 Inference)**: Split inference with encrypted late weights
  
  * Early layers: 395 ms (43.4M cycles)
  * Late layers: 74 ms (8.2M cycles)
  * Total: 504 ms, prediction verified correct (5 = expected)

**Known Constraints**

- Input size reduced to 64 bytes for testing (can scale to 3072 bytes for full CIFAR-10 images)
- Current RAM usage: 97.67% (128 KB total) - suitable for embedded devices
- Keys generated fresh per test (not persistence across resets)

Build & Flash
=============

Prerequisites
-------------

- West: v1.5.0+
- Zephyr SDK: 0.17.4
- STM32CubeProgrammer: v2.21.0
- Board: NUCLEO-L552ZE-Q (STM32L552ZE)

Build Commands
--------------

Clean build::

    west build -b nucleo_l552ze_q/stm32l552xx/ns --pristine=always

Incremental build::

    west build -b nucleo_l552ze_q/stm32l552xx/ns

Flash to Board
--------------

::

    west flash

Expected output::

    Memory Programming ...
      File          : tfm_merged.hex
      Size          : 281.58 KB 
      Address       : 0x0C000000
    
    RUNNING Program ... 
    Application is running, Please Hold on...

Runtime Verification
====================

Expected Serial Output
----------------------

**Phase 1: Enclave Info Computation**

::

    ╔════════════════════════════════════════════════════════╗
    ║      PHASE 1: ENCLAVE INFO COMPUTATION (SECURE)      ║
    ╚════════════════════════════════════════════════════════╝
    
    [SECURE]   ✓ EnclaveInfo computed successfully
    [SECURE]   EnclaveInfo (first 16 bytes): 55 B3 A7 16 BF 87 9B D9 CB 16 2D E7 16 F8 4E AC
    [TEST] ✓ PSA call successful
    [TEST] EnclaveInfo OUTPUT (SHA-256 hash):
    [TEST]   Full (32 bytes): 55 B3 A7 16 BF 87 9B D9
    [TEST]                    CB 16 2D E7 16 F8 4E AC
    [TEST]                    F0 13 00 CC 72 D7 12 06
    [TEST]                    19 34 4C 7E 99 8F 92 04
    [TEST] ✓ SUCCESS: EnclaveInfo computed in Secure partition

**Phase 2: M_update Generation**

::

    ╔════════════════════════════════════════════════════════╗
    ║    PHASE 2: M_UPDATE GENERATION (NON-SECURE)         ║
    ╚════════════════════════════════════════════════════════╝
    
    [PROVIDER] ========== SIMULATOR INITIALIZED ==========
    [PROVIDER] Hardcoded keys loaded:
    [PROVIDER]   - Provider SK: 32 bytes
    [PROVIDER]   - Provider PK (first 8 bytes): 21 22 23 24 25 26 27 28
    [PROVIDER]   - Verifier SK: 32 bytes
    [PROVIDER]   - Verifier PK (first 8 bytes): 81 82 83 84 85 86 87 88
    [PROVIDER]   - Session Key (first 8 bytes): A0 A1 A2 A3 A4 A5 A6 A7
    
    [PROVIDER] ========== GENERATING M_UPDATE ==========
    [PROVIDER] Step 1/3: Serialization
    [PROVIDER]   - Plaintext size: 120 bytes
    [PROVIDER]   - Structure: c_limit(4) || pk_v(64) || enclave_info(32) || cert_len(4) || cert(16)
    
    [PROVIDER] Step 3a/3: Nonce Generation
    [PROVIDER]   - Nonce size: 12 bytes (96-bit for GCM)
    [PROVIDER]   - Nonce value: B8 36 45 BF 14 E8 40 71 3F 18 78 3C
    
    [PROVIDER] Step 3b/3: AES-256-GCM Encryption
    [PROVIDER]   - Ciphertext (first 16 bytes): DB 83 38 F1 A9 B1 4B 85 D3 8F 85 19 5A 01 7F 99
    [PROVIDER]   - Auth tag (full): 34 1D C3 1A 2C 9D 5C 0E 47 68 06 BD 70 07 98 03
    
    [TEST] ✓ SUCCESS: M_update message generated
    [TEST] Output Message:
    [TEST]   - Ciphertext size: 120 bytes
    [TEST]   - Nonce (12 bytes):    B8 36 45 BF 14 E8 40 71 3F 18 78 3C
    [TEST]   - Auth tag (16 bytes): 34 1D C3 1A 2C 9D 5C 0E 47 68 06 BD 70 07 98 03

**Phase 2b: Inference Protocol (M_inf / PoX)**

::

    ╔════════════════════════════════════════════════════════╗
    ║    INFERENCE PROTOCOL TEST (M_inf / PoX)              ║
    ╚════════════════════════════════════════════════════════╝
    
    [TEST] ===== STEP 1: GENERATE VERIFIER KEYPAIR =====
    [TEST] ✓ Verifier keypair generated
    
    [TEST] ===== STEP 2: GENERATE DEVICE KEYPAIR =====
    [TEST] ✓ Device keypair generated
    
    [TEST] ===== STEP 3: VERIFIER GENERATES M_INF =====
    [TEST] ✓ M_inf generated and signed (144 bytes total)
    [PROTO] Nonce: E5 C7 F7 21 44 A7 B5 49 FF 99 D4 6F
    [PROTO] Signature (first 16B): FD 01 5F 14 47 7C 55 09 A4 E6 D4 4C 63 70 44 2E
    
    [TEST] ===== STEP 4: DEVICE EXECUTES INFERENCE =====
    [DEVICE] Inference result: 6
    
    [TEST] ===== STEP 5: DEVICE GENERATES PoX =====
    [TEST] ✓ PoX generated and signed (161 bytes total)
    [PROTO] Output: 6
    [PROTO] Signature (first 16B): 59 84 E7 7A AD EA 03 55 43 67 85 42 F0 88 8F 30
    
    ╔════════════════════════════════════════════════════════╗
    ║         INFERENCE PROTOCOL TEST PASSED ✓               ║
    ║                                                        ║
    ║  ✓ Verifier keypair generated                         ║
    ║  ✓ Device keypair generated                           ║
    ║  ✓ M_inf generated and signed                         ║
    ║  ✓ Device executed inference                          ║
    ║  ✓ PoX generated and signed                           ║
    ╚════════════════════════════════════════════════════════╝

**Phase 3: Single Inference in Enclave**

::

    [MAIN] Running single inference in enclave...
    [ENCLAVE] ===== ENTER =====
    [ENCLAVE] Enclave not created, creating new enclave...
    
    --- CREATE ENCLAVE ---
    [NS] Enclave region reserved: base=0x20000fc0 size=39552
    [NS] Configuration:
          Enclave memory size: 39552 bytes
          Enclave memory addr: 0x20000fc0
          Stack size: 8192 bytes
    [NS] Initializing enclave memory...
    [NS] ✓ Memory cleared
    [NS] ✓ Late weights decrypted into NS RAM (82 ms)
    [NS] ✓ Enclave creation complete (137 ms)
    
    [ENCLAVE] ✓ New enclave created
    [ENCLAVE] Configuring split inference...
    [SPLIT] ===== CMSIS-NN SPLIT INFERENCE =====
    [SPLIT] Selected image: img_10 (label=5)
    [SPLIT] Test 0 | expected = 5
    [EARLY] ✓ Early layers complete (395 ms)
    [LATE] ✓ Late layers complete (pred=5, 74 ms)
    [SPLIT] Prediction = 5 ✓ (total inference: 504 ms)
    [SPLIT] ===== DONE =====
    [ENCLAVE] ===== EXIT (total: 736 ms) =====
    [MAIN] ✓ Inference complete

**Phase 3: Inference & Benchmark**

::

    [MAIN] Running single inference in enclave...
    [ENCLAVE] ===== ENTER =====
    [ENCLAVE] Enclave not created, creating new enclave...
    
    --- CREATE ENCLAVE ---
    [NS] Enclave region reserved: base=0x20000fc0 size=39552
    [NS] Configuration:
          Enclave memory size: 39552 bytes
          Enclave memory addr: 0x20000fc0
          Stack size: 8192 bytes
    [NS] Initializing enclave memory...
    [NS] ✓ Memory cleared
    
    [SPLIT] Test 0 | expected = 6
    [SPLIT] Prediction = 6
    [SPLIT] ===== DONE =====

Performance Metrics
-------------------

- **Flash usage**: 201.4 KB (76.82% of 256 KB)
- **RAM usage**: 128.0 KB (97.67% of 128 KB)
- **Secure flash**: 120.1 KB (89% of 131 KB)
- **Secure RAM**: 52.7 KB (80% of 64 KB)

**Timing**:

- **Phase 1 (Enclave Authorization)**: ~20 ms (EnclaveInfo + M_update)
- **Phase 2 (Inference Protocol)**: ~100 ms (M_inf + PoX with ECDSA P-256)
- **Phase 3 (CIFAR-10 Inference)**: 504 ms (395 ms early + 74 ms late layers)

Target Board
============

Hardware Specifications
-----------------------

- **Board**: NUCLEO-L552ZE-Q
- **MCU**: STM32L552ZE-Q
- **CPU**: ARM Cortex-M33 with TrustZone
- **Flash**: 512 KB
- **RAM**: 256 KB (128 KB secure + 128 KB non-secure)
- **ST-LINK**: V2J47M34
- **Device ID**: 0x472

Security Features
-----------------

- TrustZone-M hardware isolation
- Secure Attribution Unit (SAU)
- Memory Protection Unit (MPU)
- AES-128 hardware accelerator

Troubleshooting
===============

Build Issues
------------

**Error**: ``psa_connect failed``

- Verify TF-M partition manifest in ``dummy_partition/tfm_dummy_partition.yaml``
- Check ``ENCLAVE_SID`` matches manifest value (``0xFFFFF002``)

**Error**: ``Late weights buffer too small``

- Ensure ``ENCLAVE_MEMORY_SIZE >= LATE_WT_TOTAL_SIZE`` (39552 bytes)
- Check enclave region allocation in ``create_enclave.cpp``

Runtime Issues
--------------

**Hash output all zeros**

- Missing PSA Crypto configuration
- Add ``CONFIG_MBEDTLS_PSA_CRYPTO_C=y`` to ``prj.conf``
- Rebuild from clean: ``west build -p always``

**Hash fails with PSA_ERROR_INVALID_ARGUMENT (-141)**

- Buffer size exceeds PSA crypto limits
- Late weights are hashed in 4096-byte chunks (already implemented)
- Verify chunking logic in ``compute_integrity_hash()``

**Prediction incorrect**

- Verify AES key in secure partition matches encryption key
- Check IV consistency: ``late_wt_iv[16] = {0,1,2,...,15}``
- Validate quantization parameters in ``L_nn_params.h``

**Stack overflow**

- Increase ``CONFIG_MAIN_STACK_SIZE`` in ``prj.conf``
- Reduce tensor buffer sizes in ``split_inference.cpp``

References
==========

- ARM TF-M Documentation: https://tf-m-user-guide.trustedfirmware.org/
- PSA API Specification: https://arm-software.github.io/psa-api/
- CMSIS-NN Library: https://github.com/ARM-software/CMSIS-NN
- Zephyr RTOS: https://docs.zephyrproject.org/

Documentation Files
====================

- **README.rst**: Main project documentation (this file)
- **VERIFICATION_REPORT.md**: ✅ **Complete hardware verification report (27 Feb 2026)** - All 3 phases of Enclave Authorization Protocol verified on STM32L552
- **ENCLAVE_AUTH_IMPL.md**: Enclave Authorization Protocol implementation details
- **INFERENCE_PROTOCOL_IMPL.md**: Inference Protocol (Phase 2) implementation details
- **BENCHMARK_RESULTS.md**: Detailed cycle-by-cycle analysis of all measurements
- **src/README.md**: Non-Secure application architecture and components
- **dummy_partition/README.md**: Secure partition implementation details
- **split_inference/README.md**: CIFAR-10 model and split inference details


The flash process uses STM32CubeProgrammer as the runner.

⸻

Notes
=====

- Ensure the board is connected via ST-LINK before flashing.
- If flashing fails, verify ST-LINK connection, power supply, and SWD frequency.
- The project is built for the Non-Secure (NS) domain of the STM32L5 (TrustZone enabled).

**Features Implemented**:

- **Phase 1: Enclave Authorization Protocol (EnclaveInfo + M_update generation)** ✅ **VERIFIED 27 Feb 2026** - Provider simulation with SHA-256 hash computation and AES-256-GCM encrypted messages. 
- **Phase 2: Inference Protocol (M_inf / PoX)** ✅ **VERIFIED 25 Feb 2026** - Verifier-signed inference requests and device-signed proof of execution with ECDSA P-256.
- **Phase 3: M_update Validation** ✅ **VERIFIED 27 Feb 2026** - Secure decryption, EnclaveInfo verification, anti-replay protection, and dynamic policy updates.
- **Phase 4: CIFAR-10 Inference** ✅ - Split inference with encrypted late weights, PSA-backed counter management, and cycle-accurate benchmarking.

**See [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) for complete hardware verification details.**

**Security Highlights**:

- **ECDSA P-256** cryptography via PSA Crypto API
- **Random nonces** per request (anti-replay protection)
- **AES-256-GCM** encryption with authentication
- **SHA-256** for integrity verification
- **TrustZone-M** hardware isolation (Secure vs Non-Secure worlds)

**Cryptographic Artifacts**:

- **Phase 1 (Authorization Protocol - Verified 27 Feb 2026)**: 
  
  * AES-256 session key (32 bytes) in Secure Flash
  * EnclaveInfo = SHA-256(Model_pub || Model_secret || code || model_ID)
  * M_update = AES-256-GCM(c_limit || pk_v || EnclaveInfo || cert) + nonce + tag
  * Dynamic policy: max_inferences starts at 0, updated to c_limit after validation

- **Phase 2 (Inference Protocol - Verified 25 Feb 2026)**:
  
  * M_inf = ECDSA_sign(SHA-256(test_image || nonce || model_id), sk_verifier)
  * PoX = ECDSA_sign(SHA-256(prediction || nonce || model_id), sk_device)

- **Phase 2**: ECDSA P-256 keypairs for Verifier and Device
  
  * M_inf = Verifier-signed (nonce || input || model_id) - 144 bytes
  * PoX = Device-signed (model_id || cert || nonce || input || output) - 161 bytes

- **Anti-replay**: Fresh random nonce (12 bytes) per M_inf request

**Constraints & Optimization**:

- PSA_MAX_IOVEC=4 limit requires buffer packing (Phase 1 solution: combined_data buffer)
- Input size optimized to 64 bytes for testing (scalable to 3072 bytes for production)
- RAM usage: 97.67% on STM32L552 (128 KB total) - suitable for embedded devices
- All cryptographic operations via PSA API (portable across ARM platforms)
