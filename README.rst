=============================================================================
Secure CIFAR-10 Split Inference with TF-M and Encrypted Late Weights
=============================================================================

Overview
========

This project demonstrates a **secure split inference architecture** for CIFAR-10 classification
on ARM Cortex-M33 with TrustZone, combining:

- **ARM Trusted Firmware-M (TF-M)**: Secure partition for cryptographic operations
- **CMSIS-NN**: Optimized neural network kernels for embedded devices
- **Split Inference**: Model split into early (unprotected) and late (weight-protected) layers
- **AES-CTR Encryption**: Late layer weights encrypted in ROM, decrypted at runtime by secure world

Architecture
============

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

4. **Late Layers** (``run_late_layers()``)
   
   - Inputs: ``early_output`` + ``early_skip``
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

::

    --- CREATE ENCLAVE ---
    [NS] Enclave region reserved: base=0x20000fc0 size=39552
    [NS] ✓ Late weights decrypted into NS RAM
    [NS] ✓ Enclave creation complete
    
    [STEP 1.5] ✓ Late weights buffer configured: 0x20000fc0 (39552 bytes)
    
    [CNT] PSA crypto init OK
    [SPLIT] Test 0 | expected = 6
    [CNT] Starting hash computation...
    [CNT] Hash setup OK
    [CNT] Hashing late weights in chunks...
    [CNT] Late weights hashed successfully
    [CNT] Hash computed successfully (len=32)
    [CNT] First 8 bytes: 0bc20736ab268068
    [CNT] Hash stored for test 0
    [SPLIT] Prediction = 6
    
    [SPLIT] Test 1 | expected = 9
    [CNT] Starting hash computation...
    [CNT] Hash setup OK
    [CNT] Hashing late weights in chunks...
    [CNT] Late weights hashed successfully
    [CNT] Hash computed successfully (len=32)
    [CNT] First 8 bytes: 2acf215c0e5f4659
    [CNT] Hash stored for test 1
    [SPLIT] Prediction = 9
    
    [CNT] Final Hash: 2acf215c0e5f4659d4d2052380ba8c3c82b8a20b0308ae43f429e12134a87686
    [SPLIT] ===== DONE =====

Performance Metrics
-------------------

- **Flash usage**: 128996 B (49.21% of 256 KB)
- **RAM usage**: 127720 B (97.44% of 128 KB)
- **Secure flash**: 118692 B (88.48% of 131 KB)
- **Secure RAM**: 52636 B (80.32% of 64 KB)

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


The flash process uses STM32CubeProgrammer as the runner.

⸻

Notes
	•	Ensure the board is connected via ST-LINK before flashing.
	•	If flashing fails, verify ST-LINK connection, power supply, and SWD frequency.
	•	The project is built for the Non-Secure (NS) domain of the STM32L5 (TrustZone enabled).
