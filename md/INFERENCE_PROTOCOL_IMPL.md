# Inference Protocol Implementation (M_inf / PoX)

## Overview

Implementation of cryptographic inference protocol enabling **Verifier-to-Device inference requests** with **Proof-of-Execution (PoX)** from the Device back to Verifier.

**Status**: ✅ **WORKING (updated flow)** - Verified inference path now uses Secure START/COMPLETE transaction with Secure-side decrypt/verify/sign.

## Protocol Definition

### M_inf: Verifier Request Message

**Sender**: Host Verifier  
**Recipient**: Device (Physical Device)

```
Plaintext structure:
   nonce       [32 bytes]  - Random nonce per request
   model_id    [4 bytes]   - Model identifier (LE)
   signature   [64 bytes]  - ECDSA P-256 sig over SHA256(nonce || model_id)

Plaintext total: 100 bytes

Transport on UART (CMD_RUN_INFERENCE):
   packet = aes_gcm_encrypt(session_key, plaintext)
             = nonce_gcm(12) || ciphertext(100) || tag(16)

Transport total: 128 bytes
```

**Note**: Input image is **not** transmitted — the device uses its own stored test image.

**Cryptography**:
- Algorithm: ECDSA P-256 (secp256r1)
- Hash: SHA-256
- Key Size: 256 bits

### PoX: Device Proof of Execution

**Sender**: Device (Physical Device)  
**Recipient**: Host Verifier

```
Structure:
  model_id    [4 bytes]   - Model identifier
  cert        [16 bytes]  - Provider certificate
  nonce       [12 bytes]  - Nonce echoed from M_inf
  output      [1 byte]    - Inference result (0-9 for CIFAR-10)
  signature   [64 bytes]  - ECDSA P-256 sig: Sign(sk_d, above fields)
  
Total: 97 bytes
```

**Cryptography**:
- Algorithm: ECDSA P-256 (secp256r1)
- Hash: SHA-256
- Key Size: 256 bits

## Implementation Details

### Files Created

1. **src/inference_protocol.h** (~250 lines)
   - Structure definitions: `m_inf_t`, `proof_of_execution_t`
   - Constants: `NONCE_SIZE`, `ECDSA_SIG_SIZE`, `MODEL_ID_SIZE`, etc.
   - Public API:
     - `generate_m_inf()`: Verifier creates signed request
     - `verify_m_inf()`: Device verifies request
     - `generate_proof_of_execution()`: Device creates signed PoX
     - `verify_proof_of_execution()`: Verifier validates PoX

2. **src/inference_protocol.cpp** (~400 lines)
   - PSA Crypto integration (key import/export, signing, verification)
   - Detailed debug output at each cryptographic operation
   - Error handling with status codes

3. **src/test_inference_protocol.cpp** (~250 lines)
   - Complete test harness demonstrating full protocol flow
   - PSA-generated keypairs (not hardcoded)
   - 5-step execution:
     1. Generate Verifier keypair
     2. Generate Device keypair
     3. Verifier creates M_inf
     4. Device executes inference
     5. Device creates PoX

### Files Modified

1. **src/main.cpp**
   - Added `extern "C" int test_inference_protocol(void);`
   - Integrated protocol test as Phase 2 (after authorization protocol)
   - Error handling for test failures

2. **CMakeLists.txt**
   - Added `src/inference_protocol.cpp` and `src/test_inference_protocol.cpp` to target_sources

3. **README.rst** (Previously updated)
   - Documentation of protocol in "Enclave Authorization Protocol" section

## Hardware Test Results

**Device**: STM32L552 Cortex-M33 @ 110 MHz  
**Build**: 201.4 KB FLASH (76.82%), 128.0 KB RAM (97.67%)  
**Execution Time**: Protocol test completes in <100 ms

### Serial Output (Verified)

```
[MAIN] Starting Inference Protocol Test...

╔════════════════════════════════════════════════════════╗
║    INFERENCE PROTOCOL TEST (M_inf / PoX)              ║
╚════════════════════════════════════════════════════════╝

[TEST] ===== STEP 1: GENERATE VERIFIER KEYPAIR =====
[TEST] ✓ Verifier keypair generated

[TEST] ===== STEP 2: GENERATE DEVICE KEYPAIR =====
[TEST] ✓ Device keypair generated

[TEST] ===== STEP 3: VERIFIER GENERATES M_INF =====
[TEST] ✓ M_inf generated and signed (80 bytes total)
[PROTO] Nonce: E5 C7 F7 21 44 A7 B5 49 FF 99 D4 6F
[PROTO] Signature (first 16B): FD 01 5F 14 47 7C 55 09 A4 E6 D4 4C 63 70 44 2E

[TEST] ===== STEP 4: DEVICE EXECUTES INFERENCE =====
[DEVICE] Inference result: 6

[TEST] ===== STEP 5: DEVICE GENERATES PoX =====
[TEST] ✓ PoX generated and signed (97 bytes total)
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
```

## Cryptographic Security

- **ECDSA P-256**: Industry-standard elliptic curve cryptography
- **SHA-256**: Cryptographically secure hash function
- **Random Nonce**: Generated fresh per request (prevents replay attacks)
- **PSA Crypto**: Uses Zephyr/TF-M's standardized PSA Crypto API
- **Key Management**: Session and verifier-side key material is established at connection time; secure operations use PSA/ECDSA paths

## Integration with Existing Features

1. **Phase 1: Enclave Authorization Protocol** (Previously implemented)
   - EnclaveInfo computation
   - M_update generation with AES-256-GCM
   - Real host/device flow over UART with a fixed AES-GCM session key

2. **Phase 2: Inference Protocol** (Current runtime path)
   - `CMD_RUN_INFERENCE` accepts encrypted packet only (`len=128`)
   - Secure START decrypts + verifies `M_inf`, then opens enclave RAM window
   - NS executes split inference atomically
   - Secure COMPLETE closes RAM window, commits counter, signs PoX

3. **Phase 3: CIFAR-10 Inference** (Already working)
   - Split inference (early + late layers)
   - Early layers: 395 ms, 43.4M cycles
   - Late layers: 74 ms, 8.2M cycles
   - Total: 504 ms, 55.5M cycles

## Current Validation Scope

- Device validates encrypted/signed inference requests in Secure world (`DP_CMD_INF_START`).
- Device generates PoX signatures in Secure world (`DP_CMD_INF_COMPLETE`).
- Device public key (`pk_d`) is served by Secure partition (`DP_CMD_GET_DEVICE_PUBKEY`).
- Legacy unverified inference mode (`CMD_RUN_INFERENCE` len=0) is disabled.
- Host retrieves `pk_d` and verifies PoX in interactive flow (option `9`).

## Remaining Improvements

- Add replay-window hardening for `M_inf` nonces in Secure state.
- Strengthen result-integrity guarantees if NS-compromise is in threat model (inference still executes in NS).
- Optionally migrate inference compute path to Secure world for strongest end-to-end integrity.

## Memory Optimization

- Protocol payload no longer carries image input (`M_inf` is nonce + model_id + signature)
- This reduces protocol-side message size and host/device transfer overhead
- Runtime RAM pressure is now dominated by model/tensor buffers, not protocol input payload

## API Usage Example

```cpp
// Host: send encrypted M_inf packet via CMD_RUN_INFERENCE (128 bytes)
// packet = nonce_gcm(12) || ciphertext(100) || tag(16)

// Device runtime path:
// 1) Secure START: decrypt + verify M_inf, open enclave RAM window
// 2) NS executes split inference atomically
// 3) Secure COMPLETE: commit counter + sign PoX
// 4) Device returns encrypted response: output(1) || pox_sig(64)
```

## Testing

Run full stack test:
```bash
west build -p auto
west build -t flash
# Observe serial output for protocol execution
```

Monitor serial:
```bash
miniterm.py /dev/ttyUSBx 115200
# or equivalent for your platform
```

Expected output confirms all 5 protocol steps execute successfully.

## References

- **PSA Crypto**: https://arm-software.github.io/psa-api/
- **ECDSA**: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
- **Zephyr RTOS**: https://docs.zephyrproject.org/
- **ARM TF-M**: https://tf-m-user-guide.trustedfirmware.org/

---

**Last Updated**: 30 March 2026  
**Status**: ✅ Production path uses Secure START/COMPLETE for decrypt/verify/sign; inference compute remains NS  
**Hardware**: STM32L552ZE-Q, ARM Cortex-M33 with TrustZone-M
