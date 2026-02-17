# Dummy Partition - TF-M Secure Service

## Overview
This is a custom **TF-M (Trusted Firmware-M) Secure Partition** that provides a secure model decryption service for the Non-Secure application. It decrypts an encrypted TFLite model stored in ROM and writes the decrypted model into a Non-Secure RAM enclave using PSA IPC.

## Architecture

```
Non-Secure World (NS)                   Secure World (TF-M)
┌────────────────────────────┐         ┌────────────────────────────┐
│ create_enclave.cpp         │         │ dummy_partition.c          │
│  • PSA connect/call        │  PSA    │  • Read encrypted chunks   │
│  • Provide ROM model ptr   │  IPC    │  • XOR decrypt             │
│  • Provide RAM enclave ptr │ <-----> │  • psa_write() to NS RAM   │
└────────────────────────────┘         └────────────────────────────┘
```

## PSA Service Interface

### Service Identifiers
Defined in [dummy_partition.h](dummy_partition.h) and mirrored in NS headers:

```c
#define ENCLAVE_SID      0x00000310U
#define ENCLAVE_VER      (1U)

#define DP_CMD_SEAL_ENCLAVE   0x5EA1U  // Seal + decrypt
#define DP_CMD_DECRYPT_MODEL  0xDEC1U  // Legacy decrypt-only
```

### Call Flow
1. **NS** connects using `psa_connect(ENCLAVE_SID, ENCLAVE_VER)`
2. **NS** sends command + encrypted model via `psa_call()`
3. **S** reads encrypted chunks via `psa_read()`
4. **S** decrypts each chunk (XOR key 0x42)
5. **S** writes decrypted data to NS enclave via `psa_write()`

### Message Layout
```
psa_invec[0] : command (DP_CMD_SEAL_ENCLAVE)
psa_invec[1] : encrypted model bytes
psa_outvec[0]: NS enclave buffer (decrypted output)
```

## Implementation Details

### Decryption Algorithm (Demo)
XOR cipher with key `0x42`:

```c
#define XOR_KEY 0x42
for (i = 0; i < chunk_size; i++) {
    decrypted[i] = encrypted[i] ^ XOR_KEY;
}
```

> **Security Note**: XOR is for demonstration only. Use AES-256-GCM in production.

### Chunked Processing
- Chunk size: **256 bytes**
- Model size: **39,504 bytes**
- Progress print every ~1KB

### Debug Output (Secure World)
```
[S] tfm_dp_enclave_seal: Processing seal + decrypt request
[S] Message sizes: in[0]=4, in[1]=39504, out[0]=40960
[S] XOR decryption key: 0x42
[S] Chunk size: 256 bytes
[S] Progress: 1024 / 39504 bytes (2.6%)
...
[S] Progress: 39504 / 39504 bytes (100.0%)
```

## Files

### dummy_partition.c
Main Secure Partition implementation:
- `tfm_dp_enclave_seal()` → decrypts model into NS RAM
- `tfm_dp_decrypt_model()` → legacy handler (deprecated)
- `print_secure_memory_stats()` → Secure RAM stats

### tfm_dummy_partition.yaml
Partition manifest for TF-M:
- Service SID: 0x00000310
- IPC model
- Non-secure clients allowed

### tfm_manifest_list.yaml.in
Manifest list for build integration

### dummy_partition.h
Service IDs and command codes (shared with NS)

## Memory Usage

### Secure World
- Secure RAM total: **64KB**
- Dummy partition BSS: **~3.2KB**

### Non-Secure Enclave
- Enclave size: **40KB (40960 bytes)**
- Model size: **39,504 bytes**
- Utilization: **96.4%**

## Build Integration

The partition is integrated via CMake and TF-M manifest:

```cmake
target_sources(tfm_app_rot_partition_dummy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/dummy_partition.c
    ${CMAKE_CURRENT_SOURCE_DIR}/secure_nsc_interface.c
)

set(DUMMY_PARTITION_MANIFEST_LIST
    ${CMAKE_CURRENT_SOURCE_DIR}/tfm_manifest_list.yaml.in
)
```

## Troubleshooting

### PSA connect fails
**Symptoms**:
```
[NS] ✗ psa_connect failed (seal)
```

**Checks**:
```bash
grep "dummy_partition" build/zephyr/.config
grep "ENCLAVE_SID" dummy_partition/dummy_partition.h
```

### Model decryption fails
**Checks**:
- XOR key matches in Python and C
- Encrypted model length fits enclave

```bash
grep "XOR_KEY" train/encrypt_model.py
grep "XOR_KEY" dummy_partition/dummy_partition.c
```

## Production Hardening (Suggested)
- Replace XOR with **AES-256-GCM**
- Store keys in **PSA Protected Storage**
- Add **integrity checks** (HMAC or AEAD)
- Enable **rollback protection**
- Minimize Secure World logging

## References
- https://tf-m-user-guide.trustedfirmware.org/
- https://developer.arm.com/documentation/ihi0064/latest
- https://docs.zephyrproject.org/latest/security/tfm.html

---

**License**: Apache 2.0  
**Last Updated**: 2024 (TF-M v2.2.0, Zephyr v4.3.0)# Dummy Partition - TF-M Secure Service

## Overview

This is a custom **TF-M (Trusted Firmware-M) secure partition** that provides **cryptographic services** for the Non-Secure (NS) application. It implements **model decryption** and **enclave sealing** operations using the **PSA (Platform Security Architecture) API**.

### Purpose
- Decrypt encrypted TFLite models in Secure World
- Write decrypted models to Non-Secure enclave memory
- Provide memory isolation between NS and S worlds
- Demonstrate TrustZone security architecture on ARM Cortex-M33

Its primary purpose is to **protect a machine learning model and its inference memory** while still allowing controlled execution from the Non-Secure (Zephyr) application using **PSA IPC**, **SAU reconfiguration**, and **token-based authorization**.

This partition acts as a *secure gatekeeper*:
- It owns the security policy
- It dynamically opens/closes memory regions
- It authorizes inference execution
- It never exposes secrets directly to Non-Secure code

---

## Security Goals

This partition enforces the following guarantees:

- 🔒 **Model confidentiality**  
  The ML model stored in Flash is *Secure-only* by default and becomes temporarily **readable** by Non-Secure code only when explicitly authorized.

- 🧠 **Inference isolation**  
  The Tensor Arena (SRAM) used for inference is inaccessible from Non-Secure unless explicitly opened.

- 🎟 **Capability-based access**  
  All sensitive operations require a **Secure-generated token**.

- ⏱ **Temporal access**  
  Memory regions are opened *only for the duration needed* and are closed immediately after use.

- 🚫 **No permanent trust**  
  Access is revoked even if Non-Secure code keeps stale pointers.

---

## Architecture

```
+-------------------------+         PSA IPC         +---------------------------+
|   Non-Secure (Zephyr)  |  <------------------>  |   Secure (TF-M Partition) |
|                         |                         |                           |
|  - Model loader         |   CMD_OPEN_MODEL        |  - SAU reconfiguration    |
|  - Inference code       |   CMD_RUN_INFERENCE     |  - Token validation       |
|  - IRQ handler          |   CMD_CLOSE_MODEL       |  - IRQ triggering         |
+-------------------------+                         +---------------------------+
```

---

## Key Concepts

### 1. Token-Based Authorization

The Secure Partition generates a **single-use inference token**:

```c
#define INFERENCE_TOKEN_MAGIC 0xA5A5A5A5
```

- Token is generated only by Secure world
- Token must be presented for verification
- Token can be invalidated explicitly

This prevents arbitrary Non-Secure calls from triggering Secure operations.

---

### 2. Dynamic SAU Reconfiguration

The partition **dynamically reprograms the SAU** to control memory visibility.

Helpers:

```c
rtpox_configure_sau_nonsecure(start, end, region);
rtpox_configure_sau_secure(start, end, region);
```

Used for:
- Model Flash region
- Inference SRAM region

This ensures:
- No static NS access in the linker
- Runtime-only permissions

---

### 3. Protected Memory Regions

#### Model Region (Flash)

- Passed by Non-Secure as `(start, size)`
- Opened with `CMD_OPEN_MODEL_ACCESS`
- Closed with `CMD_CLOSE_MODEL_ACCESS`

SAU region used:
```c
#define MODEL_SAU_REGION 7
```

#### Inference Region (SRAM)

- Tensor Arena region
- Opened only during inference

SAU region used:
```c
#define INFERENCE_SAU_REGION 5
```

---

### 4. Secure-Controlled Inference Trigger

The Secure Partition **does not execute inference itself**.

Instead:
- It validates permissions
- Then triggers a **Non-Secure IRQ**

```c
NVIC_SetPendingIRQ(NS_INFERENCE_IRQn);
```

This design:
- Keeps inference code Non-Secure
- Keeps control Secure
- Avoids Secure-side ML dependencies

---

## Supported Commands

| Command | ID | Description |
|-------|----|------------|
| `CMD_GET_TOKEN_AND_OPEN` | `0x01` | Generate token |
| `CMD_VERIFY_TOKEN` | `0x03` | Verify token validity |
| `CMD_OPEN_MODEL_ACCESS` | `0x10` | Open model Flash access |
| `CMD_CLOSE_MODEL_ACCESS` | `0x11` | Close model Flash access |
| `CMD_RUN_INFERENCE` | `0x20` | Trigger inference IRQ |
| `CMD_OPEN_INFERENCE_ACCESS` | `0x30` | Open Tensor Arena SRAM |
| `CMD_CLOSE_INFERENCE_ACCESS` | `0x31` | Close Tensor Arena SRAM |
| `CMD_CLOSE_ACCESS` | `0x02` | Revoke token |

---

## IPC Entry Point

Main service loop:

```c
psa_status_t tfm_dp_req_mngr_init(void)
```

- Waits on `TFM_DP_SECRET_DIGEST_SIGNAL`
- Dispatches PSA connect / call / disconnect
- Runs indefinitely in Secure thread

---

## Why This Design Is Interesting

This partition is **not a dummy** in practice.

It demonstrates:
- Runtime TrustZone enforcement
- Capability-based security model
- Secure mediation instead of static isolation
- A realistic pattern for **ML IP protection on MCU**

This architecture scales naturally to:
- Secure firmware updates
- Secure model swapping
- Monetized inference
- Multi-tenant embedded AI

---

## Limitations & Notes

- Token is currently a fixed magic value (demo purpose)
- No cryptographic binding yet
- SAU regions must not overlap
- Assumes correct linker-provided addresses from NS

---

## Files

```
dummy_partition/
├── CMakeLists.txt
├── dummy_partition.c      # Secure service logic
├── dummy_partition.h      # Public API
├── secure_gate.h          # NS ↔ Secure command IDs
├── tfm_dummy_partition.yaml
├── tfm_manifest_list.yaml.in
```

---

## Status

✅ Fully functional  
✅ Tested on STM32L5 + Zephyr NS  
✅ Dynamic model + inference protection  

---

## Author

Khalil Kiri  
Embedded Security & Trusted Execution Environments

