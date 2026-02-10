# Dummy Partition (TF-M Secure Service)

## Overview

This **Dummy Partition** is a custom **Trusted Firmware-M (TF-M) Secure Partition** designed to demonstrate **fine-grained access control** between Secure and Non-Secure worlds on **ARM Cortex-M33 with TrustZone** (STM32L5).

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

