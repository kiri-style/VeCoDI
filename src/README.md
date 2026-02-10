# hello_cifar – Secure Inference (Non-Secure Side)

This directory contains the **Non-Secure (NS)** application code for a Zephyr-based
demonstration of **secure AI inference** on STM32L5 using **Arm TrustZone + TF-M**.

The goal of this project is to:
- protect the **AI model stored in Flash**,
- protect the **tensor arena located in SRAM**,
- allow memory access **only through Secure World authorization**,
- execute inference **exclusively under Secure control** using PSA IPC.

---

## High-level Execution Flow (`main.cpp`)

The `main.cpp` implements the following secure lifecycle:

1. Initialize Non-Secure IRQs
2. Configure MPU protection for the **model (Flash, read-only)**
3. Configure MPU protection for the **inference memory (SRAM – tensor arena)**
4. Request a **security token** from the Secure World
5. Temporarily open access to the model region
6. Temporarily open access to the tensor arena
7. Trigger inference execution in the Secure World
8. Close all memory access permissions
9. Any further access should result in a **memory fault**

---

## `src/` Directory Structure

### 📁 CMSIS_NN/
Optimized neural network kernels from **CMSIS-NN**.

Used by TensorFlow Lite Micro for:
- convolution
- fully connected layers
- quantized int8 operators

---

### 📁 test_data/
Auxiliary test data (images, labels, etc.).

---

### 📄 main.cpp
**Main Non-Secure entry point.**

Responsibilities:
- orchestrates the full secure inference lifecycle
- performs PSA IPC calls (`psa_connect`, `psa_call`, `psa_close`)
- requests Secure-controlled memory access
- logs security-relevant execution steps

This file is the **reference implementation** for understanding the system design.

---

### 📄 mpu_model.cpp / mpu_model.h
Handles **MPU protection of the AI model in Flash**.

Key responsibilities:
- configures a read-only MPU region for the model
- exposes linker-defined boundaries
- used by Secure commands:
  - `CMD_OPEN_MODEL_ACCESS`
  - `CMD_CLOSE_MODEL_ACCESS`

---

### 📄 mpu_inference.cpp / mpu_inference.h
Manages **inference memory (tensor arena) protection** on the Non-Secure side.

Responsibilities:
- retrieves start address and size of the tensor arena
- provides region metadata to the Secure World
- contains **no inference logic**, only memory control

---

### 📄 model_ro.ld
Linker script defining the **protected Flash region** containing the AI model.

Enables:
- strict separation between code and model
- fine-grained MPU enforcement
- exposure of linker symbols:
  - `__model_ro_start`
  - `__model_ro_end`

---

### 📄 model_data.cc / model_data.h
Contains the embedded **TensorFlow Lite model** (`.tflite` format).

The model is **never directly executed from the Non-Secure side**.

---

### 📄 cifar_resnet_int8.tflite
Quantized (int8) CIFAR-10 neural network model.

Used only after Secure World validation.

---

### 📄 inference.cpp / inference.h
Inference-related logic scaffolding.

In this implementation:
- inference execution is **intentionally disabled** on the Non-Secure side
- actual execution is triggered via Secure commands

---

### 📄 ns_irq.c / ns_irq.h
Non-Secure interrupt initialization.

Executed early in `main()` to:
- establish a clean NS execution environment
- prepare Secure ↔ Non-Secure transitions

---

### 📄 secure_gate_ns.h
Shared interface between Non-Secure and Secure worlds.

Defines:
- command identifiers
- shared structures
- PSA ABI contract

---

### 📄 test_images.c / test_images.h
CIFAR-10 test images used during inference validation.

---

### 📄 output_handler.cpp / output_handler.hpp
Handles inference output formatting and logging.

---

## Security Properties Demonstrated

✔ Secure / Non-Secure isolation  
✔ Temporary and revocable memory access  
✔ MPU protection for Flash and SRAM  
✔ Token-based Secure authorization  
✔ Inference execution only in Secure World  
✔ PSA / TrustZone compliant design  

---

## Educational Objective

This project demonstrates:
- how to secure an embedded AI inference pipeline
- how to prevent model extraction
- how to restrict access to weights and activations
- how to correctly combine **Zephyr, TF-M, MPU, and PSA IPC**

---
