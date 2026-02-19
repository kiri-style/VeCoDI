# Source Code (Non-Secure Application)

## Overview
This folder contains the Non-Secure (NS) application that drives the split inference flow. The NS app:
- Creates the enclave environment.
- Requests **secure decryption of late-layer weights** into NS RAM.
- Runs CMSIS-NN split inference (early + late) using the decrypted weights.

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
- **create_enclave.cpp**: allocates the NS buffer used for late weights, invokes PSA decrypt, and manages enclave state.
- **run_enclave.cpp**: executes split inference inside the enclave thread.

### Split inference
- **split_inference.cpp / split_inference.h**: CMSIS-NN early/late execution, buffer reuse, and prediction printing.
- **test_images.c / test_images.h**: CIFAR-10 sample inputs and labels.

### Model + artifacts
- **cifar_resnet_int8.tflite**: quantized CIFAR-10 model (reference).
- **cifar_resnet_lite_int8_data.cc/h**: embedded model array (legacy path).
- **model_encrypted*.h**: legacy encrypted model headers (not used by split flow).

### Security/IPC glue
- **ns_irq.c / ns_irq.h**: NS interrupt setup for TrustZone.

## Runtime Flow (Current)
1. NS allocates `enclave_memory` sized to `LATE_WT_TOTAL_SIZE`.
2. NS sends `{cmd, encrypted_weights, iv}` to TF-M secure partition.
3. Secure partition decrypts AES-CTR into NS buffer.
4. `split_inference` uses the decrypted weights to run late layers.

## Traceable Call Chain
`main.cpp` → `create_enclave.cpp` → PSA IPC → `dummy_partition/dummy_partition.c` → back to `split_inference.cpp`.

## Notes
- The legacy full-model decryption path exists for reference, but split inference uses **late weights only**.
- Buffer sizes are tuned for STM32L552 RAM limits.
