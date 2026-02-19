# split_inference

## Purpose
Holds the split model artifacts (early/late) used by CMSIS-NN inference.

## Contents
- `early/`: early-layer weights and params (plain)
- `late/`: late-layer weights and params **encrypted** for flash storage
- `data.h`, `labels.h`: CIFAR-10 metadata

## Generation Source
The `early/` and `late/` folders are generated from SecureQNN export logs. Do not hand-edit unless you regenerate from the source.

## Runtime Flow
1. NS app requests AES-CTR decryption of `late` weights from Secure World.
2. Decrypted bytes are written into NS RAM (buffer sized to `LATE_WT_TOTAL_SIZE`).
3. `split_inference` runs late layers using that RAM buffer.

## Important Files (late/)
- `L_nn_wt_encrypted.h`: sizes + IV + externs
- `L_nn_wt_encrypted_data.c`: encrypted weight bytes in flash
- `L_nn_biases.h`: late-layer bias arrays
- `L_nn_params.h`: CMSIS-NN parameter structs