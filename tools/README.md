# tools

## Version Information

```
Zephyr:     commit 61a8648c2cc6bbec9af368a96ecae87d6798e7fe (HEAD -> main)
TF-M:       commit 04aa7243e04946b5422b124bea9c0675ab6b120f (HEAD, manifest-rev)
Updated:    5 March 2026
Protocol:   ECDH P-256 dynamic keys + AES-256-GCM encryption + anti-replay
```

## Purpose
Helper scripts for model artifacts, encryption headers, and Mac ↔ STM32 protocol communication.

## Contents

### Model Generation
- `gen_late_wt_plain.py`: Build plain late-weights binary
- `gen_late_wt_enc_header.py`: Convert encrypted binary to C header/data
- `gen_late_biases.py`: Export late-layer biases header

### Protocol Testing (Mac ↔ STM32)
- `mac_provider.py`: **Interactive protocol client** for Mac ↔ STM32 communication
  - Generate and send encrypted M_update messages
  - Execute inference commands
  - Monitor quota usage (max, count, remaining)
  - AES-256-GCM encryption/decryption
- `step1_protocol_test.py`: Basic smoke test for EnclaveInfo computation
- `test_uart.py`: Quick test for quota retrieval

## Mac Provider Script (`mac_provider.py`)

### Available Commands
1. **Compute EnclaveInfo** (0x01): Request device to compute enclave information
2. **Generate M_update (c_limit=10)** (0x02): Send authorization with 10 inference limit
3. **Generate M_update (c_limit=20)** (0x02): Send authorization with 20 inference limit
4. **Get max inferences** (0x03): Retrieve total authorized inference quota
5. **Run inference** (0x04): Execute one inference (consumes quota)
6. **Read device console** (0x06): Monitor device UART output
7. **Get inference count** (0x05): Check number of inferences already executed
8. **Get remaining inferences** (0x06): Check available quota (max - count)

### Usage
```bash
# Interactive mode
python3 tools/mac_provider.py /dev/tty.usbmodem* 115200

# Automated test sequence
printf '3\n5\n5\n7\n8\nq\n' | python3 tools/mac_provider.py /dev/tty.usbmodem* 115200
```

### Protocol Format
- **Request**: `[CMD:1][LEN:4][DATA:n]` (binary, little-endian)
- **Response**: `[STATUS:1][LEN:4][DATA:n]` (0x00=OK, 0xFF=ERROR)

### Security Features
- AES-256-GCM encryption for M_update packets
- Anti-replay protection (strictly increasing c_limit)
- Inference gating (requires valid M_update before execution)
- Session key hardcoded (matches device firmware)

## Model Regeneration Usage
1) Generate a plain late-weights binary from `split_inference/late/` sources.
2) Encrypt the binary (AES-CTR) with your chosen key/IV (external step).
3) Generate `L_nn_wt_encrypted.h` and `L_nn_wt_encrypted_data.c` from the encrypted binary.
4) Regenerate `L_nn_biases.h` if late biases change.