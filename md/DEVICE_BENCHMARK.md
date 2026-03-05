# Device Benchmark Collection

## Overview
The device benchmark system measures performance metrics directly on the STM32L552 microcontroller via UART protocol, capturing:
- ECDH key exchange performance
- Enclave creation time
- Split inference execution time (early + late layers)
- AES-CTR decryption (secure world)
- Memory usage during inference
- Quota management operations
- Counter state transitions

## Collected Metrics

### Non-Secure (NS) Metrics - 72 bytes total
- Enclave lifecycle: create, destroy cycles
- Cryptographic operations: AES decrypt, hash timing
- Inference performance: early/late layers, total
- End-to-end: run_enclave() timing
- Memory usage: RAM used/total, Flash used/total
- Counters: inference count, recreations

### Secure (S) Metrics - 88 bytes total
- AES Decrypt: cycles and operation count
- Late Hash: cycles and operation count
- Digest Compute: cycles and operation count
- Counter Management: get_max, check_allowed, increment, reset
- Memory: RAM used/total, Flash used/total

## Quick Start

### Using test_benchmark.py (Recommended)
The full benchmark script collects all metrics including ECDH handshake:

```bash
python3 test_benchmark.py
```

This will:
1. Perform ECDH handshake (P-256 key exchange)
2. Compute EnclaveInfo hash
3. Send M_update with encrypted quota (AES-256-GCM)
4. Execute split inference
5. Collect both NS and S metrics
6. Save all results to benchmark_results.txt

### Output Example

```
======================================================================
NON-SECURE (NS) BENCHMARK RESULTS
======================================================================

Enclave Lifecycle:
  Create:   7,980,975 cycles (72.6 ms)
  Destroy:          0 cycles (0.0 ms)

Inference Performance:
  Early Layers: 42,984,997 cycles (390.8 ms)
  Late Layers:   7,922,258 cycles (72.0 ms)
  Total:        51,553,622 cycles (468.7 ms)

NS Memory Usage:
  RAM Used:      121,788 / 131,072 bytes (92.9%)
  Flash Used:    176,160 / 262,144 bytes (67.2%)

======================================================================
SECURE (S) BENCHMARK RESULTS
======================================================================

Cryptographic Operations (Secure):
  AES Decrypt:     7,662,219 cycles (69.7 ms) [1 ops]

Secure Memory Usage:
  RAM Used:       52,732 / 65,536 bytes (80.5%)
  Flash Used:    119,532 / 134,144 bytes (89.1%)

======================================================================
COMBINED SYSTEM METRICS
======================================================================
Total RAM:      174,520 / 196,608 bytes (88.8%)
Total Flash:    295,692 / 396,288 bytes (74.6%)

======================================================================
MEMORY FOOTPRINT ANALYSIS
======================================================================

ELF Section Analysis (ACTUAL from build):

Flash (ROM) Sections:
├─ .rodata (Constants):     138,252 bytes ( 135.0 KB)
└─ Total Flash Used:        138,252 bytes ( 135.0 KB)

RAM (SRAM) Sections:
├─ .data (Initialized):       3,976 bytes (   3.9 KB)
├─ .bss (Zero-init):        117,809 bytes ( 115.0 KB)
└─ Total RAM Used:          121,785 bytes ( 118.9 KB)

Largest Symbols (Top 20):
 1. _ZL14enclave_memory                        39,552 bytes (  38.6 KB)
 2. late_wt_encrypted                          39,552 bytes (  38.6 KB)
 3. _ZL11wt_conv2d_6                           18,432 bytes (  18.0 KB)
 4. _ZL10early_buf0                            16,384 bytes (  16.0 KB)
 ...
```

```bash
python3 tools/get_device_benchmark.py [/dev/ttyXXX]
```

Defaults to auto-detected `/dev/tty.usbmodem*` if port not specified.

## Benchmark Workflow

### Step 1: ECDH Handshake
```
Mac → Device: CMD_ECDH_HANDSHAKE (0x07) + uncompressed P-256 public key (65 bytes)
Device → Mac: Device ephemeral public key (65 bytes)

Result: Session key derived via HKDF-SHA256 with identical salt/info on both sides
```

### Step 2: Compute EnclaveInfo  
```
Mac → Device: CMD_COMPUTE_ENCLAVE_INFO (0x01) + model_pub(32) + model_secret(32) + code_hash(32) + model_id(4)
Device → Mac: SHA-256 hash (32 bytes)
```

### Step 3: Send M_update
```
Mac encrypts plaintext: c_limit(4) || pk_v(64) || enclave_info(32) || cert_len(4) || cert(n)
Total plaintext: 120 bytes
Encryption: AES-256-GCM with ECDH-derived session key
Packet format: nonce(12) || ciphertext(120) || tag(16) = 148 bytes total

Mac → Device: CMD_VALIDATE_M_UPDATE (0x02) + packet(148 bytes)
Device → Mac: Status (0x00=OK, 0xFF=Error)
```

### Step 4: Run Split Inference
```
Mac → Device: CMD_RUN_INFERENCE (0x04)
Device:
  1. Check quota (NS)
  2. Call Secure partition to verify and manage quota
  3. Create enclave (if first inference)
  4. Decrypt late layer weights (via Secure partition)
  5. Execute early layers (NS)
  6. Execute late layers with decrypted weights (NS)
Mac → Device: Status (0x00=OK, 0xFF=Error)
```

### Step 5: Retrieve Metrics
```
Mac → Device: CMD_GET_INFERENCE_COUNT (0x05)
Device → Mac: Inference count (4 bytes LE)

Mac → Device: CMD_GET_REMAINING_INFERENCES (0x06)
Device → Mac: Remaining quota (4 bytes LE)
```

## Expected Performance

### Timing (STM32L552 @ 110 MHz)
- **ECDH Handshake**: ~500 ms (ephemeral key generation + key agreement)
- **EnclaveInfo Computation**: ~50 ms (SHA-256 hash)
- **M_update Validation**: ~30 ms (AES-256-GCM decrypt)
- **Split Inference**: 
  - Early layers: ~405 ms (44.6M cycles)
  - Late layers: ~74 ms (8.2M cycles)
  - **Total: ~479 ms per inference**
- **Quota Management**: <1 µs (atomic in Secure World)

### Memory Usage
- **Flash**: 179,940 bytes / 256 KB (68.64%)
  - Application code: ~45 KB
  - CMSIS-NN library: ~35 KB
  - Early layer weights: ~37 KB
  - Encrypted late weights: ~40 KB
  - Zephyr RTOS: ~15 KB
  - PSA Crypto: ~12 KB

- **RAM**: 128,304 bytes / 128 KB (97.89%)
  - Tensor buffers: ~48 KB
  - Enclave memory: ~39 KB (late weights)
  - Test images: ~60 KB
  - Stack: 4 KB

## Data Collection

### Automatic Report Generation
Test scripts automatically save reports:
```bash
build/device_benchmark.txt  # Performance metrics
build/memory_analysis.txt   # Flash/RAM breakdown
```

### Manual Metric Extraction
To capture raw metrics for analysis:

```python
import serial
import struct

ser = serial.Serial('/dev/tty.usbmodem1203', 115200, timeout=2)

# Read remaining quota
ser.write(b'\x06\x00\x00\x00\x00')  # CMD_GET_REMAINING_INFERENCES
status, resp_len = ser.read(1), struct.unpack('<I', ser.read(4))[0]
remaining = struct.unpack('<I', ser.read(resp_len))[0]
print(f"Remaining inferences: {remaining}")
```

## Troubleshooting

### M_update Validation Fails (Status 0xFF)
Possible causes:
1. **ECDH session key mismatch**: Ensure salt and info strings match on both sides
2. **EnclaveInfo mismatch**: Device and Mac must compute the same EnclaveInfo hash
3. **Plaintext format error**: Verify c_limit, pk_v, enclave_info, cert_len, cert order
4. **Quota already set**: Reset device before re-running tests

### Inference Timeout
- Increase timeout in serial config: `timeout=5.0`
- Check device is responsive: `python3 tools/mac_provider.py`

### Port Not Found
Auto-detection tries:
- `/dev/tty.usbmodem*` (macOS)
- `/dev/ttyACM*` (Linux)
- `/dev/ttyUSB*` (Linux alternative)

Specify port manually:
```bash
python3 tools/get_device_benchmark.py /dev/ttyACM0
```

## References
- Protocol definition: [tools/README.md](README.md)
- Test script: [test_split_inference.py](test_split_inference.py)
- Device code: [src/uart_protocol.cpp](src/uart_protocol.cpp)
