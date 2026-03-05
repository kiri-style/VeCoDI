# Device Benchmark Collection

## Overview
The device benchmark system measures performance metrics directly on the STM32L552 microcontroller, capturing:
- ECDH key exchange performance
- Enclave creation time
- Split inference execution time (early + late layers)
- Memory usage during inference
- Quota management operations

## Quick Start

### Option 1: Use the Test Suite (Recommended)
The test suite automatically performs full benchmarking with ECDH handshake and M_update:

```bash
python3 test_split_inference.py
```

This will:
1. Connect to the device
2. Perform ECDH handshake (dynamic session key)
3. Compute enclave info
4. Send M_update (authorization with quota=20)
5. Execute split inference
6. Report all metrics and timing

### Option 2: Use the Benchmark Script
For manual benchmark collection:

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
