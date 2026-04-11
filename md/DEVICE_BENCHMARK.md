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
- Host-side UART round-trip benchmark for all major protocol commands

## April 2026 Recovery Note

On 11 April 2026, a runtime inference regression was investigated and fixed.

- Symptom: `CMD_RUN_INFERENCE (0x04)` failed after successful `ECDH + M_update + Create_Enclave`.
- Root cause: runtime EnclaveInfo pre-check path could block inference even when Secure auth state was valid.
- Resolution: runtime validation kept for observability, but no longer hard-blocks verified inference path.
- Hardware validation flow: `1 -> 3 -> 21 -> 9 -> 11` completed successfully with valid PoX and matching prediction/expected label.

## Collected Metrics

### Non-Secure (NS) Metrics

The benchmark response supports multiple payload versions for backward compatibility:

- **Legacy layout:** 64 bytes (`16 x uint32_t`)
- **Extended v1 layout:** 184 bytes (`16I + 2I + 7Q + 14I + 7I`)
- **Extended v2 layout (current):** 232 bytes (`18I + 8Q + 24I`)
- **Extended v3 layout (current with lifecycle atomic):** 272 bytes (`v2 + 2Q + 6I`)
- **Extended v4 layout (current with UART coverage counters):** 288 bytes (`v3 + 4I`)

Core metrics (all layouts):
- Enclave lifecycle: create/destroy cycles
- Cryptographic operations: AES decrypt cycles
- Inference performance: early/late layers, total
- End-to-end: `run_enclave()` timing
- Memory usage: RAM used/total, Flash used/total
- Counters: inference count, recreations

Extended metrics (v1/v2):
- Request and validation counters:
  - `inference_requests_total`
  - `enclave_info_validation_failures`
- Aggregate cycle stats per stage:
  - `sum_cycles`, `min_cycles`, `max_cycles`, `count`, `avg_cycles`
  - stages: `enclave_create`, `enclave_destroy`, `aes_decrypt`, `early_layers`, `late_layers`, `total_inference`, `run_enclave`
- **Extended v2 adds IRQ atomic timing stage:**
  - `irq_atomic_sum_cycles`, `irq_atomic_min_cycles`, `irq_atomic_max_cycles`, `irq_atomic_count`, `irq_atomic_avg_cycles`
- **Extended v3 adds lifecycle atomic timing stages:**
  - `create_atomic_sum_cycles`, `create_atomic_min_cycles`, `create_atomic_max_cycles`, `create_atomic_count`, `create_atomic_avg_cycles`
  - `destroy_atomic_sum_cycles`, `destroy_atomic_min_cycles`, `destroy_atomic_max_cycles`, `destroy_atomic_count`, `destroy_atomic_avg_cycles`
  - `run_inference_with_image_count`, `dangerous_inference_no_sau_count`, `dangerous_read_ram_count`, `dangerous_read_rom_count`

### Secure (S) Metrics
- **Legacy layout:** 88 bytes (`7Q + 8I`)
- **Extended layout:** 208 bytes (`17Q + 18I`) with secure lifecycle and SAU operation counters

Extended secure fields include:
- Lifecycle cycles/counts: create/finalize/destroy enclave, inf_start, inf_complete
- SAU cycles/counts: sync open/close, flash close/open/pulse
- Core secure crypto/counter and memory fields remain backward compatible

Current device run (11 April 2026) returned the **legacy 88-byte** secure payload.

### Secure (S) Metrics - 88 bytes total
- AES Decrypt: cycles and operation count
- Late Hash: cycles and operation count
- Digest Compute: cycles and operation count
- Counter Management: get_max, check_allowed, increment, reset
- Memory: RAM used/total, Flash used/total

## Quick Start

### Using get_device_benchmark.py (Recommended)
The full benchmark script collects all metrics including ECDH handshake:

```bash
python3 tools/get_device_benchmark.py [/dev/ttyXXX]
```

This will:
1. Perform ECDH handshake (P-256 key exchange)
2. Compute EnclaveInfo hash
3. Send M_update with encrypted quota (AES-256-GCM)
4. Execute split inference
5. Collect both NS and S metrics
6. Benchmark all main UART operations (avg/min/max latency)
7. Decode extended NS aggregate metrics (including IRQ-masked and lifecycle atomic stages when available)
8. Save full report to `build/DEVICE_BENCHMARK_RESULTS.md`


## Complete Results (11 April 2026)

```
╔══════════════════════════════════════════════════════════════╗
║        NON-SECURE (NS) BENCHMARK RESULTS                    ║
╠══════════════════════════════════════════════════════════════╣
║ ENCLAVE LIFECYCLE                                            ║
╟──────────────────────────────────────────────────────────────╢
║ Create:     4,719,136 cycles  (    42.9 ms)               ║
║ Destroy:            0 cycles  (     0.0 ms)               ║
╟──────────────────────────────────────────────────────────────╢
║ CRYPTOGRAPHIC OPERATIONS                                     ║
╟──────────────────────────────────────────────────────────────╢
║ AES Decrypt:  1,043,519 cycles  (     9.5 ms)               ║
╟──────────────────────────────────────────────────────────────╢
║ INFERENCE PERFORMANCE                                        ║
╟──────────────────────────────────────────────────────────────╢
║ Early Layers: 2,818,532 cycles  (   25.6 ms)              ║
║ Late Layers:  1,274,028 cycles  (    11.6 ms)              ║
║ Total Inf:    4,116,262 cycles  (    37.4 ms)              ║
╟──────────────────────────────────────────────────────────────╢
║ END-TO-END METRICS                                           ║
╟──────────────────────────────────────────────────────────────╢
║ run_enclave(): 4,164,761 cycles  (   37.9 ms)             ║
║ Inferences:            10 total                              ║
╟──────────────────────────────────────────────────────────────╢
║ MEMORY USAGE (NS World)                                      ║
╟──────────────────────────────────────────────────────────────╢
║ Heap Used:            0 bytes  (       0 KB)                   ║
║ Stack Used:       2,048 bytes  (       2 KB)                   ║
║ RAM Used:       122,194 / 131,072 bytes (93.2%)              ║
║ Flash Used:     141,088 / 262,144 bytes (53.8%)              ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║        SECURE (S) BENCHMARK RESULTS                         ║
╠══════════════════════════════════════════════════════════════╣
║ CRYPTOGRAPHIC OPERATIONS                                     ║
╟──────────────────────────────────────────────────────────────╢
║ AES Decrypt:  7,626,509 cycles  (    69.3 ms) [1 ops]       ║
║ Late Hash:            0 cycles  (     0.0 ms) [0 ops]       ║
║ Digest Compute:       0 cycles  (     0.0 ms) [0 ops]       ║
╟──────────────────────────────────────────────────────────────╢
║ COUNTER MANAGEMENT                                           ║
╟──────────────────────────────────────────────────────────────╢
║ Get Max:            513 cycles  (     0.0 ms)               ║
║ Check Allowed:        0 cycles  (     0.0 ms)               ║
║ Increment:            0 cycles  (     0.0 ms)               ║
║ Reset:               16 cycles  (     0.0 ms)               ║
║ Total Ops:           13 operations                    ║
╟──────────────────────────────────────────────────────────────╢
║ MEMORY USAGE (Secure World)                                 ║
╟──────────────────────────────────────────────────────────────╢
║ RAM Used:        52,732 / 65,536 bytes (80.5%)               ║
║ Flash Used:     119,532 / 134,144 bytes (89.1%)              ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║        COMBINED SYSTEM METRICS                              ║
╠══════════════════════════════════════════════════════════════╣
║ Total RAM:      174,926 / 196,608 bytes (89.0%)             ║
║ Total Flash:    260,620 / 396,288 bytes (65.8%)             ║
╚══════════════════════════════════════════════════════════════╝
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
Mac → Device: CMD_COMPUTE_ENCLAVE_INFO (0x01) + nonce(32)
Device → Mac: Encrypted response
             decrypts to enclave_info(32) || sig_d(64)
```

### Step 3: Send M_update
```
Mac encrypts plaintext: c_limit(4) || pk_v(64) || enclave_info(32) || cert_len(4) || cert(n)
Total plaintext: 104 + n bytes (n = cert_len)
Encryption: AES-256-GCM with ECDH-derived session key
Packet format: nonce(12) || ciphertext(104+n) || tag(16) = (132+n) bytes total

Mac → Device: CMD_VALIDATE_M_UPDATE (0x02) + encrypted packet
Device → Mac: Status (0x00=OK, 0xFF=Error)
```

### Step 4: Run Split Inference
```
Mac → Device: CMD_RUN_INFERENCE (0x04) + encrypted M_inf
Device:
  1. Check quota (NS)
  2. Call Secure partition to verify and manage quota
  3. Require enclave pre-created (explicit lifecycle)
  4. Execute early layers (NS)
  5. Execute late layers with decrypted weights (NS)
Mac → Device: Status (0x00=OK, 0xFF=Error)
```

### Step 4a: Explicit Enclave Lifecycle (recommended)
```
Mac → Device: CMD_CREATE_ENCLAVE (0x11)
... run one or more CMD_RUN_INFERENCE (0x04) ...
Mac → Device: CMD_DESTROY_ENCLAVE (0x12)
```

### Step 6: Host UART Operation Benchmark
The script also benchmarks round-trip latency for all key operations:

- `CMD_GET_DEVICE_PUBKEY`
- `CMD_GET_MAX_INFERENCES`
- `CMD_GET_INFERENCE_COUNT`
- `CMD_GET_REMAINING_INFERENCES`
- `CMD_GET_INFERENCE_RESULT`
- `CMD_GET_BENCHMARK`
- `CMD_GET_SECURE_BENCHMARK`
- `CMD_COMPUTE_ENCLAVE_INFO`
- `CMD_VALIDATE_M_UPDATE`
- `CMD_SET_MAX_INFERENCES`
- `CMD_UPDATE_RATE_LIMIT`
- `CMD_CREATE_ENCLAVE`
- `CMD_DESTROY_ENCLAVE`
- `CMD_RUN_INFERENCE`

Report output includes per-operation: runs, OK/fail count, avg/min/max latency.

### Step 5: Retrieve Metrics
```
Mac → Device: CMD_GET_INFERENCE_COUNT (0x05)
Device → Mac: Inference count (4 bytes LE)

Mac → Device: CMD_GET_REMAINING_INFERENCES (0x06)
Device → Mac: Remaining quota (4 bytes LE)

Mac → Device: CMD_GET_BENCHMARK (0x08)
Device → Mac: NS benchmark payload (64B / 184B / 232B / 272B depending on firmware)

Mac → Device: CMD_GET_SECURE_BENCHMARK (0x09)
Device → Mac: Secure benchmark payload (88B)

### Paper-oriented fields

For publication/analysis workflows, focus on:

- `run_enclave_count`, `run_enclave_avg_cycles`, `run_enclave_min_cycles`, `run_enclave_max_cycles`
- `irq_atomic_count`, `irq_atomic_avg_cycles`, `irq_atomic_min_cycles`, `irq_atomic_max_cycles`
- `inference_requests_total` and `enclave_info_validation_failures`
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
build/DEVICE_BENCHMARK_RESULTS.md  # Full benchmark report (NS/S + operation benchmark)
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
- Protocol definition: [tools/README.md](../tools/README.md)
- Benchmark script: [tools/get_device_benchmark.py](../tools/get_device_benchmark.py)
- Interactive host verifier: [tools/mac_provider.py](../tools/mac_provider.py)
- Device code: [src/uart_protocol.cpp](../src/uart_protocol.cpp)
