# VeCoDI Benchmark Results

## Command Executed

```bash
west flash && sleep 20
python3 tools/create_enclave_size_benchmark.py /dev/cu.usbmodem1203 --runs 100 --size 512 1024 4096 8192 16384 32768 39552 --output build/create_enclave_size_benchmark_100_real_fixed.json
```

**Parameters:**
- Device: `/dev/cu.usbmodem1203` (nucleo_l552ze_q board - STM32L552 Cortex-M33)
- Baud Rate: 115200
- Runs per size: 100 trials
- Sizes tested: 512B, 1KB, 4KB, 8KB, 16KB, 32KB, 39KB (full encrypted blob)
- Method: internal embedded counters (per-operation deltas)
- Test date: 29 avril 2026

## Results Summary (Milliseconds Only)

### Quick Reference Table

| Decrypt Size | Create (ms) | Destroy (ms) |
|---|---|---|
| **512 B** | 12.401 ± 0.040 | 0.223 ± 0.000 |
| **1 KB** | 13.327 ± 0.000 | 0.255 ± 0.000 |
| **4 KB** | 18.899 ± 0.000 | 0.451 ± 0.000 |
| **8 KB** | 26.327 ± 0.000 | 0.711 ± 0.000 |
| **16 KB** | 21.190 ± 0.000 | 1.233 ± 0.000 |
| **32 KB** | 33.907 ± 7.175 | 2.275 ± 0.000 |
| **39 KB** | 45.650 ± 6.758 | 2.707 ± 0.000 |

## Detailed Results (ms + cycles)

### Create Enclave (create_enc)

| Decrypt Size | Time (ms) | Cycles | Stddev (cycles) |
|---|---|---|---|
| **512 B** | 12.401 ± 0.040 | 1,364,153 ± 4,360 | 0.320% |
| **1 KB** | 13.327 ± 0.000 | 1,465,933 ± 3.9 | 0.0003% |
| **4 KB** | 18.899 ± 0.000 | 2,078,857 ± 3.0 | 0.00014% |
| **8 KB** | 26.327 ± 0.000 | 2,895,958 ± 0.5 | 0.00002% |
| **16 KB** | 21.190 ± 0.000 | 2,330,882 ± 27.6 | 0.0012% |
| **32 KB** | 33.907 ± 7.175 | 3,729,787 ± 789,252 | 21.16% |
| **39 KB** | 45.650 ± 6.758 | 5,021,465 ± 743,398 | 14.81% |

### AES Decrypt (internal)

| Decrypt Size | Time (ms) | Cycles | Stddev (cycles) |
|---|---|---|---|
| **512 B** | 1.584 ± 0.040 | 174,220 ± 4,359 | 2.50% |
| **1 KB** | 2.477 ± 0.000 | 272,416 ± 3.7 | 0.0014% |
| **4 KB** | 7.853 ± 0.000 | 863,796 ± 0.9 | 0.00010% |
| **8 KB** | 15.020 ± 0.000 | 1,652,225 ± 0.0 | 0.00000% |
| **16 KB** | 9.362 ± 0.000 | 1,029,805 ± 27.6 | 0.0027% |
| **32 KB** | 21.037 ± 7.175 | 2,314,022 ± 789,252 | 34.11% |
| **39 KB** | 27.356 ± 6.758 | 3,009,138 ± 743,397 | 24.71% |

### Destroy Enclave (destroy_enc)

| Decrypt Size | Time (ms) | Cycles | Stddev (cycles) |
|---|---|---|---|
| **512 B** | 0.223 ± 0.000 | 24,485 ± 1.2 | 0.0049% |
| **1 KB** | 0.255 ± 0.000 | 28,069 ± 1.2 | 0.0043% |
| **4 KB** | 0.451 ± 0.000 | 49,573 ± 1.7 | 0.0034% |
| **8 KB** | 0.711 ± 0.000 | 78,245 ± 1.7 | 0.0022% |
| **16 KB** | 1.233 ± 0.000 | 135,589 ± 0.0 | 0.0000% |
| **32 KB** | 2.275 ± 0.000 | 250,277 ± 2.1 | 0.0008% |
| **39 KB** | 2.707 ± 0.000 | 297,765 ± 0.0 | 0.0000% |

## Key Observations

1. **Embedded Counter Metrics**: Results now reflect internal MCU cost per operation (not host UART timing).
2. **Create Scaling**: Create cost generally scales with decrypt size, with variance spikes at 32KB and 39KB.
3. **Destroy Scaling**: Destroy remains highly deterministic across sizes.
4. **AES Decrypt Contribution**: Decrypt is a major part of create cost and follows payload size trend.
5. **Range**: Create spans from ~1.36M cycles (512B) to ~5.02M cycles (39KB).

## Performance Scaling Analysis

- **Create per KB**: clear increasing trend with large-size variance (32KB and 39KB).
- **Destroy per KB**: near-linear and very stable.
- **Variance hotspot**: high jitter on large payloads suggests runtime path/cache/TF-M side effects under large decrypt windows.

## Benchmark Data File

Full detailed results (per-run samples): `build/create_enclave_size_benchmark_100_real_fixed.json`

## Test Environment

- **Board**: ST Microelectronics nucleo_l552ze_q (STM32L552, Cortex-M33)
- **CPU Frequency**: 110 MHz
- **Encryption**: AES decryption in Secure World (TFM)
- **Date**: 29 avril 2026 (100-run real campaign)
- **Measurement basis**: internal embedded counters (per-op deltas), plus host timing for reference

## Full Flow Benchmark

If you want the complete application flow with `M_update`, `create`, `inference`, and `destroy` in one program, use:

```bash
python3 tools/full_flow_benchmark.py /dev/tty.usbmodem1203 --runs 100 --c-limit 10
```

Optional image upload is supported with `--image` and `--image-label`. The script writes its JSON output to `build/full_flow_benchmark.json`.
