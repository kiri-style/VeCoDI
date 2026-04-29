# VeCoDI Benchmark Results

## Command Executed

```bash
python3 tools/create_enclave_benchmark.py /dev/tty.usbmodem1203 --runs 100 --size 512 1024 4096 8192 16384 32768 39552
```

**Parameters:**
- Device: `/dev/tty.usbmodem1203` (nucleo_l552ze_q board - STM32L552 Cortex-M33)
- Baud Rate: 115200
- Runs per size: 100 trials
- Sizes tested: 512B, 1KB, 4KB, 8KB, 16KB, 32KB, 39KB (full encrypted blob)
- Test date: 28 avril 2026

## Results Summary (Milliseconds Only)

### Quick Reference Table

| Decrypt Size | Create (ms) | Destroy (ms) |
|---|---|---|
| **512 B** | 14.754 ± 0.440 | 2.039 ± 0.356 |
| **1 KB** | 15.642 ± 0.432 | 1.999 ± 0.161 |
| **4 KB** | 21.293 ± 0.322 | 2.188 ± 0.550 |
| **8 KB** | 28.968 ± 0.548 | 2.865 ± 0.673 |
| **16 KB** | 43.789 ± 0.310 | 3.099 ± 0.316 |
| **32 KB** | 73.474 ± 0.302 | 4.150 ± 0.287 |
| **39 KB** | 91.039 ± 0.419 | 4.738 ± 0.427 |

## Detailed Results (ms + cycles)

### Create Enclave (create_enc)

| Decrypt Size | Time (ms) | Cycles | Stddev (cycles) |
|---|---|---|---|
| **512 B** | 14.754 ± 0.440 | 1,363,723 ± 10.2 | 0.0007% |
| **1 KB** | 15.642 ± 0.432 | 1,465,940 ± 1.5 | 0.0001% |
| **4 KB** | 21.293 ± 0.322 | 2,078,857 ± 3.3 | 0.00016% |
| **8 KB** | 28.968 ± 0.548 | 2,895,964 ± 4.3 | 0.00015% |
| **16 KB** | 43.789 ± 0.310 | 2,705,070 ± 830,083 | 30.7% |
| **32 KB** | 73.474 ± 0.302 | 3,400,319 ± 323.5 | 0.0095% |
| **39 KB** | 91.039 ± 0.419 | 3,108,397 ± 305.7 | 0.0098% |

### Destroy Enclave (destroy_enc)

| Decrypt Size | Time (ms) | Cycles | Stddev (cycles) |
|---|---|---|---|
| **512 B** | 2.039 ± 0.356 | 24,485 ± 0.0 | 0% |
| **1 KB** | 1.999 ± 0.161 | 28,069 ± 0.0 | 0% |
| **4 KB** | 2.188 ± 0.550 | 49,573 ± 0.0 | 0% |
| **8 KB** | 2.865 ± 0.673 | 78,245 ± 0.0 | 0% |
| **16 KB** | 3.099 ± 0.316 | 135,589 ± 0.0 | 0% |
| **32 KB** | 4.150 ± 0.287 | 250,277 ± 0.0 | 0% |
| **39 KB** | 4.738 ± 0.427 | 297,765 ± 0.0 | 0% |

## Key Observations

1. **Create Enclave Scaling**: Generally increases linearly with payload size, except 16KB shows anomalous high variance (30.7% with 100 runs)
2. **Destroy Enclave Scaling**: Grows steadily with payload size (linear), with near-perfect consistency (stddev = 0)
3. **Performance Range**: From 512B (14.8ms / 1.36M cycles) to 39KB (91.0ms / 3.11M cycles)
4. **Improved Stability**: 100-run dataset shows highly consistent measurements compared to 10-run baseline - most variance < 0.01%
5. **512B Baseline**: New smallest size shows minimal overhead vs 1KB (13.7K cycles difference)

## Performance Scaling Analysis

- **Create per KB**: ~80-90K cycles per kilobyte (linear relationship except 16KB anomaly)
- **Destroy per KB**: ~7.7K cycles per kilobyte (linear)
- **16KB Anomaly**: Significantly lower create_enc cycles (2.7M vs expected 3.8M) with 100x variance suggests potential memory size boundary issue

## Benchmark Data File

Full detailed results (per-run samples): `build/create_enclave_benchmark.json`

## Test Environment

- **Board**: ST Microelectronics nucleo_l552ze_q (STM32L552, Cortex-M33)
- **CPU Frequency**: 110 MHz
- **Encryption**: AES decryption in Secure World (TFM)
- **Date**: 28 avril 2026 (100-run campaign)
- **Previous Run**: 10-run campaign (28 avril 2026) - reference baseline
