# Performance Benchmark Results

**Date:** 11 April 2026  
**Platform:** STM32L552ZE-Q (Cortex-M33 @ 110 MHz)  
**Configuration:** TrustZone-M, TF-M Secure partition, CMSIS-NN optimized  
**Test:** Single inference with ECDH handshake and M_update (quota=20)

## Complete Results

```
╔══════════════════════════════════════════════════════════════╗
║        NON-SECURE (NS) BENCHMARK RESULTS                    ║
╠══════════════════════════════════════════════════════════════╣
║ ENCLAVE LIFECYCLE                                            ║
╟──────────────────────────────────────────────────────────────╢
║ Create:     4,285,049 cycles  (    39.0 ms)               ║
║ Destroy:            0 cycles  (     0.0 ms)               ║
╟──────────────────────────────────────────────────────────────╢
║ CRYPTOGRAPHIC OPERATIONS                                     ║
╟──────────────────────────────────────────────────────────────╢
║ AES Decrypt:  1,146,540 cycles  (    10.4 ms)               ║
╟──────────────────────────────────────────────────────────────╢
║ INFERENCE PERFORMANCE                                        ║
╟──────────────────────────────────────────────────────────────╢
║ Early Layers: 2,821,449 cycles  (   25.6 ms)              ║
║ Late Layers:  1,275,311 cycles  (    11.6 ms)              ║
║ Total Inf:    4,739,095 cycles  (    43.1 ms)              ║
╟──────────────────────────────────────────────────────────────╢
║ END-TO-END METRICS                                           ║
╟──────────────────────────────────────────────────────────────╢
║ run_enclave():        0 cycles  (    0.0 ms)             ║
║ Inferences:            12 total                              ║
╟──────────────────────────────────────────────────────────────╢
║ MEMORY USAGE (NS World)                                      ║
╟──────────────────────────────────────────────────────────────╢
║ Heap Used:            0 bytes  (       0 KB)                   ║
║ Stack Used:       1,536 bytes  (       2 KB)                   ║
║ RAM Used:       125,111 / 131,072 bytes (95.5%)              ║
║ Flash Used:     140,640 / 262,144 bytes (53.6%)              ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║        SECURE (S) BENCHMARK RESULTS                         ║
╠══════════════════════════════════════════════════════════════╣
║ CRYPTOGRAPHIC OPERATIONS                                     ║
╟──────────────────────────────────────────────────────────────╢
║ AES Decrypt:  7,714,544 cycles  (    70.1 ms) [1 ops]       ║
║ Late Hash:            0 cycles  (     0.0 ms) [0 ops]       ║
║ Digest Compute:       0 cycles  (     0.0 ms) [0 ops]       ║
╟──────────────────────────────────────────────────────────────╢
║ COUNTER MANAGEMENT                                           ║
╟──────────────────────────────────────────────────────────────╢
║ Get Max:            507 cycles  (     0.0 ms)               ║
║ Check Allowed:        0 cycles  (     0.0 ms)               ║
║ Increment:            0 cycles  (     0.0 ms)               ║
║ Reset:                0 cycles  (     0.0 ms)               ║
║ Total Ops:           15 operations                    ║
╟──────────────────────────────────────────────────────────────╢
║ MEMORY USAGE (Secure World)                                 ║
╟──────────────────────────────────────────────────────────────╢
║ RAM Used:        52,732 / 65,536 bytes (80.5%)               ║
║ Flash Used:     119,532 / 134,144 bytes (89.1%)              ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║        COMBINED SYSTEM METRICS                              ║
╠══════════════════════════════════════════════════════════════╣
║ Total RAM:      177,843 / 196,608 bytes (90.5%)             ║
║ Total Flash:    260,172 / 396,288 bytes (65.7%)             ║
╚══════════════════════════════════════════════════════════════╝
```

## Summary

- **Host-measured inference time (avg)**: 1204.9 ms
- **Host-measured inference time (total)**: 6024.4 ms
- **Device total inference cycles**: 4,739,095 (43.1 ms @ 110 MHz)
- **run_enclave aggregate**: count=0, avg=0 cycles, min/max=0/0
- **IRQ-masked atomic window**: count=12, avg=9,101,834 cycles (82.744 ms), sum=109,222,014 cycles (992.927 ms), min/max=7,788,161/10,130,892
- **CREATE atomic window**: count=1, avg=4,287,496 cycles (38.977 ms), sum=4,287,496 cycles (38.977 ms), min/max=4,287,496/4,287,496
- **Inference requests / validation failures**: 12 / 0
- **ECDH handshake**: ✓ SUCCESS
- **M_update validation**: ✓ SUCCESS
- **Inference execution**: ✓ SUCCESS
- **Operation benchmark**: 11 ops, ok=27, fail=0

## Inference Hotfix Validation (11 April 2026)

- Regression investigated: verified inference rejected after successful auth/setup sequence.
- Runtime fix validated on hardware with flow `1 -> 3 -> 21 -> 9 -> 11`.
- Observed result: `verified inference OK, pred=5, PoX=VALID` then `result: pred=5, expected=5`.

## SAU Window Behavior (Current)

- `Create_Enclave`: windows open for setup, then close at finalize.
- Atomic inference: windows reopen at start and close at complete.
- `Destroy_Enclave`: windows reopen for NS cleanup/zeroization path.

## Host UART Operation Benchmark

| Operation | CMD | Runs | OK | Fail | Avg (ms) | Min (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| GET_DEVICE_PUBKEY | 0x0C | 3 | 3 | 0 | 6.98 | 6.92 | 7.02 |
| GET_MAX_INFERENCES | 0x03 | 3 | 3 | 0 | 1.99 | 1.94 | 2.01 |
| GET_INFERENCE_COUNT | 0x05 | 3 | 3 | 0 | 1.99 | 1.97 | 2.01 |
| GET_REMAINING_INF | 0x06 | 3 | 3 | 0 | 2.00 | 2.00 | 2.01 |
| GET_INFERENCE_RESULT | 0x0A | 3 | 3 | 0 | 1.99 | 1.90 | 2.09 |
| GET_BENCHMARK | 0x08 | 3 | 3 | 0 | 25.01 | 24.96 | 25.06 |
| GET_SECURE_BENCH | 0x09 | 3 | 3 | 0 | 8.98 | 8.94 | 9.02 |
| COMPUTE_ENCLAVE_INFO | 0x01 | 3 | 3 | 0 | 250.96 | 250.71 | 251.16 |
| VALIDATE_M_UPDATE | 0x02 | 1 | 1 | 0 | 16.96 | 16.96 | 16.96 |
| SET_MAX_INFERENCES | 0x0B | 1 | 1 | 0 | 1.91 | 1.91 | 1.91 |
| RUN_INFERENCE | 0x04 | 1 | 1 | 0 | 1205.89 | 1205.89 | 1205.89 |

## NS Aggregate Cycle Statistics

| Stage | Count | Sum (cycles) | Avg (cycles) | Min (cycles) | Max (cycles) | Avg (ms) |
|---|---:|---:|---:|---:|---:|---:|
| enclave_create | 1 | 4,285,049 | 4,285,049 | 4,285,049 | 4,285,049 | 38.955 |
| aes_decrypt | 1 | 1,146,540 | 1,146,540 | 1,146,540 | 1,146,540 | 10.423 |
| early_layers | 12 | 31,661,126 | 2,638,427 | 623,250 | 2,821,972 | 23.986 |
| late_layers | 12 | 24,091,227 | 2,007,602 | 1,271,634 | 3,473,550 | 18.251 |
| total_inference | 12 | 63,446,271 | 5,287,189 | 4,733,441 | 6,935,814 | 48.065 |
| irq_atomic | 12 | 109,222,014 | 9,101,834 | 7,788,161 | 10,130,892 | 82.744 |
| create_atomic | 1 | 4,287,496 | 4,287,496 | 4,287,496 | 4,287,496 | 38.977 |

## Inference Results (5 runs)

| Run | Status | Prediction | Expected | Match | Host time (ms) |
|---|---|---|---|---|---:|
| 1 | OK | 5 (dog) | 5 (dog) | ✓ | 1204.3 |
| 2 | OK | 2 (bird) | 6 (frog) | ✗ | 1205.4 |
| 3 | OK | 8 (ship) | 8 (ship) | ✓ | 1204.8 |
| 4 | OK | 5 (dog) | 5 (dog) | ✓ | 1204.7 |
| 5 | OK | 0 (airplane) | 0 (airplane) | ✓ | 1205.3 |

## Memory Footprint Share (NS vs Secure)

### Used footprint share

| Resource | NS used | Secure used | Total used | NS share | Secure share |
|---|---:|---:|---:|---:|---:|
| RAM | 125,111 | 52,732 | 177,843 | 70.3% | 29.7% |
| Flash | 140,640 | 119,532 | 260,172 | 54.1% | 45.9% |

### Capacity split

| Resource | NS capacity | Secure capacity | Total capacity | NS share | Secure share |
|---|---:|---:|---:|---:|---:|
| RAM | 131,072 | 65,536 | 196,608 | 66.7% | 33.3% |
| Flash | 262,144 | 134,144 | 396,288 | 66.1% | 33.9% |

## Memory Footprint Analysis (ELF Extracted)

### ELF Sections

- .text: 37,944 bytes (37.1 KB)
- .rodata: 99,620 bytes (97.3 KB)
- .data: 3,979 bytes (3.9 KB)
- .bss: 121,130 bytes (118.3 KB)
- Flash subtotal (.text + .rodata): 137,564 bytes (134.3 KB)
- RAM subtotal (.data + .bss): 125,109 bytes (122.2 KB)

### Largest Symbols (Top 20)

| # | Symbol | Size (bytes) | Size (KB) |
|---|---|---:|---:|
| 1 | _ZL14enclave_memory | 39,552 | 38.6 |
| 2 | late_wt_encrypted | 39,552 | 38.6 |
| 3 | _ZL11wt_conv2d_6 | 18,432 | 18.0 |
| 4 | _ZL10early_buf0 | 16,384 | 16.0 |
| 5 | _ZL10early_buf1 | 16,384 | 16.0 |
| 6 | _ZL10early_buf2 | 16,384 | 16.0 |
| 7 | _ZL11wt_conv2d_4 | 9,216 | 9.0 |
| 8 | _ZL10early_skip | 8,192 | 8.0 |
| 9 | _ZL13early_ctx_buf | 8,192 | 8.0 |
| 10 | _ZL11wt_conv2d_3 | 4,608 | 4.5 |
| 11 | _ZL12early_output | 4,096 | 4.0 |
| 12 | _ZL12late_ctx_buf | 4,096 | 4.0 |
| 13 | arm_nn_softmax_common_s8 | 3,252 | 3.2 |
| 14 | _ZL9rx_buffer | 3,201 | 3.1 |
| 15 | _ZL12input_buffer | 3,072 | 3.0 |
| 16 | img_0 | 3,072 | 3.0 |
| 17 | img_1 | 3,072 | 3.0 |
| 18 | img_10 | 3,072 | 3.0 |
| 19 | img_11 | 3,072 | 3.0 |
| 20 | img_12 | 3,072 | 3.0 |

## Option Source Image (Mac vs Device)

Le script tools/full_flow_benchmark.py supporte deux modes de source image pour l inference:

1. Image envoyee depuis le Mac
2. Image locale cote device (test_images dans le firmware)

Mode 1 - image depuis le Mac:

```bash
python3 tools/full_flow_benchmark.py /dev/cu.usbmodem1203 \
	--runs 3 \
	--image cifar_input.raw \
	--image-label 3 \
	--output build/full_flow_benchmark_mac_image.json
```

Mode 2 - image depuis le device:

```bash
python3 tools/full_flow_benchmark.py /dev/cu.usbmodem1203 \
	--runs 3 \
	--use-device-image \
	--output build/full_flow_benchmark_device_image.json
```

Regle de priorite:

- Si --image et --use-device-image sont utilises ensemble, le mode device est prioritaire (pas d upload depuis le Mac).

Metadonnees JSON de sortie:

- image_used: true si upload Mac, false sinon
- image_source: mac ou device

