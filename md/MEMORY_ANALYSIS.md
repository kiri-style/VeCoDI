# Memory Footprint Analysis - Dynamic ELF Binary Breakdown

**Generated**: 5 March 2026  
**Device**: STM32L552ZE-Q (Cortex-M33 @ 110 MHz)  
**Build**: `west build -b nucleo_l552ze_q/stm32l552xx/ns`  
**Analysis Tool**: `arm-zephyr-eabi-readelf` (real binary parsing)

## Executive Summary

The split inference architecture utilizes **88.8% of total system RAM** and **74.6% of total Flash**, with:
- **Non-Secure (NS) World**: 121,788 bytes RAM (92.9%), 176,160 bytes Flash (67.2%)
- **Secure (S) World**: 52,732 bytes RAM (80.5%), 119,532 bytes Flash (89.1%)
- **Total System**: 174,520 bytes RAM / 196,608 available, 295,692 bytes Flash / 396,288 available

## Flash (ROM) Memory - 295,692 Bytes (74.6% of 396 KB)

### Non-Secure Flash: 176,160 bytes (67.2% of 256 KB)

#### Sections (ELF Analysis)
- **rodata** (Read-Only Data): 138,252 bytes (135.0 KB)
  - Encrypted late-layer weights: 39,552 bytes
  - Early-layer weights (plain ROM): ~37 KB
    - `wt_conv2d_0`: 432 bytes
    - `wt_conv2d_1`: 2,304 bytes
    - `wt_conv2d_2`: 2,304 bytes
    - `wt_conv2d_3`: 4,608 bytes
    - `wt_conv2d_4`: 9,216 bytes
    - `wt_conv2d_5`: 512 bytes
    - `wt_conv2d_6`: 18,432 bytes
  - Constants, device table, etc: ~58 KB

- **text** (Executable Code): ~38 KB
  - Application code (main.cpp, create_enclave.cpp, run_enclave.cpp, etc.)
  - Zephyr kernel code
  - TensorFlow Lite Micro inference engine
  - CMSIS-NN neural network kernels
  - PSA Crypto client wrappers

#### Top 10 Code/Data Symbols (by size)
```
 1. late_wt_encrypted              39,552 bytes (38.6 KB) - AES-encrypted weights
 2. wt_conv2d_6                    18,432 bytes (18.0 KB) - Early layer
 3. wt_conv2d_4                     9,216 bytes (9.0 KB)
 4. wt_conv2d_3                     4,608 bytes (4.5 KB)
 5. wt_conv2d_2                     2,304 bytes (2.2 KB)
 6. wt_conv2d_1                     2,304 bytes (2.2 KB)
 7. wt_conv2d_5                       512 bytes (0.5 KB)
 8. wt_conv2d_0                       432 bytes (0.4 KB)
 9. device_api_area_sw_isr_table      364 bytes (0.4 KB)
10. init_array                        292 bytes (0.3 KB)
```

### Secure Flash: 119,532 bytes (89.1% of 134 KB)

- TF-M bootloader (BL2)
- TF-M secure partition
- Dummy partition (custom crypto)
- PSA API stubs

---

## RAM (SRAM) Memory - 174,520 Bytes (88.8% of 192 KB)

### Non-Secure RAM: 121,788 bytes (92.9% of 128 KB)

#### Sections (ELF Analysis)

**bss** (Zero-Initialized): 117,809 bytes (115.0 KB)
- Early inference buffers: 48 KB
  - `early_buf0`: 16,384 bytes (16 KB)
  - `early_buf1`: 16,384 bytes (16 KB)
  - `early_buf2`: 16,384 bytes (16 KB)
  
- Context/state buffers: 12.2 KB
  - `early_ctx_buf`: 8,192 bytes (8 KB)
  - `late_ctx_buf`: 4,096 bytes (4 KB)
  
- Enclave region (for decrypted weights): 39,552 bytes (38.6 KB)
  - Allocated at runtime: `enclave_memory`
  - Holds late-layer weights decrypted by Secure world
  
- Test image storage: ~3 KB
  - `img_0` to `img_19`: 3,072 bytes each (test CIFAR-10 samples)
  
- Main stack: 4,096 bytes (4 KB)
  - `z_main_stack` (CONFIG_MAIN_STACK_SIZE=4096)
  
- Output buffers: ~2.5 KB
  - `early_output`: 4,096 bytes
  - `early_skip`: 8,192 bytes

**data** (Initialized Globals): 3,976 bytes (3.9 KB)
- Biases for all layers
- Quantization parameters (scale, zero_point)
- Global configuration variables
- Thread/synchronization primitives

#### Detailed Symbol Breakdown (Top 20)
```
 1. enclave_memory                    39,552 bytes (38.6 KB) - BSS
 2. early_buf0                        16,384 bytes (16.0 KB) - BSS
 3. early_buf1                        16,384 bytes (16.0 KB) - BSS
 4. early_buf2                        16,384 bytes (16.0 KB) - BSS
 5. wt_conv2d_6                       18,432 bytes (18.0 KB) - RODATA
 6. wt_conv2d_4                        9,216 bytes (9.0 KB)  - RODATA
 7. early_skip                         8,192 bytes (8.0 KB)  - BSS
 8. early_ctx_buf                      8,192 bytes (8.0 KB)  - BSS
 9. wt_conv2d_3                        4,608 bytes (4.5 KB)  - RODATA
10. early_output                       4,096 bytes (4.0 KB)  - BSS
11. late_ctx_buf                       4,096 bytes (4.0 KB)  - BSS
12. z_main_stack                       4,096 bytes (4.0 KB)  - BSS
13. arm_nn_softmax_common_s8           3,252 bytes (3.2 KB)  - TEXT
14. input_buffer                       3,072 bytes (3.0 KB)  - BSS
15. img_0 to img_12                    3,072 bytes each      - BSS (20 test images)
16. arm_convolve_s8                    ~2 KB                 - TEXT
17. arm_nn_activationq15_generic       ~1.5 KB               - TEXT
18. Various init structs               ~800 bytes total
```

### Secure RAM: 52,732 bytes (80.5% of 64 KB)

- PSA IPC message buffers
- Secure partition state
- TF-M context/stacks
- PSA Crypto session state

---

## Component Analysis

### Memory Distribution by Function

**Model Weights**: ~98 KB (26% of total memory)
- Early layer weights (plain): 37 KB (rodata, decrypted at load)
- Late layer weights (encrypted): 39.5 KB (rodata, decrypted at runtime to `enclave_memory`)
- Bias parameters: ~2 KB

**Tensor Buffers**: ~60 KB (16% of total memory)
- Early layer activation buffers: 48 KB (3 × 16 KB for ping-pong inference)
- Context/state for layers: 12 KB
- Output buffer: 4 KB

**Enclave/Security**: ~40 KB (11% of total memory)
- Enclave memory region: 39.5 KB (for decrypted late weights in NS world)
- PSA/Crypto overhead: ~1 KB

**Zephyr + TensorFlow**: ~45 KB (12% of total memory)
- Zephyr kernel: ~15 KB
- TensorFlow Lite Micro: ~18 KB
- CMSIS-NN optimizations: ~12 KB

**Application Code**: ~25 KB (7% of total memory)
- Split inference control: 8 KB
- Enclave management: 6 KB
- UART protocol: 5 KB
- Benchmark collection: 3 KB
- Test images: ~3 KB

---

## Recommendations for Further Optimization

### High Priority (Potential 10-20 KB savings)
1. **Reduce test images** - Currently 20 × 3 KB = 60 KB in ROM
   - Keep only 4-5 representative samples (~12 KB)
   - Load remaining from external storage if needed

2. **Inline small layers** - `wt_conv2d_0/1/2/5` are < 3 KB each
   - Consider combining or using lookup tables

### Medium Priority (5-10 KB savings)
3. **Use half-precision for context buffers** - Currently storing float32
   - Reduce `early_ctx_buf` from 8 KB to 4 KB using float16

4. **Compress early weights** - 37 KB of early weights could use RLE or sparse encoding
   - Potential 20-30% reduction with minimal decompression overhead

### Low Priority (< 5 KB savings)
5. **Move debug info to external storage** - .debug_* sections = ~700 KB
   - Doesn't affect runtime but reduces binary size for distribution

---

## Build Configuration

**Compiler Flags**:
- `-Os` (Optimize for size)
- `-ffunction-sections -fdata-sections` (Link-time GC)
- `--gc-sections` (Remove unused code)

**Zephyr Config**:
```
CONFIG_CPP=y
CONFIG_STD_CPP17=y
CONFIG_TENSORFLOW_LITE_MICRO=y
CONFIG_MAIN_STACK_SIZE=4096
CONFIG_CMSIS_NN=y
```

**TF-M Config**:
```
CONFIG_BUILD_WITH_TFM=y
CONFIG_TFM_PARTITION_CRYPTO=y
CONFIG_TFM_IPC=y
```

---

## Performance vs. Memory Trade-offs

The current configuration prioritizes **security and functionality** over maximum compactness:

| Aspect | Current | Minimum | Notes |
|--------|---------|---------|-------|
| Early buffers | 48 KB (3×16KB) | 32 KB (2×16KB) | Would reduce parallelism |
| Test images | 60 KB | 0 KB | Needed for validation |
| Enclave memory | 40 KB | 39.5 KB | Required for late weights |
| Stack size | 4 KB | 2 KB | Inference needs headroom |
| **Total minimum** | 174 KB | ~165 KB | **5% savings possible** |

---

## Tools & Methodology

**Analysis performed using**:
```bash
# Section sizes
arm-zephyr-eabi-readelf -S build/zephyr/zephyr.elf

# Symbol sizes  
arm-zephyr-eabi-nm -S build/zephyr/zephyr.elf

# Memory map
arm-zephyr-eabi-objdump -t build/zephyr/zephyr.elf
```

**Device metrics collected via UART**:
- NS and Secure benchmark commands (0x08, 0x09)
- Real-time memory usage during inference
- Cycle-accurate performance data

---

## References

- [README.rst](README.rst) - Main project overview
- [src/README.md](src/README.md) - Source code organization
- [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) - Performance metrics
- Build artifacts: `build/zephyr/zephyr.elf` (compiled binary)
