# TensorFlow Lite Micro Hello World - AI Agent Instructions

## Project Overview
This is a Zephyr-based embedded ML sample demonstrating TensorFlow Lite Micro inference on microcontrollers, with a sine wave regression model. The project integrates TensorFlow Lite Micro, Zephyr RTOS, and ARM Trusted Firmware (TFM) for secure execution.

## Architecture & Key Components

### Three-Layer Architecture
1. **Application Layer** (`src/main.cpp`): Calls `setup()` and `loop()` Arduino-style functions
2. **TF-Lite Inference Layer** (`src/main_functions.cpp`): Handles model initialization and quantized input/output
3. **TFM Security Layer** (`dummy_partition/`): Custom TFM partition for cryptographic operations

### Model Execution Flow
- Model loads from binary array: `model_quantized_tflite` (defined in `src/model.h`)
- Input: quantized `int8` x value (linear scale 0→2π)
- Processing: `MicroMutableOpResolver<10>` + `FullyConnected` op
- Output: quantized `int8` y value (dequantized to float via `params.scale/zero_point`)
- Tensor Arena: 2000 bytes statically allocated (see `kTensorArenaSize` in `main_functions.cpp`)

## Critical Workflows

### Build System (CMake-based)
```bash
# Reference kernel (QEMU): west build -p auto -b qemu_x86 . && west build -t run
# CMSIS-NN optimized (Corstone-300): west build -p auto -b mps3/corstone300/fvp . -T sample.tensorflow.helloworld.cmsis_nn
```

**Key CMake patterns:**
- TFM integration: Manifest list configured via `tfm_manifest_list.yaml.in`
- Include paths: `${ZEPHYR_BASE}/../optional/modules/lib/tflite-micro` (relative to Zephyr)
- C++ support: `NO_THREADSAFE_STATICS` compiler flag required
- Model must be included as C array via `#include "model.h"`

### Configuration (prj.conf)
Essential options:
- `CONFIG_CPP=y` + `CONFIG_STD_CPP17=y` (C++17 required)
- `CONFIG_TENSORFLOW_LITE_MICRO=y` (enables TF-Lite module)
- `CONFIG_MAIN_STACK_SIZE=2048` (inference requires sufficient stack)
- `CONFIG_REQUIRES_FLOAT_PRINTF=y` (model output format)
- TFM options: `CONFIG_BUILD_WITH_TFM=y`, `CONFIG_TFM_PARTITION_CRYPTO=y`

## Developer Conventions

### Model Integration
1. **Binary Model Format**: Place `.tflite` (quantized) or `.tflite.c` (generated C array) in `src/`
2. **Symbol Naming**: Model accessed via `model_quantized_tflite` extern array (configurable in `main_functions.cpp:50`)
3. **Quantization**: Model uses `int8` quantization; handle via `params.scale` + `params.zero_point`
4. **Arena Size**: Tune `kTensorArenaSize` if OOM errors; 2000 bytes default for sine model

### Code Organization
- **Pure C** files: `dummy_partition.c`, `test_images_simple.c`, `constants.c`
- **C++** files: `main_functions.cpp`, `main.cpp` (TF-Lite APIs require C++17)
- **Mixed C/C++**: Use `extern "C"` blocks in headers (see `main_functions.h`)
- **Platform-specific**: Output via `HandleOutput()` in `output_handler.hpp` (platform abstraction)

### Testing Pattern
- `sample.yaml` defines two test variants: reference kernels (qemu_x86) and CMSIS-NN optimized (mps3/corstone300/fvp)
- Console harness expects regex: `"x_value:.*, y_value:.*"` (multi-line ordered validation)
- Run count: 10 iterations by default (`NUM_LOOPS` in `main.cpp:57`)

## Integration Points & Dependencies

### External Dependencies
- **Zephyr RTOS**: Kernel APIs, printk, TFM NS interface
- **TensorFlow Lite Micro**: Op resolver, interpreter, schema validation
- **CMSIS-NN**: Optional accelerated kernels (requires Cortex-M + separate config flag)
- **TFM**: Crypto partition integration (PSA API)

### Cross-Component Data Flow
```
Zephyr main() → setup()/loop() → TF-Lite inference → TFM crypto (optional) → HandleOutput()
```

### Tensor Memory Management
- Arena allocated statically: `uint8_t tensor_arena[kTensorArenaSize]` (aligned to 16 bytes)
- Schema version checked at init: `model->version() != TFLITE_SCHEMA_VERSION`
- Tensor pointers obtained post-allocation: `interpreter->input(0)` and `output(0)`

## Gotchas & Common Issues

1. **Missing TF-Lite Includes**: CMakeLists.txt must add TensorFlow Lite include paths explicitly (relative to `${ZEPHYR_BASE}/../optional/modules/`)
2. **Stack Overflow**: Increase `CONFIG_MAIN_STACK_SIZE` if inference crashes; TF-Lite uses significant stack
3. **Float Printf**: Enable `CONFIG_REQUIRES_FLOAT_PRINTF=y` or use custom formatting for model output
4. **Model Schema Mismatch**: Verify `.tflite` model matches `TFLITE_SCHEMA_VERSION` at runtime
5. **Op Resolver Capacity**: Resolver limited to 10 ops (`MicroMutableOpResolver<10>`); expand if using custom ops

## File Reference
- **Model Training**: `train/train_hello_world_model.ipynb` (generates quantized `.tflite`)
- **Validation**: `check_files.sh` (verifies image classification test files)
- **Backup Configs**: `.backup` files preserve original state before modifications
