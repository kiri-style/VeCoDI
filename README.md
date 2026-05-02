# Secure Inference on NUCLEO-L552ZE-Q

Reproduction of experiments for secure inference benchmarks on STM32L552 Cortex-M33.

## Prerequisites

- **Board**: NUCLEO-L552ZE-Q
- **MCU**: STM32L552
- **ARM Core**: Cortex-M33

### Software Requirements

```bash
west >= 1.5.0
Zephyr SDK >= 0.17.4
STM32CubeProgrammer >= 2.21.0
Python 3.7+
```

### Installation

```bash
pip install west
west init -m https://github.com/norrathep/secure-inference-nucleo.git workspace
cd workspace
west update
```

## Build

### Clean Build

```bash
west build -b nucleo_l552ze_q/stm32l552xx/ns --pristine=always
```

### Incremental Build

```bash
west build -b nucleo_l552ze_q/stm32l552xx/ns
```

## Flash

```bash
west flash
```

**Note**: Serial port example: `/dev/cu.usbmodem1203` (adjust for your system)

## Benchmarks

### Create/Destroy vs Payload Size

```bash
west flash && sleep 20
python3 tools/create_enclave_size_benchmark.py /dev/cu.usbmodem1203 \
  --runs 100 \
  --size 512 1024 4096 8192 16384 32768 39552 \
  --output build/create_enclave_size_benchmark_100_real_fixed.json
```

### Full Flow Benchmark (Default)

```bash
python3 tools/full_flow_benchmark.py /dev/tty.usbmodem1203 \
  --runs 100 \
  --c-limit 10
```

### Full Flow Benchmark with Host Image

```bash
python3 tools/full_flow_benchmark.py /dev/cu.usbmodem1203 \
  --runs 3 \
  --image cifar_input.raw \
  --image-label 3 \
  --output build/full_flow_benchmark_mac_image.json
```

### Full Flow Benchmark with Device Image

```bash
python3 tools/full_flow_benchmark.py /dev/cu.usbmodem1203 \
  --runs 3 \
  --use-device-image \
  --output build/full_flow_benchmark_device_image.json
```

**Priority Rule**: If both `--image` and `--use-device-image` are provided, device image mode takes precedence.

## Optional Configuration

### Increase NS Flash Allocation

Edit the flash layout:

```bash
vim ../modules/tee/tf-m/trusted-firmware-m/platform/ext/target/stm/nucleo_l552ze_q/partition/flash_layout.h
```

Edit the device tree:

```bash
vim ./boards/st/nucleo_l552ze_q/nucleo_l552ze_q_stm32l552xx_ns.dts
```

Rebuild with `west build -b nucleo_l552ze_q/stm32l552xx/ns`.

## Reference

[https://github.com/norrathep/secure-inference-nucleo/tree/main](https://github.com/norrathep/secure-inference-nucleo/tree/main)