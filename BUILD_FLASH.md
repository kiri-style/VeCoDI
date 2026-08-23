# Build & Flash

## Prerequisites

- West: v1.5.0+
- Zephyr SDK: 0.17.4
- STM32CubeProgrammer: v2.21.0
- Board: NUCLEO-L552ZE-Q (STM32L552ZE)

## Build Commands

Clean build:

```bash
west build -b nucleo_l552ze_q/stm32l552xx/ns --pristine=always
```

Incremental build:

```bash
west build -b nucleo_l552ze_q/stm32l552xx/ns
```

## Flash to Board

```bash
west flash
```

Expected output:

```text
Memory Programming ...
  File          : tfm_merged.hex
  Size          : 281.58 KB
  Address       : 0x0C000000

RUNNING Program ...
Application is running, Please Hold on...
```

## Environment Notes

From the project root, ensure the Zephyr environment is loaded before building or flashing:

```bash
. /Users/user/zephyrproject/zephyr/zephyr-env.sh
```

Example sequence:

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/VeCoDI
. /Users/user/zephyrproject/zephyr/zephyr-env.sh
west build -b nucleo_l552ze_q/stm32l552xx/ns --pristine=always
west flash
```

## NS Stack Zero Benchmark

The project includes a dedicated benchmark that asks the board to zero the whole non-secure stack and then returns the cycle count measured by the STM32 cycle counter.

Run directly from the project root:

```bash
python3 tools/ns_stack_zero_time.py --port /dev/tty.usbmodem21103
```

With a known cycle count:

```bash
python3 tools/ns_stack_zero_time.py --cycles 18522 --stack-bytes 3072
```

### How it works

1. The Python script sends UART command `0x1C` to the firmware.
2. The firmware calls `benchmark_measure_ns_stack_zero_time_cycles(CONFIG_MAIN_STACK_SIZE)`.
3. The board allocates a scratch buffer sized like the NS stack, writes non-zero values, measures the time with `k_cycle_get_32()`, then performs `memset(..., 0, ...)`.
4. The cycle counter is stopped and the raw 32-bit cycle count is sent back over UART.
5. The Python helper converts cycles to microseconds, milliseconds, and seconds using the STM32 clock frequency.

Example output:

```text
=== NS stack zero benchmark ===
CPU clock      : 110,000,000 Hz
Stack size     : 3,072 bytes
Cycle count    : 18,517 cycles
Time in us     : 168.336 us
Time in ms     : 0.168 ms
Time in s      : 0.000168 s
Cycles/byte    : 6.028 cycles/byte
```

This is the single-command workflow to reproduce the same experience as the hardware benchmark without manually splitting the steps between firmware and host-side conversion.
