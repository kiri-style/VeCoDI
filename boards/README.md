# boards

## Purpose
Board-specific Zephyr configuration overrides for this sample.

## Contents
- `nucleo_l552ze_q_stm32l552xx_ns.conf`: Non-secure (TrustZone) settings for NUCLEO-L552ZE-Q.

## What it configures
- TF-M/IPC configuration for NS build
- Board-specific memory/layout adjustments
- Sample-specific Kconfig overrides

## Notes
Add new `<board>.conf` files here if you extend to other targets.