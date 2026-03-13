# tools

Utilities for model artifacts and UART protocol validation.

## Main script (manual test)

- `mac_provider.py`: interactive Mac client for the STM32 device.

Run:

```bash
./.venv/bin/python tools/mac_provider.py /dev/tty.usbmodem11203 115200
```

## Interactive menu summary

Session/Auth:
- `1` ECDH handshake (derive dynamic session key)
- `2` Compute EnclaveInfo
- `3` Send M_update (prompts current quota and suggests valid next `c_limit`)
- `4` Get device public signing key `pk_d`

Quota/Counters:
- `5` Get max inferences
- `6` Set max inferences (manual override command)
- `7` Get inference count
- `8` Get remaining inferences

Inference:
- `9` Verified inference (encrypted `M_inf`, signature checked on device)
- `10` Legacy inference (empty payload)
- `11` Get last prediction/expected

Bench/Debug:
- `12` Get NS benchmark metrics
- `13` Get Secure benchmark metrics
- `14` Read console output
- `15` Deterministic SAU state (UNREGISTERED/OPEN/CLOSED + base + size)
- `16` Raw UART command
- `17` Session status

## Important behavior

- `9` requires:
  - successful `1` (ECDH)
  - successful `3` (M_update accepted)
- Anti-replay is enforced by device: `M_update` is rejected when `c_limit <= current max`.
- If `3` is rejected, resend with higher `c_limit`.

## Other helper scripts

- `get_device_benchmark.py`: automated benchmark and protocol run.
- `gen_late_wt_plain.py`, `gen_late_wt_enc_header.py`, `gen_late_biases.py`: model artifact generation.