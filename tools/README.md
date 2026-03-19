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
- `6` Update rate limit (secure API)
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
- `15` SAU state (best-effort; may be blocked by hardened policy)
- `16` Raw UART command
- `17` Session status (`dynamic session`, `cached EnclaveInfo`, `pk_d`, `model_id`, `cert_len`, `enclave created`)
- `18` Security tests (unitary or combined: ex `1,4,6`)
- `19` DANGER: inference without explicit create
- `20` DANGER: direct read of protected memory

Enclave lifecycle:
- `21` Create enclave
- `22` Destroy enclave

## Session status details

- `Session status` now queries the device for enclave lifecycle state.
- It shows `Enclave created: YES` when the enclave currently exists on-device.
- It shows `Enclave created: NO` before creation or after destruction.
- It shows `UNKNOWN` if the UART query fails.

## Protocol architecture (host perspective)

1. `1` ECDH → dynamic session key
2. `2` EnclaveInfo attested (`nonce -> enclave_info||sig_d`) and verified with `pk_d`
3. `3` M_update authorized (`c_limit` strictly increasing)
4. `9` Verified inference returns encrypted `pred || pox_sig`
5. Mac verifies PoX signature against:
  - `model_id(4 LE) || cert || nonce_inf || pred`

## Important behavior

- `9` requires:
  - successful `1` (ECDH)
  - successful `3` (M_update accepted)
  - enclave created via `21`
- Anti-replay is enforced by device: `M_update` is rejected when `c_limit <= current max`.
- If `3` is rejected, resend with higher `c_limit`.
- Before enclave creation, the device also checks that the current Secure recomputation of `EnclaveInfo` still matches the boot-time sealed reference.
- `9`, `19`, and `20` no longer auto-create the enclave.

## Security tests (option 18)

- **T1** Fake EnclaveInfo
  - Sends M_update with modified EnclaveInfo
  - Expected: rejection

- **T2** Replay M_update
  - Sends same valid packet twice
  - Expected: first pass, second rejected

- **T3** GCM tag tamper
  - Flips one tag bit
  - Expected: rejection

- **T4** Invalid M_inf signature
  - Sends random/invalid verifier signature
  - Expected: rejection

- **T5** SAU side-effect check on rejected inference
  - Reads SAU state before/after rejected M_inf
  - Expected: no transition to OPEN + same region

- **T6** PoX negative verification
  - Gets a real PoX then verifies with a wrong message
  - Expected: wrong-message verify = False, correct-message verify = True

## Danger tests

- **19 / 0x0E** inference without explicit create
  - Validation path for forbidden access behavior
- **20 / 0x0F** direct protected-memory read
  - With SAU closed: may cause HardFault/reset/no response

## Other helper scripts

- `get_device_benchmark.py`: automated benchmark and protocol run.
- `gen_late_wt_plain.py`, `gen_late_wt_enc_header.py`, `gen_late_biases.py`: model artifact generation.