# Mac ↔ STM32 Interactive Protocol (Updated Guide)

Practical guide to control the STM32L552 device from macOS using `tools/mac_provider.py`.

---

## Architecture (summary)

```
┌─────────────────────────┐         USB/UART          ┌──────────────────────────┐
│   Mac (Provider)        │ ◄─────────────────────►  │  STM32L552 (Device)      │
│                         │                           │                          │
│  - Python script        │   Binary commands         │  - TF-M firmware         │
│  - Builds M_update      │   ─────────────────►      │  - Validates M_update    │
│  - AES/ECDH crypto      │   ◄─────────────────      │  - Runs inference        │
│  - Interactive menu     │      Responses            │  - TrustZone security    │
└─────────────────────────┘                           └──────────────────────────┘
```

---

## macOS setup

### 1) Prepare Python dependencies

```bash
python3 --version
./.venv/bin/python -m pip install pyserial cryptography
```

### 2) Detect the serial port

```bash
ls /dev/tty.usbmodem*
```

Example:

```bash
/dev/tty.usbmodem14203
```

---

## Firmware preparation

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean
west build -d build
west flash
```

---

## Run the interactive provider

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean
./.venv/bin/python tools/mac_provider.py /dev/tty.usbmodem11203 115200
```

Replace `/dev/tty.usbmodem11203` with your actual port.

---

## Current menu (high level)

- `1`) ECDH handshake
- `2`) Compute EnclaveInfo (attested)
- `3`) Send M_update (custom quota)
- `4`) Get device signing public key
- `5..8`) Quota/counters
- `9`) Verified inference
- `10`) Legacy inference
- `11`) Last result
- `12/13`) NS/Secure benchmark
- `14`) Console read
- `15`) SAU state
 - `16`) Raw command
 - `17`) Session status
 - `18`) Security tests (single or combined)
 - `19`) DANGER: inference without SAU open
 - `20`) DANGER: direct protected-memory read

---

## Recommended validation flow

### Step 1: ECDH

Enter command `1`.

Expected: dynamic session key established.

### Step 2: EnclaveInfo

Enter command `2`.

Expected: Secure world returns attested `enclave_info(32) || sig_d(64)`, verified on host side.

### Step 3: M_update (anti-replay)

Enter command `3`.

Expected:
- M_update accepted when `c_limit` is strictly greater than current max.
- Rejected otherwise (anti-replay behavior).

### Step 4: Verified inference

Enter command `9`.

Expected: verified inference succeeds when steps 1 and 3 succeeded.

### Step 5: SAU state

Enter command `15`.

Expected: deterministic memory protection status.

---

## Protocol format

### Request (Mac → Device)

```text
[CMD:1 byte][LENGTH:4 bytes LE][DATA:n bytes]
```

### Response (Device → Mac)

```text
[STATUS:1 byte][LENGTH:4 bytes LE][DATA:n bytes]
```

---

## Command reference (current firmware)

| CMD  | Name                     | Input                                   | Output |
|------|--------------------------|-----------------------------------------|--------|
| 0x01 | COMPUTE_ENCLAVE_INFO     | nonce(32) or empty payload              | encrypted/attested response |
| 0x02 | VALIDATE_M_UPDATE        | nonce + ciphertext + tag                | status |
| 0x03 | GET_MAX_INFERENCES       | none                                    | uint32 |
| 0x04 | RUN_INFERENCE            | encrypted `M_inf` or empty (legacy)     | status / encrypted response |
| 0x05 | GET_INFERENCE_COUNT      | none                                    | uint32 |
| 0x06 | GET_REMAINING_INFERENCES | none                                    | uint32 |
| 0x07 | ECDH_HANDSHAKE           | P-256 public key (65B)                  | device public key (65B) |
| 0x08 | GET_BENCHMARK            | none                                    | NS metrics |
| 0x09 | GET_SECURE_BENCHMARK     | none                                    | Secure metrics |
| 0x0A | GET_INFERENCE_RESULT     | none                                    | prediction + expected |
| 0x0B | SET_MAX_INFERENCES       | uint32                                  | status |
| 0x0C | GET_DEVICE_PUBKEY        | none                                    | `pk_d` (65B) |
| 0x0D | GET_SAU_STATE            | none                                    | state(1)+base(4)+size(4) |
| 0x0E | RUN_INFERENCE_NO_SAU     | none                                    | test status/prediction |
| 0x0F | READ_PROTECTED_MEM       | none                                    | no response or error/fault path |

---

## Security notes

⚠️ Current keys are hardcoded for testing.

Consistency must be preserved across:
- Host side: `tools/mac_provider.py`
- Device side: `src/uart_protocol.cpp` and `dummy_partition/dummy_partition.c`

For production:
1. Generate secure random keys
2. Store provider keys in an HSM
3. Provision device keys through a secure mechanism

---

## Troubleshooting

### Permission denied on `/dev/tty.usbmodem*`

```bash
sudo chmod 666 /dev/tty.usbmodem14203
```

### Device not responding

1. Confirm firmware is in interactive mode (`MAC_INTERACTIVE_MODE = 1`)
2. Check USB connection
3. Replug the device
4. Re-check the serial device with `ls /dev/tty.usbmodem*`

### Module `serial` not found

```bash
./.venv/bin/python -m pip install pyserial
```

### Command timeout

1. Verify baudrate is 115200
2. Increase timeout in `mac_provider.py` if needed
3. Inspect device logs for protocol errors

### M_update validation fails

1. Ensure ECDH (command `1`) was completed in the same session
2. Ensure `c_limit > current max`
3. Retry command `3` with a larger `c_limit`

---

## Security test suite (menu option 18)

Included negative tests:
- T1: `M_update` replay (same `c_limit`)
- T2: `M_update` with tampered AES-GCM tag
- T3: `M_update` with invalid `EnclaveInfo`
- T4: Inference without active ECDH session
- T5: Verify failure does not force SAU to OPEN
- T6: Negative PoX verification (tampered message must fail)

Examples:
- `18` then `a` → run T1..T6
- `18` then `4` → run only T4
- `18` then `1,4,6` → run a selected subset

---

## Danger options (19/20)

- `19` (`CMD_RUN_INFERENCE_NO_SAU`, `0x0E`): attempt inference without opening SAU
- `20` (`CMD_READ_PROTECTED_MEM`, `0x0F`): direct protected-memory read attempt

These are robustness tests and require explicit confirmation.

---

## Resources

- Python script: `tools/mac_provider.py`
- Protocol handler: `src/uart_protocol.cpp`
- Interactive main flow: `src/main.cpp`
- Verification report: `md/VERIFICATION_REPORT.md`

---

Last updated: 13 March 2026  
Tested on: macOS + STM32L552ZE-Q
