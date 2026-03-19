# Quick Start: Mac ↔ STM32 Interactive Mode

## Step 1: Firmware is already flashed ✅

You have already flashed the firmware in interactive mode.

## Step 2: Find the serial port

```bash
ls /dev/tty.usbmodem*
```

You should see something like `/dev/tty.usbmodem14203`.

## Step 3: Install Python dependencies (one-time)

```bash
pip3 install pyserial cryptography
```

## Step 4: Run the Python script on your Mac

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean

python3 tools/mac_provider.py /dev/tty.usbmodem14203 115200
```

*(Replace `/dev/tty.usbmodem14203` with your serial port.)*

## Interactive Menu

The current menu includes:

- `1` ECDH handshake
- `2` Compute EnclaveInfo (attested)
- `3` Send M_update (quota custom)
- `6` Update rate limit (secure API)
- `21` Create enclave
- `22` Destroy enclave
- `9` Verified inference
- `15` SAU state (best-effort; may be blocked by hardened policy)
- `18` Security tests (single or combined)
- `19` DANGER: inference without explicit create
- `20` DANGER: direct protected-memory read

## Recommended Test Scenario

1. **Command 1**: ECDH handshake
2. **Command 2**: Compute EnclaveInfo (attestation)
3. **Command 3**: Send M_update (`c_limit` > current max)
4. **Command 21**: Create enclave (explicit lifecycle)
5. **Command 9**: Run verified inference
6. **Command 15**: Check SAU state (if available)
7. **Command 22**: Destroy enclave
8. **Command 18**: Run security tests (example: `1,4,5`)

## Full Documentation

See [../tools/README.md](../tools/README.md) for full interactive command details.

## Return to Auto-Test Mode

1. In `src/main.cpp`, change:
   ```cpp
   #define MAC_INTERACTIVE_MODE 0  // Instead of 1
   ```

2. Rebuild and flash:
   ```bash
   west build
   west build -t flash
   ```
