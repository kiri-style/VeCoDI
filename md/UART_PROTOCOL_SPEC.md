# UART Protocol Specification - Mac ↔ STM32 Communication

## Overview

Binary protocol for bidirectional communication between Mac (Provider/Verifier) and STM32L552 (Device) over USB/UART. Implements authorization (`EnclaveInfo` + `M_update`), secure inference request validation (`M_inf`) and PoX return path.

**Status**: ✅ **Implemented and validated on hardware** (March 2026)

---

## Protocol Architecture

```
┌──────────────────────────┐         USB/UART (115200)        ┌─────────────────────────┐
│   Mac (Provider)         │ ◄──────────────────────────────► │  STM32L552 (Device)     │
│                          │                                   │                         │
│  tools/mac_provider.py   │   Binary Protocol                │  src/uart_protocol.cpp  │
│  - AES-256-GCM encrypt   │   ──────────────────────►        │  - PSA Crypto decrypt   │
│  - Generate M_update     │   ◄──────────────────────        │  - Quota management     │
│  - Monitor quota         │      Response packets            │  - TFM integration      │
└──────────────────────────┘                                   └─────────────────────────┘
```

---

## Packet Format

### Request (Mac → Device)
```
┌─────────┬─────────┬─────────┬─────────┬─────────┬──────────┐
│  CMD    │  LEN[0] │  LEN[1] │  LEN[2] │  LEN[3] │  DATA    │
│ (1 byte)│ (1 byte)│ (1 byte)│ (1 byte)│ (1 byte)│ (n bytes)│
└─────────┴─────────┴─────────┴─────────┴─────────┴──────────┘
```
- **CMD**: Command ID (see Commands section)
- **LEN**: Data length (4 bytes, little-endian, uint32_t)
- **DATA**: Command-specific payload (optional)

### Response (Device → Mac)
```
┌─────────┬─────────┬─────────┬─────────┬─────────┬──────────┐
│ STATUS  │  LEN[0] │  LEN[1] │  LEN[2] │  LEN[3] │  DATA    │
│ (1 byte)│ (1 byte)│ (1 byte)│ (1 byte)│ (1 byte)│ (n bytes)│
└─────────┴─────────┴─────────┴─────────┴─────────┴──────────┘
```
- **STATUS**: `0x00` (OK) or `0xFF` (ERROR)
- **LEN**: Data length (4 bytes, little-endian, uint32_t)
- **DATA**: Response payload (optional)

---

## Commands

### 0x01: CMD_COMPUTE_ENCLAVE_INFO
Compute enclave information digest (hash of model + code).

**Request**:
- Data: 100 bytes (model_pub[64] || model_secret[32] || code_hash[32] || model_id[4])
- Alternative: 0 bytes (uses default placeholder values)

**Response**:
- Status: `0x00`
- Data:
  - 32 bytes (`EnclaveInfo`) in basic mode, or
  - 124 bytes (`EnclaveInfo[32] || sig_d[64] || nonce[28]`) when attested response is enabled

**Purpose**: First step of authorization protocol. Device computes deterministic digest used in M_update encryption.

---

### 0x02: CMD_VALIDATE_M_UPDATE
Validate encrypted M_update packet and apply inference quota.

**Request**:
- Data: nonce(12) || ciphertext(n) || tag(16)
- Minimum: 28 bytes (12 + 0 + 16)
- Maximum: 256 bytes

**M_update Plaintext Structure**:
```c
struct M_update_plaintext {
    uint32_t c_limit;         // Inference quota (4 bytes)
    uint8_t pk_v[64];         // Verifier public key
    uint8_t enclave_info[32]; // Enclave digest
    uint32_t cert_len;        // Certificate length
    uint8_t cert[n];          // Certificate data
};
```

**Response**:
- Status: `0x00` (validated, quota updated) or `0xFF` (failed)
- Data: None

**Validation Steps**:
1. AES-256-GCM decrypt using session key
2. Extract `c_limit` from first 4 bytes of plaintext
3. **Anti-replay check**: Reject if `c_limit <= current_max`
4. Update `max_inferences = c_limit`, reset `inference_count = 0`

**Security Features**:
- **Anti-replay**: Strictly increasing c_limit enforcement
- **Authenticated encryption**: AES-GCM with 128-bit tag
- **PSA Crypto**: Hardware-accelerated decryption in Secure World

---

### 0x03: CMD_GET_MAX_INFERENCES
Retrieve total authorized inference quota.

**Request**:
- Data: None (0 bytes)

**Response**:
- Status: `0x00`
- Data: 4 bytes (uint32_t, little-endian) - current max_inferences

**Example**:
```
Request:  [03 00 00 00 00]
Response: [00 04 00 00 00  14 00 00 00]  // max_inferences = 20
```

---

### 0x04: CMD_RUN_INFERENCE
Execute one gated inference (consumes quota).

**Request**:
- Data can be:
  - 0 bytes (legacy path), or
  - encrypted `M_inf` payload (nonce+model_id+signature verifier)

**Response**:
- Status: `0x00` (success) or `0xFF` (rejected)
- Data:
  - legacy: empty payload
  - secure path: encrypted payload containing output class and PoX signature

**Gating Logic**:
1. Check `max_inferences != 0` (M_update applied)
2. Check `inference_count < max_inferences` (quota available)
3. If secure mode: decrypt/verify `M_inf` before executing inference
4. Increment `inference_count` only on success

**Blocking Conditions**:
- No M_update applied yet (`max_inferences == 0`)
- Quota exhausted (`inference_count >= max_inferences`)
- Invalid encrypted payload, invalid signature, or decrypt/auth failure

---

### 0x05: CMD_GET_INFERENCE_COUNT
Retrieve number of inferences already executed.

**Request**:
- Data: None (0 bytes)

**Response**:
- Status: `0x00`
- Data: 4 bytes (uint32_t, little-endian) - current inference_count

**Example**:
```
Request:  [05 00 00 00 00]
Response: [00 04 00 00 00  03 00 00 00]  // inference_count = 3
```

---

### 0x06: CMD_GET_REMAINING_INFERENCES
Calculate and retrieve remaining inference quota.

**Request**:
- Data: None (0 bytes)

**Response**:
- Status: `0x00`
- Data: 4 bytes (uint32_t, little-endian) - remaining inferences

**Calculation**:
```c
remaining = (max_inferences > inference_count) 
            ? (max_inferences - inference_count) 
            : 0;
```

**Example**:
```
Request:  [06 00 00 00 00]
Response: [00 04 00 00 00  11 00 00 00]  // remaining = 17 (20 - 3)
```

---

### Additional Security/Diagnostics Commands

| CMD  | Name                        | Description |
|------|-----------------------------|-------------|
| 0x07 | removed                     | Static AES-GCM session key is used instead |
| 0x08 | `CMD_GET_BENCHMARK`         | Read NS benchmark metrics |
| 0x09 | `CMD_GET_SECURE_BENCHMARK`  | Read Secure benchmark metrics |
| 0x0A | `CMD_GET_INFERENCE_RESULT`  | Read last prediction/expected pair |
| 0x0B | `CMD_SET_MAX_INFERENCES`    | Override max quota for tests |
| 0x0C | `CMD_GET_DEVICE_PUBKEY`     | Export `pk_d` for host PoX verification |
| 0x0D | `CMD_GET_SAU_STATE`         | SAU state (`state/base/size`), best-effort on hardened policy |
| 0x0E | `CMD_RUN_INFERENCE_NO_SAU`  | Danger test: inference without explicit create |
| 0x0F | `CMD_READ_PROTECTED_MEM`    | Danger test: direct protected-memory read |
| 0x11 | `CMD_CREATE_ENCLAVE`        | Explicit enclave create lifecycle command |
| 0x12 | `CMD_DESTROY_ENCLAVE`       | Explicit enclave destroy lifecycle command |
| 0x13 | `CMD_UPDATE_RATE_LIMIT`     | Update quota via secure API (`uint32 LE`) |

### Lifecycle note

`CMD_RUN_INFERENCE` no longer auto-creates an enclave. The expected flow is:
1. `CMD_CREATE_ENCLAVE` (`0x11`)
2. `CMD_RUN_INFERENCE` (`0x04`)
3. `CMD_DESTROY_ENCLAVE` (`0x12`) when done

---

## Complete Quota Management

The protocol implements a **3-metric quota system**:

| Command | Metric | Description |
|---------|--------|-------------|
| 0x03 | **max_inferences** | Total authorized quota (set by M_update) |
| 0x05 | **inference_count** | Number of inferences consumed |
| 0x06 | **remaining** | Available quota (max - count) |

**State Transitions**:
```
Initial State:
  max_inferences = 0
  inference_count = 0
  remaining = 0

After M_update (c_limit=20):
  max_inferences = 20
  inference_count = 0
  remaining = 20

After 3 inferences:
  max_inferences = 20
  inference_count = 3
  remaining = 17

After quota exhausted:
  max_inferences = 20
  inference_count = 20
  remaining = 0
  → CMD_RUN_INFERENCE returns 0xFF
```

---

## Security Features

### 1. AES-256-GCM Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key**: 256-bit static AES-GCM session key shared by NS and Secure
- **Nonce**: 12 bytes (96 bits), randomly generated per M_update
- **Tag**: 16 bytes (128 bits), authenticated encryption tag
- **Implementation**: PSA Crypto API (hardware-accelerated on STM32L552)

### 2. Anti-Replay Protection
- **Mechanism**: Strictly increasing c_limit enforcement
- **Check**: `new_c_limit > current_max_inferences`
- **Prevention**: Cannot downgrade quota (e.g., 20 → 10 rejected)
- **Location**: `handle_validate_m_update()` in `uart_protocol.cpp`

### 3. Inference Gating
- **Requirement**: Valid M_update must be applied before any inference
- **Initial State**: `max_inferences = 0` → all inferences blocked
- **Gate Check**: request is denied unless policy and lifecycle preconditions are met
- **Prevents**: Unauthorized inference execution

### 4. Session and PoX Verification
- Session establishment uses a fixed session key shared by NS and Secure.
- Host retrieves `pk_d` (`0x0C`) then verifies PoX signatures returned by secure inference path (`0x04`).
- Negative PoX validation is exercised in host security test T6.

---

## Implementation Details

### Device Side (STM32L552)

**Files**:
- `src/uart_protocol.h`: Protocol definitions, command IDs
- `src/uart_protocol.cpp`: Command handlers, state machine (407 lines)
- `src/main.cpp`: Integration with MAC_INTERACTIVE_MODE

**UART Configuration**:
- **Device**: lpuart1 (ST-LINK VCP)
- **Baud Rate**: 115200
- **Data**: 8 bits, No parity, 1 stop bit (8N1)
- **Flow Control**: None
- **Polling**: k_yield() tight loop for low latency

**State Variables**:
```c
static uint8_t mock_enclave_info[32];    // Computed EnclaveInfo
static uint32_t mock_max_inferences;     // Total quota
static uint32_t mock_inference_count;    // Consumed quota
```

### Mac Side (Python)

**File**: `tools/mac_provider.py` (385 lines)

**Dependencies**:
- `pyserial`: UART communication
- `cryptography`: AES-GCM encryption

**Key Functions**:
```python
def send_command(cmd_id, data):
    """Send binary command packet"""
    
def read_response():
    """Receive and parse response packet"""
    
def generate_m_update(c_limit, enclave_info):
    """Generate AES-GCM encrypted M_update"""
```

**Usage Examples**:
```bash
# Interactive mode
python3 tools/mac_provider.py /dev/tty.usbmodem* 115200

# Automated test: authorize + 3 inferences + check quota
printf '3\n5\n5\n5\n4\n7\n8\nq\n' | python3 tools/mac_provider.py /dev/tty.usbmodem* 115200
```

---

## Test Scenarios

### Scenario 1: Inference Gating (Initial State)
```
Sequence: 5 (inference) → expect 0xFF

Result:
✗ Inference blocked (no M_update applied yet)
max_inferences = 0
```

### Scenario 2: Authorization + Execution
```
Sequence: 3 (M_update c_limit=20) → 5,5,5 (3 inferences) → 4,7,8 (check quotas)

Result:
✓ M_update validated (max=20)
✓ 3 inferences executed
✓ max_inferences = 20
✓ inference_count = 3
✓ remaining = 17
```

### Scenario 3: Anti-Replay Protection
```
Sequence: 3 (c_limit=20) → 2 (c_limit=10) → 4 (check max)

Result:
✓ First M_update applied (max=20)
✗ Second M_update rejected (10 ≤ 20, anti-replay)
✓ max_inferences = 20 (unchanged)
```

### Scenario 4: Quota Exhaustion
```
Sequence: 2 (c_limit=2) → 5,5 (2 inferences) → 5 (3rd inference) → 8 (check remaining)

Result:
✓ M_update applied (max=2)
✓ First 2 inferences succeed
✗ Third inference blocked (quota exhausted)
✓ remaining = 0
```

---

## Performance Metrics

### Latency (measured on STM32L552 @ 110 MHz)

| Operation | Time | Notes |
|-----------|------|-------|
| **UART RX** | <1 ms | Per byte at 115200 baud |
| **CMD_COMPUTE_ENCLAVE_INFO** | ~5 ms | XOR-based placeholder |
| **CMD_VALIDATE_M_UPDATE** | ~70 ms | PSA AEAD decrypt |
| **CMD_GET_MAX_INFERENCES** | <1 ms | Read variable |
| **CMD_RUN_INFERENCE** | variable | Includes gating, optional decrypt/verify M_inf, inference, PoX generation |
| **CMD_GET_INFERENCE_COUNT** | <1 ms | Read variable |
| **CMD_GET_REMAINING_INFERENCES** | <1 ms | Subtraction |

### Memory Footprint

**Device (STM32)**:
- **FLASH**: +32 bytes (command handlers)
- **RAM**: +72 bytes (mock_enclave_info[32] + quotas[8] + rx_buffer[256])

**Mac (Python)**:
- **Script**: 385 lines (~15 KB)
- **Dependencies**: pyserial + cryptography

---

## Error Handling

### UART Communication Errors
- **Timeout**: 1 second for RX_DATA state
- **Invalid Command**: Silently ignore (optional LED blink diagnostic)
- **Length Mismatch**: Reject if len > MAX_COMMAND_DATA_SIZE (256)

### Protocol Errors
- **Invalid M_update**: Return `0xFF` status
  - Decryption failure
  - Anti-replay check failed
  - Invalid plaintext format
- **Inference Blocked**: Return `0xFF` status
  - No M_update applied
  - Quota exhausted

### Mac-side Error Handling
```python
resp = device.read_response()
if not resp or resp[0] != RESP_OK:
    print("✗ Command failed")
else:
    print("✓ Command succeeded")
```

---

## Current Coverage

- [x] Quota management (max/count/remaining)
- [x] Anti-replay protection on `M_update`
- [x] Static session-key bootstrap
- [x] Secure inference path (`M_inf` verification + PoX response)
- [x] Host-side PoX positive/negative checks
- [x] SAU deterministic state command and danger diagnostics (`0x0E`, `0x0F`)

---

## References

### Implementation Files
- Device: `src/uart_protocol.h`, `src/uart_protocol.cpp`
- Mac: `tools/mac_provider.py`
- Documentation: `QUICKSTART_MAC.md`, `tools/README.md`

### Related Protocols
- Enclave Authorization Protocol: `ENCLAVE_AUTH_IMPL.md`
- Inference Protocol (M_inf/PoX): `INFERENCE_PROTOCOL_IMPL.md`
- Detailed exchange architecture (graphs + sequence diagrams): `PROTOCOL_DETAILED_ARCHITECTURE.md`

### Hardware
- Board: NUCLEO-L552ZE-Q (STM32L552 Cortex-M33 @ 110 MHz)
- TrustZone: ARM TrustZone-M with TF-M 2.1.0
- UART: lpuart1 via ST-LINK VCP

---

**Last Updated**: March 3, 2026  
**Status**: ✅ Fully Implemented and Tested
