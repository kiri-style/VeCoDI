# Case Study: Secure and Verifiable CIFAR-10 Inference on STM32L552ZE-Q

## Goal
This case study documents a real deployment of the SAVID prototype on a low-end TrustZone-M MCU and can be integrated into the paper as the practical applicability section.

The objective is to show that, on real hardware, SAVID can:
1. Enforce model confidentiality through split inference and protected late weights.
2. Enforce authorized usage through secure quota management.
3. Return verifiable inference outputs with Secure-side PoX signing.
4. Keep runtime overhead practical for constrained edge devices.

## Deployment Context
- Device: NUCLEO-L552ZE-Q (ARM Cortex-M33 @ 110 MHz, TrustZone-M)
- Runtime split:
  - Non-Secure world (Zephyr): UART protocol, split inference execution
  - Secure world (TF-M partition): crypto services, policy checks, SAU control, PoX signing
- Model path:
  - Early layers in plain ROM
  - Late layers encrypted in ROM and decrypted at runtime into enclave RAM

## Protocol Path Used in This Case Study
Validated interactive flow:
1. ECDH handshake (`CMD_ECDH_HANDSHAKE`)
2. EnclaveInfo attestation (`CMD_COMPUTE_ENCLAVE_INFO`)
3. Authorization update (`CMD_VALIDATE_M_UPDATE`) with anti-replay (`c_limit` strictly increasing)
4. Explicit enclave lifecycle create (`CMD_CREATE_ENCLAVE`)
5. Verified inference (`CMD_RUN_INFERENCE`) using Secure START/COMPLETE transaction
6. Optional secure teardown (`CMD_DESTROY_ENCLAVE`)

Secure transaction behavior during inference:
- START (`DP_CMD_INF_START`): decrypt and verify `M_inf`, open enclave window, create tx state
- NS inference executes in atomic window
- COMPLETE (`DP_CMD_INF_COMPLETE`): commit counter, close enclave window, sign PoX

## Security Mechanisms Demonstrated

### 1) Model confidentiality in practice
- Late weights remain encrypted in flash.
- Decryption is performed by Secure world.
- Access to enclave memory is controlled by dynamic SAU windows.

Observed SAU lifecycle behavior:
- Create: windows open for setup, then closed at finalize
- Verified inference: windows reopen at START and close at COMPLETE
- Destroy: windows reopened for NS cleanup/zeroization path

### 2) Authorization and anti-replay
- `M_update` accepted only when `c_limit` is strictly greater than the previously accepted limit.
- Counter/quota state is managed in Secure world and committed only on successful transaction completion.

### 3) Verifiable output
- Device returns PoX signed with Secure-resident device key (`sk_d`).
- Host verification path uses `pk_d` (`CMD_GET_DEVICE_PUBKEY`) to validate PoX.

## Empirical Results (Hardware)

### A) Latency comparison used in paper-style summary
Source: `TABLE2_FINAL.md`

| Model   | NS (ms) | S (ms) | SAVID (ms) | Overhead (ms) | Overhead (%) |
|---------|---------|--------|------------|---------------|--------------|
| CIFAR-10 | 38.4    | 40.3   | 43.1       | 4.7           | 12.2%        |

Interpretation:
- SAVID adds a bounded overhead versus NS baseline while adding memory isolation and verifiability controls.
- The measured overhead remains in single-digit milliseconds for this setup.

### B) End-to-end benchmark snapshot
Source: `BENCHMARK_RESULTS.md` (11 April 2026 run)

- NS inference total: 4,739,095 cycles (43.1 ms)
- NS early layers: 2,821,449 cycles (25.6 ms)
- NS late layers: 1,275,311 cycles (11.6 ms)
- Secure AES decrypt: 7,714,544 cycles (70.1 ms)
- Combined memory usage:
  - RAM: 177,843 / 196,608 bytes (90.5%)
  - Flash: 260,172 / 396,288 bytes (65.7%)

### C) Operational robustness snapshot
Source: `md/VERIFICATION_REPORT.md` and `md/DEVICE_BENCHMARK.md`

- End-to-end path validated on hardware after regression fix.
- Verified run observed with valid PoX and matching expected class in validation flow.
- Security negative tests are documented for replay, tampered tag, invalid verifier signature, and protected-memory access checks.

## Practical Takeaways
1. Practicality on low-end MCU: The prototype runs within tight RAM/flash budgets while keeping secure control in TF-M.
2. Security-performance tradeoff: Overhead exists but remains bounded relative to baseline inference latency.
3. Deployability: The command-driven lifecycle (create, run, destroy) supports controlled operation and debugging on real hardware.
4. Evidence-driven validation: Both functional and security-path checks were exercised directly on the board.

## Known Limitations (for transparent reporting)
- Inference compute remains in Non-Secure world; Secure world supervises validation, policy, and signing.
- Current evaluation uses CIFAR-10 split model and UART host interaction, which is representative of a constrained edge pipeline but not an exhaustive domain-specific application.
- Reported numbers depend on firmware revision and run configuration; paper should cite measurement date and command flow.

## Suggested Paper Insert (ready to paste)

"We evaluate SAVID through a real deployment on an STM32L552ZE-Q (Cortex-M33, 110 MHz) running Zephyr (NS) and TF-M (Secure). The case study uses a split CIFAR-10 model in which early layers execute in NS and late layers are stored encrypted in flash and decrypted under Secure control. The full protocol flow (ECDH handshake, EnclaveInfo attestation, M_update authorization, explicit enclave create, verified inference, and optional destroy) was validated on hardware. During verified inference, Secure START decrypts and verifies `M_inf` and opens the enclave window, NS executes inference atomically, and Secure COMPLETE commits quota state and signs PoX. In our measurements, SAVID reaches 43.1 ms for CIFAR-10 inference versus 38.4 ms for NS baseline, corresponding to a 4.7 ms (12.2%) overhead, while providing memory isolation and verifiable result generation. Combined memory usage was 177,843/196,608 bytes RAM and 260,172/396,288 bytes flash in the reported run."