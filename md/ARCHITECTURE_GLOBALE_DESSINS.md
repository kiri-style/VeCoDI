# Global Architecture — clean version (diagrams + detailed exchanges)

## 1) Overview

```mermaid
flowchart LR
    H[Host Mac\nProvider / Verifier\nmac_provider.py]
    N[Device NS\nZephyr UART\nuart_protocol.cpp]
    S[Secure Partition\nTF-M\ndummy_partition.c]

    H <-->|UART 115200\nCMD/LEN/DATA| N
    N <-->|PSA IPC| S
```

---

## 2) UART frame (Host ↔ Device)

```text
Host -> Device
+---------+-------------------+-----------+
| CMD (1) | LEN (4, little)   | DATA (n)  |
+---------+-------------------+-----------+

Device -> Host
+------------+-------------------+-----------+
| STATUS (1) | LEN (4, little)   | DATA (n)  |
+------------+-------------------+-----------+

STATUS:
0x00 = OK
0xFF = ERROR
```

---

## 3) Session handshake (ECDH)

```mermaid
sequenceDiagram
    autonumber
    participant H as Host (Provider/Verifier)
    participant N as Device NS
    participant S as Secure Partition

    H->>N: 0x07 ECDH_HANDSHAKE + pk_h_ephemeral
    N->>S: ECDH + HKDF (device side)
    S-->>N: pk_d_ephemeral + session context
    N-->>H: STATUS OK + pk_d_ephemeral
    H->>H: ECDH + HKDF -> identical session_key
```

---

## 4) Enclave attestation + `M_update`

```mermaid
sequenceDiagram
    autonumber
    participant H as Host (Provider/Verifier)
    participant N as Device NS
    participant S as Secure Partition

    H->>N: 0x01 COMPUTE_ENCLAVE_INFO (+nonce)
    N->>S: compute_enclave_info(pub||secret||code||model_id)
    Note over S: computed from stored metadata\nno runtime enclave creation required
    S-->>N: enclave_info (+attestation)
    N-->>H: STATUS OK + enclave_info (+attestation)

    Note over H: Host computes M_update
    Note over H: plaintext = c_limit||pk_v||enclave_info||cert_len||cert
    Note over H: transport = nonce||AES-GCM(ciphertext)||tag

    H->>N: 0x02 VALIDATE_M_UPDATE + nonce||ciphertext||tag
    N->>S: validate_m_update (decrypt + checks)
    S->>S: anti-replay (c_limit strictly increasing)
    S->>S: atomic update max_inferences = c_limit
    S-->>N: accept / reject
    N-->>H: STATUS OK / ERROR
```

### Exact `EnclaveInfo` contents

```text
EnclaveInfo (32 bytes) = SHA-256(
    model_pub    (32 bytes) ||
    model_secret (32 bytes) ||
    code_hash    (32 bytes) ||
    model_id     (4 bytes, little-endian)
)
```

```text
Concatenated binary input for the hash:
+----------------------+--------+
| model_pub            | 32 B   |
| model_secret         | 32 B   |
| code_hash            | 32 B   |
| model_id (little)    | 4 B    |
+----------------------+--------+
Total hash input: 100 B
SHA-256 output: 32 B (enclave_info)
```

```text
Important:
- EnclaveInfo is computed even if the runtime enclave has not been created yet.
- The computation uses protected metadata already stored on the device.
- Opening the SAU window for inference execution is not required at this stage.
```

```text
M_update (logical plaintext)
+-------------+----------+------------------+--------------+----------+
| c_limit (4) | pk_v(64) | enclave_info(32) | cert_len (4) | cert (n) |
+-------------+----------+------------------+--------------+----------+

M_update (transport)
+------------+----------------+----------+
| nonce (12) | ciphertext (n) | tag (16) |
+------------+----------------+----------+
```

---

## 5) Verified inference + PoX

```mermaid
sequenceDiagram
    autonumber
    participant H as Host (Verifier)
    participant N as Device NS
    participant S as Secure + Inference

    H->>N: 0x04 RUN_INFERENCE + M_inf
    N->>S: signature/policy verification + secure processing
    S->>S: run inference if quota allows
    S->>S: PoX signature with sk_d
    S-->>N: output_class + pox_sig
    N-->>H: STATUS OK + response

    H->>N: 0x0C GET_DEVICE_PUBKEY (if needed)
    N-->>H: STATUS OK + pk_d
    H->>H: verify PoX with pk_d
```

```text
M_inf (active format)
+------------+--------------+-----------------+
| nonce (12) | model_id (4) | signature_v (64)|
+------------+--------------+-----------------+

Secure inference response
+-----------------+-------------+
| output_class (1)| pox_sig (64)|
+-----------------+-------------+

Logical PoX-signed message
+----------+---------+------------+---------------+
| model_id | cert(n) | nonce_inf  | output_class  |
+----------+---------+------------+---------------+
```

---

## 6) Internal device focus (NS ↔ Secure ↔ Enclave)

```mermaid
flowchart LR
    subgraph DEV[STM32 Device]
        direction LR

        subgraph NS[NS World]
            direction TB
            NSH[UART handler\nparse + routing]
            ENC[Enclave region\nlate weights / secrets]
        end

        S[Secure World\nTF-M\ncrypto + policy]

        NSH <-->|PSA IPC| S
        S -->|SAU open| ENC
        ENC -->|read protected data| S
        S -->|SAU close| ENC
        S -->|status + outputs| NSH
    end
```

```text
Execution rule:
Host CMD -> NS handler -> PSA IPC -> Secure validation/crypto ->
if authorized: Secure opens SAU, reads enclave data, computes, closes SAU ->
status/result returned to NS -> Host
```

---

## 7) Internal `0x04` pipeline (inference)

```mermaid
sequenceDiagram
    autonumber
    participant N as NS handler
    participant S as Secure partition
    participant E as Enclave region

    N->>N: parse M_inf (nonce, model_id, sig_v)
    N->>S: secure inference request (PSA IPC)

    S->>S: verify session + format + signature + policy
    alt valid message + quota OK
        S->>S: open SAU
        S->>E: read protected data
        E-->>S: protected blocks
        S->>S: decrypt + secure compute + counter update
        S->>S: PoX sign (sk_d)
        S->>S: close SAU
        S-->>N: output_class + pox_sig
        N-->>N: build UART response
    else rejection
        S->>S: ensure SAU closed
        S-->>N: error status
    end
```

---

## 8) Internal `0x02` pipeline (`M_update`)

```mermaid
sequenceDiagram
    autonumber
    participant N as NS handler
    participant S as Secure partition

    N->>N: parse nonce||ciphertext||tag
    N->>S: validate_m_update (PSA IPC)
    S->>S: AES-GCM decrypt + tag verify
    S->>S: parse c_limit, pk_v, enclave_info, cert
    S->>S: recompute enclave_info
    S->>S: anti-replay check (strictly increasing)
    alt valid
        S->>S: atomic update max_inferences = c_limit
        S-->>N: OK
    else invalid
        S-->>N: ERROR
    end
```

---

## 9) State machine

```mermaid
stateDiagram-v2
    [*] --> NoSession
    NoSession --> SessionReady: 0x07 ECDH
    SessionReady --> MetadataAttested: 0x01 EnclaveInfo
    MetadataAttested: measurement complete\nruntime enclave not yet created
    MetadataAttested --> PolicyReady: 0x02 M_update validated
    PolicyReady --> PolicyReady: 0x04 inference (count++)
    PolicyReady --> Blocked: quota exhausted / invalid request
    Blocked --> PolicyReady: new valid 0x02
```

---

## 10) Security + observability

```mermaid
flowchart TD
    A[Host-side security tests] --> B[T1 replay M_update]
    A --> C[T2 forged AES-GCM tag]
    A --> D[T3 invalid enclave_info]
    A --> E[T4 invalid inference request]
    A --> F[T5 SAU does not remain OPEN after rejection]
    A --> G[T6 PoX: wrong message fails]

    H[Runtime observability] --> I[0x03 max_inferences]
    H --> J[0x05 inference_count]
    H --> K[0x06 remaining]
    H --> L[0x0D SAU state]
    H --> M[0x08 / 0x09 benchmarks]
```
