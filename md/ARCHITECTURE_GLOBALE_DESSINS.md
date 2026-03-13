# Architecture globale — version propre (dessins + échanges détaillés)

## 1) Vue d’ensemble

```mermaid
flowchart LR
    H[Host Mac\nProvider / Verifier\nmac_provider.py]
    N[Device NS\nZephyr UART\nuart_protocol.cpp]
    S[Secure Partition\nTF-M\ndummy_partition.c]

    H <-->|UART 115200\nCMD/LEN/DATA| N
    N <-->|PSA IPC| S
```

---

## 2) Trame UART (Host ↔ Device)

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

## 3) Handshake de session (ECDH)

```mermaid
sequenceDiagram
    autonumber
    participant H as Host (Provider/Verifier)
    participant N as Device NS
    participant S as Secure Partition

    H->>N: 0x07 ECDH_HANDSHAKE + pk_h_ephemeral
    N->>S: ECDH + HKDF (côté device)
    S-->>N: pk_d_ephemeral + contexte session
    N-->>H: STATUS OK + pk_d_ephemeral
    H->>H: ECDH + HKDF -> session_key identique
```

---

## 4) Attestation enclave + `M_update`

```mermaid
sequenceDiagram
    autonumber
    participant H as Host (Provider/Verifier)
    participant N as Device NS
    participant S as Secure Partition

    H->>N: 0x01 COMPUTE_ENCLAVE_INFO (+nonce)
    N->>S: compute_enclave_info(pub||secret||code||model_id)
    S-->>N: enclave_info (+attestation)
    N-->>H: STATUS OK + enclave_info (+attestation)

    Note over H: Host calcule M_update
    Note over H: plaintext = c_limit||pk_v||enclave_info||cert_len||cert
    Note over H: transport = nonce||AES-GCM(ciphertext)||tag

    H->>N: 0x02 VALIDATE_M_UPDATE + nonce||ciphertext||tag
    N->>S: validate_m_update (decrypt + checks)
    S->>S: anti-replay (c_limit strictement croissant)
    S->>S: update atomique max_inferences = c_limit
    S-->>N: accept / reject
    N-->>H: STATUS OK / ERROR
```

```text
M_update (plaintext logique)
+-------------+----------+------------------+--------------+----------+
| c_limit (4) | pk_v(64) | enclave_info(32) | cert_len (4) | cert (n) |
+-------------+----------+------------------+--------------+----------+

M_update (transport)
+------------+----------------+----------+
| nonce (12) | ciphertext (n) | tag (16) |
+------------+----------------+----------+
```

---

## 5) Inférence vérifiée + PoX

```mermaid
sequenceDiagram
    autonumber
    participant H as Host (Verifier)
    participant N as Device NS
    participant S as Secure + Inference

    H->>N: 0x04 RUN_INFERENCE + M_inf
    N->>S: vérification signature/policy + traitement secure
    S->>S: inference si quota autorisé
    S->>S: signature PoX avec sk_d
    S-->>N: output_class + pox_sig
    N-->>H: STATUS OK + réponse

    H->>N: 0x0C GET_DEVICE_PUBKEY (si nécessaire)
    N-->>H: STATUS OK + pk_d
    H->>H: vérification PoX avec pk_d
```

```text
M_inf (format actif)
+------------+--------------+-----------------+
| nonce (12) | model_id (4) | signature_v (64)|
+------------+--------------+-----------------+

Réponse inférence sécurisée
+-----------------+-------------+
| output_class (1)| pox_sig (64)|
+-----------------+-------------+

Message logique signé PoX
+----------+---------+------------+---------------+
| model_id | cert(n) | nonce_inf  | output_class  |
+----------+---------+------------+---------------+
```

---

## 6) Focus interne device (NS ↔ Secure ↔ Enclave)

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
Règle d’exécution:
Host CMD -> NS handler -> PSA IPC -> Secure validation/crypto ->
si autorisé: Secure ouvre SAU, lit l'enclave, calcule, referme SAU ->
retour status/résultat vers NS -> Host
```

---

## 7) Pipeline interne `0x04` (inférence)

```mermaid
sequenceDiagram
    autonumber
    participant N as NS handler
    participant S as Secure partition
    participant E as Enclave region

    N->>N: parse M_inf (nonce, model_id, sig_v)
    N->>S: secure inference request (PSA IPC)

    S->>S: verify session + format + signature + policy
    alt message valide + quota OK
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

## 8) Pipeline interne `0x02` (`M_update`)

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

## 9) Machine d’états

```mermaid
stateDiagram-v2
    [*] --> NoSession
    NoSession --> SessionReady: 0x07 ECDH
    SessionReady --> Attested: 0x01 EnclaveInfo
    Attested --> PolicyReady: 0x02 M_update validé
    PolicyReady --> PolicyReady: 0x04 inference (count++)
    PolicyReady --> Blocked: quota atteint / requête invalide
    Blocked --> PolicyReady: nouveau 0x02 valide
```

---

## 10) Sécurité + observabilité

```mermaid
flowchart TD
    A[Tests sécurité côté host] --> B[T1 replay M_update]
    A --> C[T2 tag AES-GCM falsifié]
    A --> D[T3 enclave_info invalide]
    A --> E[T4 requête inférence invalide]
    A --> F[T5 SAU ne reste pas OPEN après rejet]
    A --> G[T6 PoX: mauvais message échoue]

    H[Observabilité runtime] --> I[0x03 max_inferences]
    H --> J[0x05 inference_count]
    H --> K[0x06 remaining]
    H --> L[0x0D SAU state]
    H --> M[0x08 / 0x09 benchmarks]
```
