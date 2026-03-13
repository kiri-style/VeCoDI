# Mac ↔ STM32 Interactive Protocol (Guide à jour)

Guide pratique pour piloter le device STM32L552 depuis Mac avec `tools/mac_provider.py`.

---

## Architecture (résumé)

```
┌─────────────────────────┐         USB/UART          ┌──────────────────────────┐
│   Mac (Provider)        │ ◄─────────────────────►  │  STM32L552 (Device)      │
│                         │                           │                          │
│  - Python script        │   Commands binaires       │  - Firmware TF-M         │
│  - Génère M_update      │   ─────────────────►      │  - Valide M_update       │
│  - Cryptographie AES    │   ◄─────────────────      │  - Execute inferences    │
│  - Interface menu       │      Réponses             │  - Sécurité TrustZone    │
└─────────────────────────┘                           └──────────────────────────┘
```

---

## Installation sur Mac

### 1. Préparer Python et dépendances

```bash
python3 --version

# Dépendances dans le venv projet (recommandé)
./.venv/bin/python -m pip install pyserial cryptography
```

### 2. Vérifier le port série

Connectez votre STM32L552 via USB, puis:

```bash
# Trouver le port série
ls /dev/tty.usbmodem*

# Exemple de résultat:
# /dev/tty.usbmodem14203
```

---

## Préparation firmware

### Compiler et flasher

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean

west build -d build
west flash
```

---

## Utilisation

### 1. Démarrer le Provider (Mac)

Dans un nouveau terminal sur votre Mac:

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean

./.venv/bin/python tools/mac_provider.py /dev/tty.usbmodem11203 115200
```

Le menu actuel expose:

```
1) ECDH handshake
2) Compute EnclaveInfo
3) Send M_update (quota custom)
4) Get device signing pubkey
5..8) quota/counters
9) Verified inference
10) Legacy inference
11) Last result
12/13) NS/Secure benchmark
14) Console read
15) SAU state
16) Raw command
17) Session status
18) Security tests (unitaires/combinables)
19) DANGER: inference sans SAU open
20) DANGER: lecture mémoire protégée

Enter command: 
```

---

## Scénario de test recommandé (à jour)

### Étape 1: ECDH

```
Enter command: 1
```

**Résultat**: clé de session dynamique dérivée.

---

### Étape 2: EnclaveInfo

```
Enter command: 2

[2] Computing EnclaveInfo...
→ Sent command 0x01 (32 bytes data)

[UART] ← Command received: 0x01
[CMD] Compute EnclaveInfo
[CMD] ✓ EnclaveInfo attested
← Received status 0x00 (124 bytes data)

✓ EnclaveInfo attestation verified with pk_d
✓ EnclaveInfo: 55b3a716bf879bd9cb162de716f84eacf01300cc72d7120619344c7e998f9204
```

**Résultat**: le Secure World renvoie `enclave_info(32) || sig_d(64)` attesté (nonce challenge côté Mac).

---

### Étape 3: M_update (anti-replay)

```
Enter command: 3

[PROVIDER] Generating M_update:
  - c_limit: 10
  - plaintext size: 124 bytes
  - enclave_info: 55b3a716bf879bd9...
  - nonce: 3fdb8b9a94e3a2324323528012345678
  - ciphertext size: 124 bytes
  - tag: 3374e4ddc57b1c6d84be32de768b1628

→ Sent command 0x02 (152 bytes data)

[UART] ← Command received: 0x02
[CMD] Validate M_update
[SECURE] DP_CMD_VALIDATE_M_UPDATE received
[CMD] anti-replay enforced

Si rejet (`RESP_ERROR`), renvoyer avec `c_limit` plus grand que le max courant.
```

**Résultat**: si `c_limit` est strictement supérieur au max courant, le M_update est accepté.

---

### Étape 4: Verified inference

```
Enter command: 9
```

**Résultat**: `verified inference OK` si `1` + `3` réussi.

---

### Étape 5: SAU state

```
Enter command: 15
```

Réponse:

```
✓ SAU state = UNREGISTERED/OPEN/CLOSED
  base = 0x........
  size = ....
```

**Résultat**: état mémoire protégé déterministe côté firmware.

---

## Règles essentielles

- `9` requiert une session ECDH active + un M_update accepté.
- Anti-replay strict: `c_limit` doit toujours augmenter.
- En cas de rejet M_update, relancer `3` avec valeur plus haute.

---

## Protocole de Communication

### Format des paquets

**Requête (Mac → Device)**:
```
[CMD:1 byte][LENGTH:4 bytes LE][DATA:n bytes]
```

**Réponse (Device → Mac)**:
```
[STATUS:1 byte][LENGTH:4 bytes LE][DATA:n bytes]
```

### Commandes disponibles (firmware actuel)

| CMD  | Nom                      | Input                                 | Output                  |
|------|--------------------------|---------------------------------------|-------------------------|
| 0x01 | COMPUTE_ENCLAVE_INFO     | model+secret+code+id                  | enclave_info (encrypted/plain) |
| 0x02 | VALIDATE_M_UPDATE        | nonce + ciphertext + tag              | status                  |
| 0x03 | GET_MAX_INFERENCES       | none                                  | uint32                  |
| 0x04 | RUN_INFERENCE            | `M_inf` chiffré ou vide (legacy)      | status / réponse chiffrée |
| 0x05 | GET_INFERENCE_COUNT      | none                                  | uint32                  |
| 0x06 | GET_REMAINING_INFERENCES | none                                  | uint32                  |
| 0x07 | ECDH_HANDSHAKE           | pubkey P-256 (65B)                    | pubkey device (65B)     |
| 0x08 | GET_BENCHMARK            | none                                  | NS metrics              |
| 0x09 | GET_SECURE_BENCHMARK     | none                                  | Secure metrics          |
| 0x0A | GET_INFERENCE_RESULT     | none                                  | pred + expected         |
| 0x0B | SET_MAX_INFERENCES       | uint32                                | status                  |
| 0x0C | GET_DEVICE_PUBKEY        | none                                  | pk_d (65B)              |
| 0x0D | GET_SAU_STATE            | none                                  | state(1)+base(4)+size(4)|
| 0x0E | RUN_INFERENCE_NO_SAU     | none                                  | status/pred (test danger) |
| 0x0F | READ_PROTECTED_MEM       | none                                  | no response (fault) ou 1 octet |

### Option 18 (tests unitaires / combinés)

- `18` puis `a` : lance toute la suite
- `18` puis `4` : lance uniquement T4
- `18` puis `1,4,5` : combine plusieurs tests

### Options danger

- **19**: tente une inference sans `enclave_sau_open()`
- **20**: tente une lecture directe de mémoire protégée (peut provoquer HardFault/reset)

### Status codes

- `0x00` (RESP_OK): Commande exécutée avec succès
- `0xFF` (RESP_ERROR): Erreur lors de l'exécution

---

## Sécurité

### Clés cryptographiques

⚠️ **IMPORTANT**: Les clés actuelles sont hardcodées pour les tests.

Les éléments cryptographiques doivent rester cohérents entre:
- **Mac**: `tools/mac_provider.py`
- **Device**: `src/uart_protocol.cpp` et `dummy_partition/dummy_partition.c`

Pour la production:
1. Générer des clés aléatoires sécurisées
2. Utiliser un HSM pour stocker les clés du Provider
3. Provisionner les clés device via mécanisme sécurisé

### Propriétés vérifiées

✅ **AES-256-GCM**: Chiffrement authentifié avec tag 128-bit  
✅ **EnclaveInfo**: Vérification constant-time dans Secure World  
✅ **Anti-replay**: c_limit doit être strictement croissant  
✅ **Atomic update**: max_inferences mis à jour atomiquement  
✅ **Zero-knowledge**: La clé de session reste dans Secure World

---

## Dépannage

### "Permission denied" sur /dev/tty.usbmodem*

```bash
sudo chmod 666 /dev/tty.usbmodem14203
```

### Device ne répond pas

1. Vérifiez que le firmware est en mode interactif (`MAC_INTERACTIVE_MODE = 1`)
2. Vérifiez la connexion USB
3. Essayez de débrancher/rebrancher
4. Vérifiez le port série avec `ls /dev/tty.usbmodem*`

### "Module 'serial' not found"

```bash
pip3 install pyserial
```

### Timeout lors des commandes

1. Vérifiez que le baudrate est correct (115200)
2. Augmentez le timeout dans `mac_provider.py` (ligne `timeout=5.0`)
3. Vérifiez les logs device pour les erreurs

### M_update validation échoue

1. Vérifiez que ECDH (`1`) a bien été fait dans la session courante
2. Vérifiez que `c_limit > current max`
3. Relancez `3` avec une valeur strictement supérieure

---

## Tests sécurité (option 18)

La suite intégrée dans `mac_provider.py` couvre les cas négatifs suivants:

- **T1**: Rejeu de `M_update` (anti-replay, `c_limit` identique)
- **T2**: `M_update` avec tag AES-GCM falsifié
- **T3**: `M_update` avec `EnclaveInfo` incorrect
- **T4**: Inference sans session ECDH active
- **T5**: Vérification qu'un échec ne force pas la SAU en OPEN
- **T6**: Vérification négative PoX (message altéré doit échouer)

Exemples:

- `18` puis `a` → lance T1..T6
- `18` puis `4` → lance uniquement T4
- `18` puis `1,4,6` → lance un sous-ensemble combiné

## Validation danger (options 19/20)

- **19** (`CMD_RUN_INFERENCE_NO_SAU`, `0x0E`) : tente une inference sans ouvrir SAU.
- **20** (`CMD_READ_PROTECTED_MEM`, `0x0F`) : tente une lecture directe mémoire protégée (comportement attendu: erreur, no-response, ou reset selon protection active).

Ces options sont destinées aux tests de robustesse et demandent confirmation explicite.

---

## Ressources

- **Script Python**: `tools/mac_provider.py`
- **Protocol handler**: `src/uart_protocol.cpp`
- **Main interactif**: `src/main.cpp`
- **Verification report**: `VERIFICATION_REPORT.md`

---

**Dernière mise à jour**: 13 mars 2026  
**Testé sur**: macOS + STM32L552ZE-Q
