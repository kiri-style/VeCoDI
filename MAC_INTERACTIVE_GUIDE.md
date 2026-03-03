# Mac ↔ STM32 Interactive Protocol

Guide pour utiliser la communication interactive entre votre Mac (Provider/Verifier) et la carte STM32L552 (Device).

---

## Architecture

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

### 1. Installer Python et dépendances

```bash
# Python 3.8+ requis
python3 --version

# Installer les dépendances
pip3 install pyserial cryptography
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

## Préparation du Firmware

### Mode Interactif (Mac ↔ STM32)

Le firmware est configuré pour le mode interactif via la macro dans `src/main.cpp`:

```cpp
#define MAC_INTERACTIVE_MODE 1  // Mode interactif activé
```

### Mode Test Auto (Tests locaux)

Pour revenir au mode test automatique (sans Mac):

```cpp
#define MAC_INTERACTIVE_MODE 0  // Tests automatiques
```

### Compiler et flasher

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean

# Build
west build -p auto

# Flash
west build -t flash
```

---

## Utilisation

### 1. Démarrer le Device (STM32)

Après flash, le device affiche:

```
========================================
=== ENCLAVE AUTHORIZATION PROTOCOL ===
========================================

╔════════════════════════════════════════════════════════╗
║          MAC INTERACTIVE MODE ENABLED                  ║
║                                                        ║
║  Device ready to receive commands from Mac Provider   ║
║                                                        ║
║  On your Mac, run:                                     ║
║    python3 tools/mac_provider.py /dev/tty.usbmodem*   ║
║                                                        ║
║  Available commands:                                   ║
║    1) Compute EnclaveInfo                              ║
║    2) Send M_update (c_limit=10)                       ║
║    3) Send M_update (c_limit=20)                       ║
║    4) Get max inferences                               ║
║    5) Run inference                                    ║
╚════════════════════════════════════════════════════════╝

[UART] Protocol initialized on uart@40004400
[UART] Ready to receive commands from Mac
[MAIN] Entering command processing loop...
```

### 2. Démarrer le Provider (Mac)

Dans un nouveau terminal sur votre Mac:

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean

python3 tools/mac_provider.py /dev/tty.usbmodem14203 115200
```

Vous verrez le menu interactif:

```
============================================================
  Mac Provider/Verifier - Enclave Authorization Protocol
============================================================

 Available Commands:
  1) Compute EnclaveInfo on device
  2) Generate and send M_update (c_limit=10)
  3) Generate and send M_update (c_limit=20)
  4) Get max inferences from device
  5) Run inference on device
  6) Read device console (2 seconds)
  7) Get inference count from device
  8) Get remaining inferences from device
  q) Quit

Enter command: 
```

---

## Scénario de Test Complet

### Étape 1: Vérifier l'état initial

```
Enter command: 4

[4] Getting max inferences from device...
[UART] ← Command received: 0x03
[CMD] Get max inferences
[CMD] ✓ Current max_inferences: 0
✓ Current max_inferences: 0
```

**Résultat**: Le device démarre avec `max_inferences = 0` (aucune inference autorisée).

---

### Étape 2: Calculer EnclaveInfo

```
Enter command: 1

[1] Computing EnclaveInfo on device...
→ Sent command 0x01 (100 bytes data)

[UART] ← Command received: 0x01
[CMD] Compute EnclaveInfo
[CMD] ✓ EnclaveInfo computed
← Received status 0x00 (32 bytes data)

✓ EnclaveInfo received: 55b3a716bf879bd9cb162de716f84eacf01300cc72d7120619344c7e998f9204
```

**Résultat**: Le Secure World calcule le hash SHA-256 de `Model_pub || Model_secret || code || model_ID`.

---

### Étape 3: Envoyer M_update (c_limit=10)

```
Enter command: 2

[2] Generating M_update with c_limit=10...
✓ Got EnclaveInfo: 55b3a716bf879bd9...

[PROVIDER] Generating M_update:
  - c_limit: 10
  - plaintext size: 120 bytes
  - enclave_info: 55b3a716bf879bd9...
  - nonce: 3fdb8b9a94e3a2324323528012345678
  - ciphertext size: 120 bytes
  - tag: 3374e4ddc57b1c6d84be32de768b1628

→ Sent command 0x02 (148 bytes data)

[UART] ← Command received: 0x02
[CMD] Validate M_update
[SECURE] DP_CMD_VALIDATE_M_UPDATE received
[CMD] ✓ M_update validated successfully
← Received status 0x00 (0 bytes data)

✓ M_update validated successfully!
  Device should now have max_inferences = 10
```

**Résultat**: Le device a validé le M_update et mis à jour `max_inferences` de 0 → 10.

---

### Étape 4: Vérifier la mise à jour

```
Enter command: 4

[4] Getting max inferences from device...
[CMD] ✓ Current max_inferences: 10
✓ Current max_inferences: 10
```

**Résultat**: Confirmation que la limite a été mise à jour!

---

### Étape 5: Exécuter des inferences

```
Enter command: 5

[5] Requesting inference on device...
[CMD] Run inference
[CMD] ✓ Inference allowed and counter incremented
✓ Inference executed successfully
```

Répétez 10 fois, puis à la 11ème tentative:

```
Enter command: 5

[5] Requesting inference on device...
[CMD] Run inference
[CMD] ✗ Inference blocked (limit reached)
✗ Inference blocked (limit reached or other error)
```

**Résultat**: Le device bloque après 10 inferences (limite atteinte).

---

### Étape 6: Mettre à jour avec nouvelle limite (c_limit=20)

```
Enter command: 3

[3] Generating M_update with c_limit=20...
[PROVIDER] Generating M_update:
  - c_limit: 20
  ...
✓ M_update validated successfully!
  Device should now have max_inferences = 20
```

**Résultat**: Le compteur max est maintenant 20 (anti-replay vérifié: 20 > 10 ✓).

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

### Commandes disponibles

| CMD  | Nom                      | Input                                | Output              |
|------|--------------------------|--------------------------------------|---------------------|
| 0x01 | COMPUTE_ENCLAVE_INFO     | model_pub + model_secret + code + ID | 32 bytes SHA-256    |
| 0x02 | VALIDATE_M_UPDATE        | nonce + ciphertext + tag (148B)      | status only         |
| 0x03 | GET_MAX_INFERENCES       | (none)                               | uint32_t            |
| 0x04 | RUN_INFERENCE            | (none)                               | status only         |

### Status codes

- `0x00` (RESP_OK): Commande exécutée avec succès
- `0xFF` (RESP_ERROR): Erreur lors de l'exécution

---

## Sécurité

### Clés cryptographiques

⚠️ **IMPORTANT**: Les clés actuelles sont hardcodées pour les tests.

Les clés doivent correspondre entre:
- **Mac**: `tools/mac_provider.py`
- **Device**: `src/provider_sim.cpp` et `dummy_partition/dummy_partition.c`

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

1. Vérifiez que les clés correspondent entre Mac et Device
2. Vérifiez que EnclaveInfo est identique des deux côtés
3. Anti-replay: assurez-vous que c_limit > dernier c_limit accepté

---

## Prochaines Étapes

### Intégration Inference Complète

Actuellement, `CMD_RUN_INFERENCE` vérifie juste le compteur. Pour l'intégration complète:

1. Modifier `handle_run_inference()` dans `uart_protocol.cpp`
2. Appeler `run_split_inference()` avec une vraie image CIFAR-10
3. Retourner le résultat de classification au Mac

### Protocole Inference (M_inf / PoX)

Intégrer le protocole d'inference avec signatures ECDSA:

1. Mac envoie M_inf (signed inference request)
2. Device valide signature + nonce
3. Device exécute inference
4. Device retourne PoX (signed proof of execution)

---

## Ressources

- **Script Python**: `tools/mac_provider.py`
- **Protocol handler**: `src/uart_protocol.cpp`
- **Main interactif**: `src/main.cpp`
- **Verification report**: `VERIFICATION_REPORT.md`

---

**Dernière mise à jour**: 27 février 2026  
**Testé sur**: macOS + STM32L552ZE-Q
