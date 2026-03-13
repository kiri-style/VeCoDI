# Quick Start: Mac ↔ STM32 (flow validé)

## 1) Build + flash

```bash
west build -d build
west flash
```

## 2) Lancer l’outil Mac

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean
./.venv/bin/python tools/mac_provider.py /dev/tty.usbmodem11203 115200
```

## 3) Séquence recommandée

1. `1` → ECDH handshake
2. `2` → Compute EnclaveInfo
3. `3` → Send M_update
   - utiliser `c_limit > current max` (anti-replay)
4. `9` → Verified inference
5. `15` → SAU state (deterministic)

## Règles importantes

- `9` ne marche que si:
  - `1` a réussi
  - `3` a été **accepté**
- Si `3` est rejeté (`RESP_ERROR`), augmenter `c_limit` et renvoyer.

## Interpréter le SAU state (option 15)

- `UNREGISTERED`: fenêtre non encore enregistrée
- `OPEN`: fenêtre enclave ouverte côté NS
- `CLOSED`: fenêtre enclavée/protégée côté NS

La réponse binaire de `CMD_GET_SAU_STATE (0x0D)` est:
- `state(1)` + `base(4)` + `size(4)`

## Commande utile pour vérif rapide

```bash
printf '1\n2\n3\n\n9\n15\nq\n' | ./.venv/bin/python tools/mac_provider.py /dev/tty.usbmodem11203 115200
```
