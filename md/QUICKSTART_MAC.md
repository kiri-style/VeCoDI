# Quick Start: Mac ↔ STM32 Interactive Mode

## Étape 1: Le firmware est déjà flashé! ✅

Vous venez de flasher le firmware en mode interactif.

## Étape 2: Trouver le port série

```bash
ls /dev/tty.usbmodem*
```

Vous devriez voir quelque chose comme `/dev/tty.usbmodem14203`

## Étape 3: Installer les dépendances Python (une seule fois)

```bash
pip3 install pyserial cryptography
```

## Étape 4: Lancer le script Python sur votre Mac

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/hello_cifar_clean

python3 tools/mac_provider.py /dev/tty.usbmodem14203 115200
```

*(Remplacez `/dev/tty.usbmodem14203` par votre port série)*

## Menu Interactif

Le menu courant inclut notamment:

- `1` ECDH handshake
- `2` Compute EnclaveInfo (attesté)
- `3` Send M_update (quota custom)
- `9` Verified inference
- `15` SAU state
- `18` Security tests (unitaires / combinables)
- `19` DANGER: inference sans SAU open
- `20` DANGER: lecture mémoire protégée

## Scénario de Test Recommandé

1. **Commande 1**: ECDH handshake
2. **Commande 2**: Compute EnclaveInfo (attestation)
3. **Commande 3**: Envoyer M_update (`c_limit` > max courant)
4. **Commande 9**: Exécuter une inference vérifiée
5. **Commande 15**: Vérifier SAU state = `CLOSED`
6. **Commande 18**: Lancer tests sécurité (ex: `1,4,5`)

## Documentation Complète

Voir [MAC_INTERACTIVE_GUIDE.md](MAC_INTERACTIVE_GUIDE.md) pour tous les détails.

## Revenir au Mode Test Auto

1. Dans `src/main.cpp`, changer:
   ```cpp
   #define MAC_INTERACTIVE_MODE 0  // Au lieu de 1
   ```

2. Recompiler et flasher:
   ```bash
   west build
   west build -t flash
   ```
