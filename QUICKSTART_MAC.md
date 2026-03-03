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

Vous verrez:

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
  q) Quit

Enter command: 
```

## Scénario de Test Recommandé

1. **Commande 4**: Vérifier max_inferences initial (devrait être 0)
2. **Commande 1**: Calculer EnclaveInfo
3. **Commande 2**: Envoyer M_update avec c_limit=10
4. **Commande 4**: Vérifier max_inferences (devrait être 10 maintenant!)
5. **Commande 5**: Exécuter une inference (répéter 10 fois)
6. **Commande 5**: La 11ème tentative devrait être bloquée

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
