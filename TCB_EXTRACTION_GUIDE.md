# TCB Extraction Tool - Guide d'Utilisation

## Vue d'Ensemble
Le programme `tcb_size_extractor.py` analyse automatiquement le code source de la partition Secure pour extraire et calculer la taille du **Trust Computation Base (TCB)** - l'ensemble des variables statiques sensibles à la sécurité.

---

## Comment Exécuter le Programme

### Prérequis
- Python 3.6+
- Zephyr SDK avec le projet VeCoDI

### Exécution Simple
```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/VeCoDI
python3 tools/tcb_size_extractor.py
```

### Résultat
Le programme génère deux fichiers dans le répertoire `build/`:

1. **`TCB_EXTRACTION_REPORT.txt`** - Rapport détaillé en texte
2. **`TCB_EXTRACTION_DATA.json`** - Données structurées (JSON)

### Sortie Console
```
[*] Scanning secure_benchmark.c...
[*] Scanning secure_nsc_interface.c...
[*] Scanning create_enclave.c...
[*] Scanning dummy_partition.c...
  ✓ [Variables trouvées...]

TCB BREAKDOWN BY CATEGORY
[Détails par catégorie...]

SUMMARY & TOTALS
====================================================================================================
TOTAL SECURE PARTITION TCB : 511 bytes (0.50 KB)
```

---

## Détails des 511 Bytes

Le TCB est organisé en **8 catégories de sécurité** couvrant 37 variables statiques:

### 📊 Répartition Globale

| Catégorie | Taille | % | Rôle |
|-----------|--------|---|-----|
| M_update Authorization | **201 bytes** | 39.3% | Autorisation des mises à jour de modèles |
| Device Keys & Transactions | **111 bytes** | 21.7% | Clés cryptographiques et identifiants TX |
| Model Identity & Crypto | **102 bytes** | 20.0% | Identité et crypto du modèle |
| SAU Memory Protection | **46 bytes** | 9.0% | Configuration des fenêtres d'accès mémoire |
| ECDH Session & Keys | **33 bytes** | 6.5% | Session d'échange de clés |
| Counters & State | **8 bytes** | 1.6% | Compteurs d'inférences |
| Enclave Lifecycle | **8 bytes** | 1.6% | État du cycle de vie |
| EnclaveInfo & Attestation | **2 bytes** | 0.4% | Flags d'attestation |
| **TOTAL** | **511 bytes** | 100% | |

---

## Détail Complet des Variables (37 total)

### 1️⃣ M_UPDATE AUTHORIZATION (201 bytes)
Protège le processus d'autorisation des mises à jour de modèles:

```
s_cert                          : 128 bytes  (63.7%)  - Certificat M_update du modèle
s_pk_v                          :  64 bytes  (31.8%)  - Clé publique du modèle (vérification)
s_cert_len                      :   4 bytes  ( 2.0%)  - Taille du certificat
s_model_id                      :   4 bytes  ( 2.0%)  - ID unique du modèle
s_auth_valid                    :   1 bytes  ( 0.5%)  - Flag: autorisation valide?
────────────────────────────────────────────────────
SOUS-TOTAL                      : 201 bytes
```

**Rôle**: Vérifie que toute mise à jour de modèle est signée par l'autorité de certification.

---

### 2️⃣ DEVICE KEYS & TRANSACTIONS (111 bytes)
Gère les clés cryptographiques du device et les transactions sécurisées:

```
s_device_pubkey                 :  65 bytes  (58.6%)  - Clé publique du device (ECC)
s_tx_nonce                      :  32 bytes  (28.8%)  - Nonce de transaction (anti-replay)
s_device_sign_key_id            :   4 bytes  ( 3.6%)  - ID de la clé de signature
s_tx_id                         :   4 bytes  ( 3.6%)  - ID unique de la transaction
s_tx_model_id                   :   4 bytes  ( 3.6%)  - ID du modèle en cours de TX
s_device_key_ready              :   1 bytes  ( 0.9%)  - Flag: device prêt?
s_tx_active                     :   1 bytes  ( 0.9%)  - Flag: transaction active?
────────────────────────────────────────────────────
SOUS-TOTAL                      : 111 bytes
```

**Rôle**: Authentifie le device, empêche les replays, gère les transactions de modèles.

---

### 3️⃣ MODEL IDENTITY & CRYPTO (102 bytes)
Identité et matériel cryptographique du modèle actuel:

```
current_model_pub               :  32 bytes  (31.4%)  - Public key du modèle (ECDH)
current_model_secret            :  32 bytes  (31.4%)  - Secret du modèle (ECDH)
current_code_hash               :  32 bytes  (31.4%)  - Hash SHA-256 du code du modèle
current_model_id                :   4 bytes  ( 3.9%)  - ID du modèle
current_model_info_valid        :   1 bytes  ( 1.0%)  - Flag: info valide?
current_model_secret_valid      :   1 bytes  ( 1.0%)  - Flag: secret valide?
────────────────────────────────────────────────────
SOUS-TOTAL                      : 102 bytes
```

**Rôle**: Vérifie l'intégrité du modèle, maintient la chaîne d'authentification.

---

### 4️⃣ SAU MEMORY PROTECTION (46 bytes)
Configuration des fenêtres de Secure Attribution Unit pour l'isolation mémoire:

```
ROM Protection (4 variables)    :  10 bytes  - Base/size ROM, registered flag
Code Protection (4 variables)   :  10 bytes  - Base/size code, registered flag
Enclave Protection (4 variables):  10 bytes  - Base/size enclave, registered flags
Non-Secure Access (7 variables) :  16 bytes  - RAM/Flash limits, registered flag

Détail:
sau_rom_base                    :   4 bytes  - Adresse de base ROM
sau_rom_size                    :   4 bytes  - Taille enclaved ROM
sau_rom_registered              :   1 bytes  - Fenêtre enregistrée?
sau_code_base                   :   4 bytes  - Adresse de base code
sau_code_size                   :   4 bytes  - Taille code enclaved
sau_code_registered             :   1 bytes  - Fenêtre enregistrée?
sau_enclave_base                :   4 bytes  - Adresse de base enclave
sau_enclave_size                :   4 bytes  - Taille enclave
sau_enclave_registered          :   1 bytes  - Fenêtre enregistrée?
sau_enclave_open                :   1 bytes  - Enclave accessible?
sau_model_ro_open               :   1 bytes  - Modèle ROM accessible?
sau_ns_ram_base                 :   4 bytes  - Base RAM Non-Secure
sau_ns_ram_limit                :   4 bytes  - Limite RAM Non-Secure
sau_ns_flash_base               :   4 bytes  - Base Flash Non-Secure
sau_ns_flash_limit              :   4 bytes  - Limite Flash Non-Secure
sau_ns_flash_open               :   1 bytes  - Flash Non-Secure accessible?
────────────────────────────────────────────────────
SOUS-TOTAL                      :  46 bytes
```

**Rôle**: Implémente l'isolation mémoire au niveau hardware (SAU du Cortex-M33).

---

### 5️⃣ ECDH SESSION & KEYS (33 bytes)
Clés de session ECDH pour la confiance mutuelle device-enclave:

```
secure_session_key              :  32 bytes  (97.0%)  - Clé de session dérivée (SHA-256)
secure_session_key_set          :   1 bytes  ( 3.0%)  - Flag: clé définie?
────────────────────────────────────────────────────
SOUS-TOTAL                      :  33 bytes
```

**Rôle**: Authentifie mutuellement le device et l'enclave via ECDH.

---

### 6️⃣ COUNTERS & STATE (8 bytes)
Compteurs d'inférences et état des limites:

```
last_accepted_counter_limit     :   4 bytes  (50.0%)  - Limite d'inférences acceptée
default_model_id                :   4 bytes  (50.0%)  - ID du modèle par défaut
────────────────────────────────────────────────────
SOUS-TOTAL                      :   8 bytes
```

**Rôle**: Respecte les quotas d'inférences par device.

---

### 7️⃣ ENCLAVE LIFECYCLE (8 bytes)
État du cycle de vie de l'enclave:

```
inference_counter_secure        :   4 bytes  (50.0%)  - Compteur d'inférences locales
max_inferences_per_enclave_secure:  4 bytes  (50.0%)  - Max inférences autorisées
────────────────────────────────────────────────────
SOUS-TOTAL                      :   8 bytes
```

**Rôle**: Gère le nombre d'inférences exécutées par enclave.

---

### 8️⃣ ENCLAVEINFO & ATTESTATION (2 bytes)
Flags minimaux d'attestation:

```
current_enclave_info_valid      :   1 bytes  (50.0%)  - EnclaveInfo valide?
boot_enclave_info_valid         :   1 bytes  (50.0%)  - EnclaveInfo de boot valide?
────────────────────────────────────────────────────
SOUS-TOTAL                      :   2 bytes
```

**Rôle**: Trace l'état d'attestation des enclaves.

---

## Métriques d'Efficacité Mémoire

```
TCB Size:                    511 bytes
Secure World Available RAM:  65,536 bytes (64 KB)
────────────────────────────────────
% of Secure RAM used:        0.78%
Remaining for other uses:    65,025 bytes
```

---

## Note: PSA Crypto Service

Le service PSA Crypto (256 bytes) **n'est PAS compté** dans le TCB car:
- Il est déjà entièrement protégé au sein du monde Secure de TF-M
- Il représente une couche d'infrastructure TF-M, non une variable applicative
- Notre TCB mesure uniquement les **variables statiques applicatives** de la partition Secure

---

## Comment Interpréter les Résultats

### Rapport Texte (`TCB_EXTRACTION_REPORT.txt`)
Lisible par humain, contient:
- Détail de chaque variable trouvée
- Résumé par catégorie avec pourcentages
- Métriques d'efficacité mémoire

### Données JSON (`TCB_EXTRACTION_DATA.json`)
Importable par scripts, contient:
```json
{
  "total_tcb_bytes": 511,
  "variables": {
    "s_cert": 128,
    "s_pk_v": 64,
    ...
  },
  "categories": {
    "M_update Authorization": 201,
    "Device Keys & Transactions": 111,
    ...
  },
  "memory_efficiency": {
    "tcb_percent_of_secure_ram": 0.78,
    "secure_ram_used": 511,
    "secure_ram_total": 65536,
    "secure_ram_remaining": 65025
  }
}
```

---

## Modification du Programme

### Ajouter une Nouvelle Variable
Éditez le code source pertinent dans `dummy_partition/` et le programme les détectera automatiquement.

### Exclure des Variables
Modifiez la liste `CATEGORIES` dans `tools/tcb_size_extractor.py` pour exclure certaines variables.

### Changer les Chemins de Fichiers
Modifiez `SOURCE_FILES` dans le script:
```python
SOURCE_FILES = [
    'dummy_partition/secure_benchmark.c',
    'dummy_partition/secure_nsc_interface.c',
    '...'
]
```

---

## Résumé Exécutif

✅ **TCB Total: 511 bytes (0.50 KB)**
- Seulement 0.78% de la RAM Secure disponible
- 37 variables statiques sécuritaires identifiées
- 8 catégories fonctionnelles distinctes
- Extraction automatisée et reproductible

