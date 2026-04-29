# Atomic Inference Window Benchmark

Guide pour benchmarker l'inférence dans la fenêtre atomique de sécurité.

---

## Vue d'Ensemble

La fenêtre atomique d'inférence est une section critique de code où:
1. **Early Layers** s'exécutent en enclave Secure (accès aux clés)
2. **Late Layers** s'exécutent en Non-Secure avec poids chiffrés
3. **Integrity Hash** est calculé pour attestation

Ce benchmark mesure les cycles CPU utilisés par chaque phase.

---

## Architecture de l'Inférence

```
┌─────────────────────────────────────────────────────────────┐
│         ATOMIC INFERENCE WINDOW (run_split_inference)       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. set_atomic_inference_window_open(true)                │
│                                                             │
│  2. run_early_layers()                                     │
│     └─ Exécute convolutions en Secure World              │
│     └─ Accès aux clés de modèle                          │
│     └─ Mesure: early_layers_cycles                       │
│                                                             │
│  3. run_late_layers()                                      │
│     └─ Déchiffrement et exécution en Non-Secure (ou      │
│        encrypted en Secure selon config)                  │
│     └─ Accumule dans buffers temporaires                 │
│     └─ Mesure: late_layers_cycles                        │
│                                                             │
│  4. compute_integrity_hash()                               │
│     └─ Hash SHA-256 pour authentification                │
│     └─ Ajoute overhead au total_inference_cycles         │
│                                                             │
│  5. set_atomic_inference_window_open(false)              │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  TOTAL INFERENCE CYCLES = early + late + hash + overhead   │
└─────────────────────────────────────────────────────────────┘
```

---

## Fichiers Impliqués

### Code Source
- **[src/split_inference.cpp](../src/split_inference.cpp#L539)** - Fonction `run_split_inference()` (fenêtre atomique)
- **[src/split_inference.cpp](../src/split_inference.cpp#L400)** - `run_early_layers()` avec benchmarks
- **[src/split_inference.cpp](../src/split_inference.cpp#L480)** - `run_late_layers()` avec benchmarks
- **[src/benchmark.h](../src/benchmark.h)** - Macros BENCHMARK_START/END
- **[src/benchmark.cpp](../src/benchmark.cpp)** - Implémentation cycle counter (k_cycle_get_32)

### Scripts
- **[tools/atomic_inference_benchmark.py](./atomic_inference_benchmark.py)** - Analyseur Python des résultats

---

## Comment Compiler et Déboguer le Benchmark

### 1. Build avec CMSIS-NN (Optimal - Cortex-M33)

```bash
cd /Users/user/zephyrproject/zephyr/samples/modules/tflite-micro/VeCoDI

# Build complet avec optimisations CMSIS-NN
west build -p auto -b mps3/corstone300/fvp . -T sample.tensorflow.helloworld.cmsis_nn
```

**Options:**
- `-p auto` : Détecte automatiquement si reconfiguration nécessaire
- `-b mps3/corstone300/fvp` : Board Cortex-M33 (FVP = Fast Virtualizer)
- `-T sample.tensorflow.helloworld.cmsis_nn` : Cible CMSIS-NN optimisée

### 2. Build Référence (QEMU x86)

```bash
west build -p auto -b qemu_x86 .
```

**Utile pour:**
- Déboguer sans hardware ARM spécifique
- Vérifier la logique sans optimisations CMSIS-NN

---

## Exécuter le Benchmark

### Option A: Simulation FVP (Cortex-M33 complète)

```bash
# Après compilation avec FVP
west build -t run
```

**Avantages:**
- Simule exactement le Cortex-M33 (110 MHz)
- Mesures de cycles précises
- Pas besoin de hardware physique

**Sortie attendue:**
```
[SPLIT] Executing split inference...
[SPLIT] expected = 3
[EARLY] Running early layers: X cycles...
[LATE] Running late layers: Y cycles...
[SPLIT] Prediction = 3 (total inference: Z cycles, W ms)
```

### Option B: Hardware STM32L552 (Nucleo)

```bash
# 1. Compiler pour la cible matérielle
west build -p auto -b nucleo_l552ze_q_stm32l552xx_ns .

# 2. Flash le device
west flash

# 3. Se connecter au UART (115200 bps)
screen /dev/cu.usbserial-* 115200

# 4. Déclencher l'inférence via commande UART
# Commands disponibles: créer enclave, lancer inférence, etc.
```

---

## Extraire les Résultats

Une fois l'inférence exécutée, le script Python extrait automatiquement les cycles:

```bash
# Depuis le répertoire du projet
python3 tools/atomic_inference_benchmark.py
```

**Fichier généré:**
- `build/ATOMIC_INFERENCE_BENCHMARK.json` - Données structurées pour post-traitement

---

## Lecture de la Sortie du Benchmark

### Console Output Exemple

```
════════════════════════════════════════════════════════════════════════════════════════════════════
                     ATOMIC INFERENCE WINDOW BENCHMARK                  
════════════════════════════════════════════════════════════════════════════════════════════════════

Target: STM32L552 Cortex-M33 @ 110 MHz
Implementation: CMSIS-NN Split Inference (Early + Late Layers)

Measurements collected: 10

✓ Total Inferences measured: 10
✓ Early layers measured: 10
✓ Late layers measured: 10

────────────────────────────────────────────────────────────────────────────────────────────────────
TOTAL INFERENCE (Early + Late + Overhead)
────────────────────────────────────────────────────────────────────────────────────────────────────

Cycles Statistics:
  Min:        3,421,045 cycles  (  31.10 ms)
  Max:        3,456,789 cycles  (  31.43 ms)
  Average:    3,438,917 cycles  (  31.26 ms)
  Range:         35,744 cycles  (   0.33 ms)

────────────────────────────────────────────────────────────────────────────────────────────────────
EARLY LAYERS (Enclave-only)
────────────────────────────────────────────────────────────────────────────────────────────────────

Cycles Statistics:
  Min:        1,523,401 cycles  (  13.85 ms)
  Max:        1,545,678 cycles  (  14.05 ms)
  Average:    1,534,539 cycles  (  13.95 ms)
  Range:         22,277 cycles  (   0.20 ms)

────────────────────────────────────────────────────────────────────────────────────────────────────
LATE LAYERS (Host + Enclave, Encrypted)
────────────────────────────────────────────────────────────────────────────────────────────────────

Cycles Statistics:
  Min:          987,123 cycles  (   8.97 ms)
  Max:        1,012,456 cycles  (   9.20 ms)
  Average:      999,289 cycles  (   9.08 ms)
  Range:         25,333 cycles  (   0.23 ms)

────────────────────────────────────────────────────────────────────────────────────────────────────
BREAKDOWN (Early vs Late)
────────────────────────────────────────────────────────────────────────────────────────────────────

Average per inference (cycles):
  Early layers:      1,534,539 cycles  (  13.95 ms)  44.6%
  Late layers:         999,289 cycles  (   9.08 ms)  29.1%
  Overhead:            905,089 cycles  (   8.23 ms)  26.3%
  ──────────────────────────────────────────────────
  Total:             3,438,917 cycles  (  31.26 ms)  100.0%
```

### Signification de chaque métrique

| Métrique | Signification | Valeur Exemple |
|----------|---------------|-----------------|
| **Early layers** | Convolutions en mode Secure | 1.5M cycles (44.6%) |
| **Late layers** | Chiffrement + NC inférence | 1.0M cycles (29.1%) |
| **Overhead** | Hash, PEC, contexte switching | 0.9M cycles (26.3%) |
| **Total** | Fenêtre complète | 3.4M cycles (31.26 ms) |
| **Range** | Variation min/max | 35K cycles (0.33 ms) |

---

## Interpretation des Résultats

### Qu'est-ce qui est Normal?

#### Early Layers (Secure Enclave)
- **Attendu:** ~13-15 ms pour CIFAR-10 (~50 layers)
- **Facteurs:** CMSIS-NN optimisation, SAU overhead, hash computation
- **Écart acceptable:** ±5% (~0.7 ms)

#### Late Layers (Host + Secure)
- **Attendu:** ~8-10 ms pour poids chiffrés
- **Facteurs:** Déchiffrement par chunks (PSA), exécution réseau
- **Écart acceptable:** ±8% (~0.8 ms)

#### Overhead
- **Inclut:**
  - Integrity hash SHA-256 (~2-3 ms)
  - Context switching (SAU, trust boundaries)
  - Buffer management
  - Cycle counter precision (~±0.1 ms)

### Variance Attendue

**±5-10% est normal** car:
- PSA crypto décrypte par chunks (timing variable)
- Cache CPU se remplit progressivement
- Interrupt handling non-déterministe

**>15% variance suggère:**
- Cache misses excessifs
- Interrupts fréquentes
- Modèle chargé différemment

---

## Modifier le Benchmark pour des Mesures Spécifiques

### 1. Mesurer seulement Early Layers

Éditez [src/split_inference.cpp](../src/split_inference.cpp#L450):

```cpp
BENCHMARK_START(early);
run_early_layers(input_buffer, early_output, early_skip);
BENCHMARK_END(early, g_benchmark_metrics.early_layers_cycles);
```

### 2. Ajouter des Point de Mesure Intermédiaires

```cpp
// Avant decrypt
uint32_t t1 = benchmark_get_cycles();

// After decrypt
uint32_t t2 = benchmark_get_cycles();
printk("[LATE] Decrypt time: %u cycles\n", t2 - t1);
```

### 3. Mesurer par Layer CMSIS-NN

Modifiez [src/split_inference.cpp](../src/split_inference.cpp#L400):

```cpp
for (int layer = 0; layer < num_layers; layer++) {
    uint32_t start = benchmark_get_cycles();
    // Execute layer via arm_nn functions
    uint32_t cycles = benchmark_get_cycles() - start;
    printk("[LAYER %d] %u cycles\n", layer, cycles);
}
```

---

## Dépannage

### Problème: Output ne montre pas les cycles

**Cause:** `BENCHMARK_*` macros désactivées ou incompilées

**Solution:**
```bash
# Vérifier la config
cat prj.conf | grep -i benchmark

# Recompiler
rm -rf build
west build -p auto -b mps3/corstone300/fvp . -T sample.tensorflow.helloworld.cmsis_nn
```

### Problème: Cycles incohérents entre runs

**Causes possibles:**
1. Cache CPU non purgé → solution: réchauffer le cache avec run initial
2. Interrupts système → solution: utiliser board avec interrupts réduites
3. Erreur de mesure clock → solution: vérifier `CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC`

**Fix:**
```bash
# Vérifier CPU_FREQ_HZ dans src/benchmark.cpp
grep -n "CPU_FREQ_HZ" src/benchmark.cpp

# Doit être 110 MHz pour STM32L552
```

### Problème: Le build échoue avec CMSIS-NN

```bash
# Solution: Fallback au reference kernel
west build -p auto -b qemu_x86 .
```

---

## Fichiers Générés par le Benchmark

### `build/ATOMIC_INFERENCE_BENCHMARK.json`

Structure des données:
```json
{
  "timestamp": "2026-04-29T...",
  "cpu_freq_hz": 110000000,
  "cpu_freq_mhz": 110,
  "measurements": [
    {"total_inference_cycles": 3421045, ...},
    ...
  ],
  "summary": {
    "total_inference": {
      "min_cycles": 3421045,
      "max_cycles": 3456789,
      "avg_cycles": 3438917,
      "min_ms": 31.1,
      "max_ms": 31.43,
      "avg_ms": 31.26,
      "count": 10
    },
    "early_layers": { ... },
    "late_layers": { ... },
    "breakdown": {
      "early_percent": 44.6,
      "late_percent": 29.1,
      "overhead_percent": 26.3
    }
  }
}
```

### Console Output
- Imprimé directement par `run_split_inference()`
- Formaté pour extracteur regex Python
- Pattern: `[SPLIT] Prediction = N (total inference: X cycles, Y ms)`

---

## Cas d'Usage: Comparer avec Autre Device

### Benchmark sur STM32L552 (Cortex-M33 @ 110 MHz)
```bash
west build -p auto -b nucleo_l552ze_q_stm32l552xx_ns .
# Mesure le device physique
```

### Benchmark sur Corstone-300 FVP
```bash
west build -p auto -b mps3/corstone300/fvp . -T sample.tensorflow.helloworld.cmsis_nn
# Simule le design référence ARM
```

### Comparer les résultats
```bash
# Ratio cycles entre devices
python3 -c "
l552_ms = 31.26
corstone_ms = 32.15
ratio = l552_ms / corstone_ms
print(f'STM32L552 est {ratio:.1%} plus rapide que Corstone-300')
"
```

---

## Prochaines Étapes

1. **Optimiser Early Layers:** Ajouter plus d'opérations CMSIS-NN
2. **Réduire Overhead:** Implémenter streaming integrity hash
3. **Comparer avec TFLite Micro:** Mesurer le gain du split
4. **Profiler par Layer:** Identifier les bottlenecks CMSIS-NN

