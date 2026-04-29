# README Real Benchmark VeCoDI

## Objectif

Ce document décrit le benchmark reel execute sur la carte STM32L552 pour mesurer:
- M_update
- create enclave
- verified inference
- destroy enclave

Il remplace le pipeline simule qui produisait des valeurs de type 25 ms sans execution materielle.

## Contexte Materiel

- Board: NUCLEO-L552ZE-Q
- MCU: Cortex-M33
- Frequence: 110 MHz
- Port macOS recommande: /dev/cu.usbmodem1203

## Commande Recommandee 100 Runs Reels

Depuis la racine du projet:

```bash
python3 tools/benchmark_100_inferences.py \
  --flash \
  --boot-wait 20 \
  --runs 100 \
  --c-limit 30 \
  --port /dev/cu.usbmodem1203 \
  --image cifar_input.raw \
  --image-label 3 \
  --output build/full_flow_benchmark_100_real.json
```

## Fichier Resultat

Le resultat principal est:
- build/full_flow_benchmark_100_real.json

Champs importants:
- samples[].m_update_cycles
- samples[].create_enclave_cycles
- samples[].inference_cycles
- samples[].destroy_enclave_cycles
- summary.*

## Conversion Cycles vers Millisecondes

Formule a 110 MHz:

ms = cycles / 110000

Exemples:
- 261980 cycles = 2.382 ms
- 5,175,558 cycles = 47.051 ms
- 5,319,516 cycles = 48.359 ms

## Pourquoi Create peut etre a 46-47 ms et aussi a 90 ms

Ce sont deux mesures differentes:

1. Mesure carte (cycles)
- Create cote MCU, calcule via compteur embarque
- Typiquement autour de 46-47 ms apres conversion

2. Mesure host (ms)
- host_create_ms vu depuis le Mac
- Inclut UART, protocole, attente reponse, latence OS
- Typiquement autour de 90 ms

Les deux valeurs sont correctes simultanement.

## Interpreting Inference

Dans le benchmark reel full flow:
- inference_cycles est mesure cote carte
- valeur observee autour de 5.32M cycles
- soit environ 48.36 ms

Donc cette mesure n est pas equivalente au scenario simule atomic-only a 25 ms.

## Bonnes Pratiques de Reproductibilite

- Utiliser le port /dev/cu.usbmodem* sur macOS
- Garder un boot-wait apres flash pour eviter les timeouts UART
- Utiliser un c_limit suffisant pour eviter M_update rejected
- Ignorer le premier run si besoin de no-warmup stats

## No Warmup (recommande)

Pour exclure le run 1:

```bash
python3 - <<'PY'
import json
from pathlib import Path
p = Path('build/full_flow_benchmark_100_real.json')
d = json.loads(p.read_text())
s = d['samples'][1:]
for key in ['m_update_cycles','create_enclave_cycles','inference_cycles','destroy_enclave_cycles']:
    vals = [x[key] for x in s]
    avg = sum(vals)/len(vals)
    print(f"{key}: avg={avg:.1f} cycles ({avg/110000:.3f} ms)")
PY
```

## Fichiers Lies

- tools/benchmark_100_inferences.py
- tools/full_flow_benchmark.py
- BENCHMARK_100_INFERENCES.md
- build/full_flow_benchmark_100_real.json
