# Analyse de conformit code vs papier

Document de rfrence: Secure_and_Verifiable_Inference_of_DNN_on_Low_End_Edge_Devices.pdf
Date de l'analyse: 22 avril 2026

## Methode (sans supposition)

- Source papier analysee via extraction texte locale (/tmp/savid_paper.txt).
- Source code analysee dans le workspace courant (NS + Secure TF-M + protocole UART + benchmarks).
- Chaque verdict est base sur des elements observables (fichiers, structures, commandes, flux).
- Quand un point du papier n'est pas demonstrable dans ce repo, il est marque "Non verifiable".

## Resume executif

- Globalement, l'architecture de ce repo suit bien l'esprit SAVID: split inference, Secure World minimal, controle de quota, PoX signe en Secure, isolation SAU dynamique.
- Mais il y a des ecarts importants entre le protocole formel du papier (Provision/Authorize/Execute) et l'implementation concrete (M_update + commandes UART/PSA).
- Il y a aussi des incoherences internes dans le papier (notamment sur la confidentialite de l'entree), ce qui rend certaines comparaisons "partielles" plutot que "pas match".

---

## 1) Architecture et modele de confiance

### 1.1 TrustZone-M + separation Secure/Non-Secure
Verdict: MATCH

Preuves:
- Le projet utilise TF-M et PSA IPC: prj.conf active CONFIG_BUILD_WITH_TFM, CONFIG_TFM_IPC, CONFIG_TFM_PARTITION_CRYPTO.
- Partition Secure dediee exposee via SID 0xFFFFF002:
  - dummy_partition/tfm_dummy_partition.yaml
  - dummy_partition/dummy_partition.c:62-73

### 1.2 Idee "3e environnement" type Shangri-La (code inference en NS, controle securite en Secure)
Verdict: PARTIEL MAIS COHERENT

Ce qui match:
- L'inference reste en NS (split_inference.cpp), alors que Secure fait controle/crypto/SAU.
- SAU est pilote dynamiquement depuis Secure pour ouvrir/fermer fenetres RAM/ROM:
  - dummy_partition/dummy_partition.c:980-1170 (open/close RAM/ROM)
  - dummy_partition/dummy_partition.c:1491-1513, 1879, 1969

Ecart:
- Le papier formalise des APIs Provision/Authorize/Execute/Destroy, alors que le code expose plutot une API de commandes PSA/UART (DP_CMD_* + CMD_*).

---

## 2) Cycle de vie (Create/Execute/Destroy)

### 2.1 Create / Destroy
Verdict: MATCH

Preuves:
- Create enclave cote NS + Secure:
  - src/create_enclave.cpp:299-409
  - dummy_partition/dummy_partition.c:1318-1391 (DP_CMD_CREATE_ENCLAVE)
- Finalize create (fermeture RAM apres setup):
  - src/create_enclave.cpp:261-288
  - dummy_partition/dummy_partition.c:1393-1410
- Destroy enclave:
  - src/create_enclave.cpp:501-547
  - dummy_partition/dummy_partition.c:1412-1438

### 2.2 Execute atomique
Verdict: PARTIEL

Ce qui match:
- Fenetre atomique START -> inference NS -> COMPLETE avec commit Secure:
  - src/uart_protocol.cpp:909-1018
  - dummy_partition/dummy_partition.c:1762-2000

Ecart:
- Le papier dit "disable interrupts" dans Execute (algo), ici le masquage IRQ est fait cote NS (irq_lock), pas dans une API Execute unique cote Secure.
- Le papier mentionne "erase stack" dans Execute; ce comportement n'est pas visible tel quel dans cette implementation.

---

## 3) Confidentialite du modele (G1)

### 3.1 Protection directe des poids prives (modele split + partie privee chiffree)
Verdict: MATCH

Preuves:
- Poids late chiffrs stockes et decryptes via Secure (AES-CTR):
  - split_inference/README.md
  - dummy_partition/dummy_partition.c:686-783 (decrypt)
  - src/create_enclave.cpp:261-352
- SAU ferme l'acces NS hors fenetre autorisee:
  - dummy_partition/dummy_partition.c:980-1170

### 3.2 Controle du nombre d'inferences (anti-extraction indirecte)
Verdict: PARTIEL

Ce qui match:
- Anti-replay strict sur c_limit (M_update):
  - dummy_partition/dummy_partition.c:623
- Compteur secure et limite secure utilises avant/pendant inference:
  - dummy_partition/dummy_partition.c:1762-1784, 1970-1973

Ecart important:
- Override direct de limite possible via commande runtime (SET_MAX_INFERENCES / UPDATE_RATE_LIMIT), sans preuve explicite de signature fournisseur dans ce chemin:
  - src/uart_protocol.cpp:1360-1382, 1491-1505
  - dummy_partition/dummy_partition.c:1595-1615

Impact:
- Par rapport au papier (autorisation formelle par owner), ce chemin runtime reduit la force de la garantie G1-2 si expose en production.

---

## 4) Verifiable inference / PoX (G2)

### 4.1 Verification M_inf en Secure
Verdict: MATCH

Preuves:
- START de transaction decrypte M_inf puis verifie signature ECDSA avec pk_v:
  - dummy_partition/dummy_partition.c:1762-1877

### 4.2 Generation de PoX en Secure
Verdict: MATCH (implementation concrete), MAIS ECART AVEC FORMAT PAPIER

Implementation observee:
- Message signe pour PoX: model_id || cert || nonce || output
  - dummy_partition/dummy_partition.c:1907-1955
- Signature faite avec cle device Secure:
  - dummy_partition/dummy_partition.c:1955-1964

Ecart avec papier:
- Le papier decrit une preuve couvrant F || M_ID || In || Out || pk_Pvd (selon ses sections protocol/security).
- Le code ne signe pas explicitement F ni In dans le PoX runtime observe.

Conclusion:
- PoX existe et est bien secure-side, mais son contenu signe ne correspond pas exactement a la formulation formelle du papier.

### 4.3 Verification du cert provider
Verdict: PARTIEL / NON FINALISE

Preuve:
- Un chemin de verification indique explicitement TODO pour verifier le cert provider:
  - src/inference_protocol.cpp:314

Note:
- Ce fichier semble etre surtout un module de test/simulation, pas necessairement le chemin final Mac Python. Donc: preuve d'incompletude locale, pas preuve absolue d'absence globale.

---

## 5) Authenticite de l'entree et confidentialite de l'entree

### 5.1 Entree capteur "authentique" (papier)
Verdict: PAS MATCH (dans ce repo)

Papier:
- Decrit F qui recupere l'entree via peripherique/senseur et garantit authenticite de l'entree.

Code observe:
- Inference basee sur images de test embarquees ou image uploadee par UART:
  - src/split_inference.cpp:82-101, 646-700
  - src/uart_protocol.cpp:1021-1047

Conclusion:
- Ce repo est une maquette/prototype CIFAR orientee benchmark/protocole, pas une chaine capteur attestee de bout en bout.

### 5.2 "Verification sans entree" (papier)
Verdict: INCOHERENT DANS LE PAPIER (donc comparaison stricte impossible)

Constat:
- Le papier dit a un endroit que la validation de preuve ne depend pas de In.
- Mais l'algorithme I4 et sections protocol/security incluent In dans la verification.

Evidence papier:
- /tmp/savid_paper.txt:130
- /tmp/savid_paper.txt:943-944
- /tmp/savid_paper.txt:1031-1033

Conclusion:
- Le document de reference n'est pas auto-coherent sur ce point, donc impossible de marquer un "match" propre ici sans clarifier la spec.

---

## 6) Alignement protocolaire (Algorithm 1/2 vs code)

### 6.1 Provision / Authorize / Execute formalises
Verdict: PARTIEL

Papier:
- APIs explicites Provision/Authorize/Execute/Destroy avec tokens signes (owner + consumer).

Code:
- Mecanisme reel base sur:
  - ECDH session key
  - M_update chiffre AES-GCM
  - verification M_inf + PoX via DP_CMD_INF_START/COMPLETE
- Pas de fonction unique Execute(u, In, Hs_id, proof, Tu) implementee telle quelle.

References:
- src/uart_protocol.cpp:706-1018
- dummy_partition/dummy_partition.c:588-676, 1762-2000
- /tmp/savid_paper.txt:670-776, 919-939

### 6.2 Signature utilisateur par requete (Tu)
Verdict: PAS MATCH

Papier:
- Execute verifie une signature utilisateur Tu sur u || In || Hs_id || proof.

Code:
- Le START verifie signature du verifier sur M_inf, mais pas de Tu tel que defini dans l'algorithme.
- La politique est principalement installee via M_update (state secure).

References:
- /tmp/savid_paper.txt:745-769, 936-939
- dummy_partition/dummy_partition.c:1762-1877

---

## 7) Evaluation et benchmarks

### 7.1 Plateforme et objectif evaluation
Verdict: MATCH

Preuves:
- NUCLEO-L552ZE-Q / Cortex-M33, TrustZone-M, mesures cycles et latence presentes.
- Fichiers de resultats:
  - BENCHMARK_RESULTS.md
  - benchmark_results.txt
  - TABLE2_FINAL.md

### 7.2 Chiffres exacts du papier vs chiffres locaux
Verdict: PARTIEL

Constat:
- Le papier contient une table avec valeurs cibles (ex: ~46.62/46.64/46.73 ms).
- Le repo contient plusieurs campagnes avec valeurs parfois differentes (selon scenario et pipeline mesure).

Conclusion:
- L'instrumentation existe et le type de comparaison existe, mais les valeurs numeriques exactes ne sont pas toujours identiques entre papier et etat courant du code/resultats.

---

## 8) Points "Non verifiable" (par prudence)

- Verification complete cote outil Mac/Python de toutes les signatures/certificats: non verifiable sans audit complet des scripts host actifs dans ta campagne de test.
- Correspondance 1:1 de toutes les figures/tables du PDF avec une version unique de firmware: non verifiable ici car plusieurs fichiers de benchmark coexistent.
- Propriete "formal verification once, reusable" (claim du papier): non verifiable depuis ce code seul.

---

## 9) Tableau final Match / No-Match

| Theme | Statut |
|---|---|
| TrustZone-M + separation Secure/NS | Match |
| Split model + poids prives chiffres + decrypt Secure | Match |
| SAU dynamique open/close pour fenetre enclave | Match |
| Lifecycle Create/Finalize/Destroy | Match |
| Transaction START/COMPLETE avec commit secure | Match |
| Quota/anti-replay c_limit | Partiel |
| Autorisation formelle owner->user (Algorithm 1/2) | Partiel a Pas match |
| Signature utilisateur Tu par requete Execute | Pas match |
| Format PoX exactement conforme a la spec papier | Partiel |
| Authentification entree capteur (sensor-trust) | Pas match |
| Evaluation pratique sur NUCLEO-L552ZE-Q | Match |
| Egalite stricte de tous les chiffres du papier | Partiel |

---

## 10) Priorites de correction (si tu veux aligner avec le papier)

1. Bloquer/retirer les chemins de changement de quota non autorises en prod (CMD_SET_MAX_INFERENCES / UPDATE_RATE_LIMIT), ou les proteger par verification cryptographique owner.
2. Aligner la semantique Execute avec la spec (Tu: signature user par requete, compteur u, Hs_id).
3. Decider et figer la definition PoX (contenu exact signe), puis aligner papier + firmware + verifier host.
4. Clarifier la contradiction du papier sur la confidentialite d'entree (I4 inclut In vs texte disant verification sans In).
5. Si objectif papier strict: remplacer le mode image UART par un chemin d'entree capteur authentifie.

---

## Fichiers inspectes (principaux)

- Secure_and_Verifiable_Inference_of_DNN_on_Low_End_Edge_Devices.pdf (via /tmp/savid_paper.txt)
- dummy_partition/dummy_partition.c
- dummy_partition/dummy_partition.h
- dummy_partition/tfm_dummy_partition.yaml
- src/create_enclave.cpp
- src/uart_protocol.cpp
- src/split_inference.cpp
- src/run_enclave.cpp
- src/inference_protocol.cpp
- prj.conf
- CMakeLists.txt
- BENCHMARK_RESULTS.md
- TABLE2_FINAL.md
- benchmark_results.txt
