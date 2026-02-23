# Integrity Hash System Architecture (CNT)

## Overview

The system computes a SHA-256 hash to verify the integrity of:
- **Input data** (CIFAR-10 image)
- **Code** (weight addresses)
- **Model weights** (early + late layers)

## 2-Phase Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: INITIALIZATION                   │
│                  (create_enclave + setup)                    │
└─────────────────────────────────────────────────────────────┘

1. AES-CTR decryption of late weights
   ROM (encrypted) ──[TF-M Secure]──> RAM NS (plaintext)
   
2. Late weights buffer configuration
   set_late_weights_buffer(0x20000fc0, 39552)
   
3. PRE-COMPUTE late weights hash (ONCE ONLY)
   
   ┌─────────────────────────────────────────────┐
   │ precompute_late_weights_hash()              │
   ├─────────────────────────────────────────────┤
   │ SHA-256(                                    │
   │   code_pointers[28 bytes] ||               │ 
   │   wt_conv2d_7[36864 bytes] ||              │
   │   wt_conv2d_8[2048 bytes] ||               │
   │   wt_fc[640 bytes]                         │
   │ )                                           │
   │ ────────────────────────────────────────    │
   │ = late_weights_hash[32 bytes]              │
   └─────────────────────────────────────────────┘
   
   Stored in static memory for reuse


┌─────────────────────────────────────────────────────────────┐
│                  PHASE 2: INFERENCE LOOP                     │
│                   (for each image)                           │
└─────────────────────────────────────────────────────────────┘

For each test image (Test 0, Test 1, ...):

   ┌─────────────────────────────────────────────┐
   │ compute_integrity_hash(input_image)         │
   ├─────────────────────────────────────────────┤
   │ SHA-256(                                    │
   │   input_image[3072 bytes] ||               │
   │   wt_conv2d[432 bytes] ||                  │
   │   wt_conv2d_1[2304 bytes] ||               │
   │   wt_conv2d_2[2304 bytes] ||               │
   │   wt_conv2d_3[4608 bytes] ||               │
   │   wt_conv2d_4[9216 bytes] ||               │
   │   wt_conv2d_5[512 bytes] ||                │
   │   wt_conv2d_6[18432 bytes] ||              │
   │   late_weights_hash[32 bytes]              │
   │ )                                           │
   │ ────────────────────────────────────────────│
   │ = inference_hash[32 bytes]                 │
   └─────────────────────────────────────────────┘
   
   Stored in last_integrity_hash[32]
```

## Technical Details

### Phase 1: Late Weights Hash Pre-computation

**Function:** `precompute_late_weights_hash()`  
**Called from:** `main.cpp` line 49, after `set_late_weights_buffer()`  
**Frequency:** **Once** after decryption

**Hashed data (in order):**

```cpp
1. Code pointers (28 bytes)
   ┌────────────────────────────────────┐
   │ const void* early_weight_ptrs[] = {│
   │   wt_conv2d,      // 4 bytes      │
   │   wt_conv2d_1,    // 4 bytes      │
   │   wt_conv2d_2,    // 4 bytes      │
   │   wt_conv2d_3,    // 4 bytes      │
   │   wt_conv2d_4,    // 4 bytes      │
   │   wt_conv2d_5,    // 4 bytes      │
   │   wt_conv2d_6     // 4 bytes      │
   │ };                                 │
   └────────────────────────────────────┘
   
2. Late weight conv2d_7 (36864 bytes)
   - Hashed in 4096-byte chunks (9 chunks)
   - Address: 0x20000fc0 + LATE_WT_CONV2D_7_OFFSET
   
3. Late weight conv2d_8 (2048 bytes)
   - Hashed in 1 chunk (< 4096)
   - Address: 0x20000fc0 + LATE_WT_CONV2D_8_OFFSET
   
4. Late weight fc (640 bytes)
   - Hashed in 1 chunk (< 4096)
   - Address: 0x20000fc0 + LATE_WT_FC_OFFSET
```

**Total hashed:** 28 + 36864 + 2048 + 640 = **39580 bytes**  
**Result:** 32 bytes stored in `late_weights_hash[32]`

**Log output:**
```
[CNT] Computing late weights hash...
[CNT] ✓ Late weights hash (code_ptrs + late_wt): 2c8bb3f00e9d15fb...
```

---

### Phase 2: Inference Hash (per image)

**Function:** `compute_integrity_hash(input_data, hash_output)`  
**Called from:** `run_split_inference()` in test loop  
**Frequency:** **Every inference** (Test 0, Test 1, ...)

**Hashed data (in order):**

```cpp
1. Input image (3072 bytes = 32×32×3)
   - CIFAR-10 image in int8
   - Varies per test → different hash
   
2. Early weight conv2d (432 bytes)
   - ROM, plain text
   - Hashed in 1 chunk
   
3. Early weight conv2d_1 (2304 bytes)
   - Hashed in 1 chunk
   
4. Early weight conv2d_2 (2304 bytes)
   - Hashed in 1 chunk
   
5. Early weight conv2d_3 (4608 bytes)
   - Hashed in 2 chunks (4096 + 512)
   
6. Early weight conv2d_4 (9216 bytes)
   - Hashed in 3 chunks (4096 + 4096 + 1024)
   
7. Early weight conv2d_5 (512 bytes)
   - Hashed in 1 chunk
   
8. Early weight conv2d_6 (18432 bytes)
   - Hashed in 5 chunks (4×4096 + 2048)
   
9. Pre-computed late weights hash (32 bytes)
   - Reuses hash from Phase 1
   - Avoids re-hashing 40KB of late weights!
```

**Total hashed:** 3072 + 37808 (early) + 32 (late_hash) = **40912 bytes**  
**Result:** 32 bytes stored in `hash_output[32]`

**Log output (exemple Test 0):**
```
[CNT] Computing inference hash...
[CNT] ✓ Inference hash (input + early_wt + late_hash): 9c64e02237b58a7a...
```

---

## Chunking Strategy

### Why chunking?

PSA Crypto has a buffer size limit (~4-8KB). Large weights (wt_conv2d_4 = 9KB, wt_conv2d_6 = 18KB, wt_conv2d_7 = 36KB) exceed this limit.

### Helper function

```cpp
hash_buffer_chunked(operation, data, size, label) {
    chunk_size = 4096;
    while (remaining > 0) {
        to_hash = min(remaining, chunk_size);
        psa_hash_update(operation, ptr, to_hash);
        ptr += to_hash;
        remaining -= to_hash;
    }
}
```

### SHA-256 streaming property

```
hash(A || B || C) = hash_finish(
    hash_update(
        hash_update(
            hash_update(init, A),
        B),
    C)
)
```

Chunking is **transparent**: hash of sequential chunks = hash of complete buffer.

---

## Key Optimization

### Without optimization (naive version):

```
For each inference:
  hash(input || early_wt || code_ptrs || late_wt)
  
Total hashed per inference: ~80 KB
Time: high (chunking 40KB late weights)
```

### With optimization (implemented):

```
Phase 1 (once):
  late_hash = hash(code_ptrs || late_wt)
  
Phase 2 (per inference):
  inference_hash = hash(input || early_wt || late_hash)
  
Total hashed per inference: ~41 KB (instead of 80 KB)
Gain: 49% reduction, late weights not re-hashed
```

---

## Complete Data Flow

```
ROM (Flash)                        RAM NS
═══════════                        ══════

early_wt_plain ─────────┐
(35 KB)                 │
                        ├──> [Hash Phase 2]
input_image ────────────┤     (per inference)
(3 KB)                  │          │
                        │          v
                        │     inference_hash
                        │     (32 bytes)
                        │
late_wt_encrypted ──[TF-M AES]──> late_wt_plain
(40 KB ROM)         decrypt        (40 KB RAM @ 0x20000fc0)
                                        │
                                        v
                                   [Hash Phase 1]
                                   (once)
                                        │
                                        v
code_ptrs ──────────────┐         late_hash
(28 bytes)              ├────>    (32 bytes)
                        │              │
                        └──────────────┘
```

---

## Concrete Example

### Test 0 (cat image):

```
Phase 1 (already done):
  late_hash = SHA-256(code_ptrs || late_wt_7,8,fc)
            = 2c8bb3f00e9d15fbf815ec8a12aff636d7f0026bb0bef4028065828aa2003eb5

Phase 2:
  input_0 = [cat pixel_data, 3072 bytes]
  
  inference_hash_0 = SHA-256(
      input_0 ||
      wt_conv2d || wt_conv2d_1 || ... || wt_conv2d_6 ||
      late_hash
  )
  = 9c64e02237b58a7a6f38284f2eb29c10040942d50fbfb25953180010c03d5293
```

### Test 1 (truck image):

```
Phase 1 (same result):
  late_hash = 2c8bb3f00e9d15fb... (identical)

Phase 2:
  input_1 = [truck pixel_data, 3072 bytes] ← DIFFERENT!
  
  inference_hash_1 = SHA-256(
      input_1 ||  ← Changes here!
      wt_conv2d || ... || wt_conv2d_6 ||
      late_hash
  )
  = 39bcda0932c5ff6bde9233d0fd84ef99f8e9e35d23e056756a8d39ca104dcd56
                                                          ← Completely different!
```

**SHA-256 avalanche effect:** Changing 1 byte of input completely changes the final hash.

---

## Security and Integrity

### Final hash coverage

The inference hash **covers everything**:

```
✓ Input data           (via direct concatenation)
✓ Code addresses       (via late_hash → code_ptrs)
✓ Early weights 0-6    (via direct concatenation)
✓ Late weights 7,8,fc  (via late_hash)
```

### Attack detection

| Attack | Detection |
|---------|-----------|
| Input modification | Hash changes (input in inference_hash) |
| Early weights modification | Hash changes (early_wt in inference_hash) |
| Late weights modification | Hash changes (late_wt in late_hash) |
| Code modification (pointers) | Hash changes (code_ptrs in late_hash) |
| Replay attack | External timestamp required (out of scope) |

---

## Performance

### Theoretical measurements

**Phase 1 (once):**
- Data: 39580 bytes
- Chunks: ~10 psa_hash_update calls
- Time: ~10-15ms (estimated)

**Phase 2 (per image):**
- Data: 40912 bytes
- Chunks: ~11 psa_hash_update calls
- Time: ~10-15ms (estimated)

**Without optimization (per image):**
- Data: ~80000 bytes
- Chunks: ~20 psa_hash_update calls
- Time: ~20-30ms (estimated)

**Gain:** ~50% reduction in hash time per inference

---

## Source Code

### Key files

```
src/split_inference.cpp
├── hash_buffer_chunked()           [Chunking helper]
├── precompute_late_weights_hash()  [Phase 1]
└── compute_integrity_hash()        [Phase 2]

src/split_inference.h
└── precompute_late_weights_hash()  [Declaration]

src/main.cpp
└── main() line 49                  [Phase 1 call]
```

### Global variables

```cpp
static uint8_t late_weights_hash[32];    // Phase 1 result
static bool late_hash_computed = false;  // Validation flag
static uint8_t last_integrity_hash[32];  // Last Phase 2 hash
```

---

## Architecture Summary

```
┌──────────────────────────────────────────────────────────────┐
│                      CNT HASH SYSTEM                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Phase 1: SETUP (1×)                                        │
│  ────────────────────────────────────────                   │
│  Decryption → Configuration → Hash Late Weights             │
│  ROM → RAM NS → SHA-256(code+late) → late_hash[32]         │
│                                                              │
│  Phase 2: INFERENCE (N×)                                    │
│  ────────────────────────────────────────                   │
│  Load Image → Hash Inference → Early → Late → Prediction   │
│  SHA-256(input+early+late_hash) → inference_hash[32]       │
│                                                              │
│  Optimization:                                              │
│  Late weights (40KB) hashed 1× instead of N×                │
│  Gain: 50% hash time reduction                              │
│                                                              │
│  Security:                                                  │
│  Complete coverage: Input + Code + Early WT + Late WT      │
│  Modification detection via SHA-256 avalanche effect       │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Annotated Logs

```
[STEP 1.5] Configuring split inference with decrypted weights...
[CNT] Computing late weights hash...
      ↓ Phase 1: hash(code_ptrs || late_wt_7,8,fc) = 40KB
[CNT] ✓ Late weights hash (code_ptrs + late_wt): 2c8bb3f0...
      ↑ Stored in late_weights_hash[32]

[SPLIT] Test 0 | expected = 6
[CNT] Computing inference hash...
      ↓ Phase 2: hash(input_0 || early_wt || late_hash) = 41KB
[CNT] ✓ Inference hash (input + early_wt + late_hash): 9c64e023...
      ↑ Unique hash for image 0
[EARLY] Starting early layers...
[EARLY] ✓ Early layers complete
[LATE] Starting late layers...
[LATE] ✓ Late layers complete
[SPLIT] Prediction = 6

[SPLIT] Test 1 | expected = 9
[CNT] Computing inference hash...
      ↓ Phase 2: hash(input_1 || early_wt || late_hash) = 41KB
[CNT] ✓ Inference hash (input + early_wt + late_hash): 39bcda09...
      ↑ DIFFERENT hash because input_1 ≠ input_0
[EARLY] Starting early layers...
[EARLY] ✓ Early layers complete
[LATE] Starting late layers...
[LATE] ✓ Late layers complete
[SPLIT] Prediction = 9

[CNT] ✓ All hash computations complete
      ↑ Last hash stored in last_integrity_hash[32]
```
