#+#+#+#+
# Dummy Partition (TF-M Secure Service)

## Overview
This TF-M secure partition provides cryptographic services for the Non-Secure (NS) app. In the current flow it **decrypts encrypted late-layer weights** and writes them into an NS RAM buffer via PSA IPC.

## Key Paths (Secure World)
- `dummy_partition/dummy_partition.c`: command dispatcher + AES-CTR decryption implementation
- `dummy_partition/tfm_dummy_partition.yaml`: TF-M service manifest (SID, IPC model)
- `dummy_partition/tfm_manifest_list.yaml.in`: manifest list included by build system

## Service Identity
Defined in [tfm_dummy_partition.yaml](tfm_dummy_partition.yaml):

- **SID**: `0xFFFFF002`
- **Version**: `1`
- **Connection-based**: yes

## Commands
Defined in [dummy_partition.c](dummy_partition.c):

- `DP_CMD_SECRET_DIGEST = 0`
- `DP_CMD_DECRYPT_MODEL = 2` (deprecated, returns NOT_SUPPORTED)
- `DP_CMD_DECRYPT_LATE_WEIGHTS = 3` **(current)**

## Current Flow (Late Weights)
NS calls `psa_call()` with:

```
in_vec[0] = cmd (DP_CMD_DECRYPT_LATE_WEIGHTS)
in_vec[1] = encrypted late weights (flash)
in_vec[2] = IV (16 bytes)
out_vec[0] = NS RAM buffer (decrypted output)
```

The secure partition:
1. Sets up **AES-128-CTR** with PSA Crypto.
2. Applies the IV from `in_vec[2]`.
3. Decrypts in chunks using `psa_cipher_update()`.
4. Writes plaintext into the NS output buffer.

## End-to-End Path (What Runs)
1. NS app calls `create_enclave()` in `src/create_enclave.cpp`.
2. NS packages `{cmd, encrypted_weights, iv}` and calls PSA IPC.
3. TF-M routes the request to `dummy_partition.c` (this file).
4. AES-CTR decrypts encrypted weights and writes plaintext to the NS buffer.
5. NS runs `run_split_inference()` in `src/split_inference.cpp` using the decrypted weights.

## Architecture (Current)
```
Non-Secure app                              Secure world (TF-M)
┌────────────────────────────┐             ┌────────────────────────────┐
│ psa_call(SID=0xFFFFF002)   │  IPC        │ tfm_dp_req_mngr_init()      │
│  in_vec[0]=cmd (u32)        │───────────► │  └─ tfm_dp_secret_digest_ipc│
│  in_vec[1]=payload #1       │             │     ├─ secret digest       │
│  in_vec[2]=payload #2       │             │     └─ AES-CTR decrypt     │
│  out_vec[0]=output buffer   │             │        (writes to out_vec) │
└────────────────────────────┘             └────────────────────────────┘
```

The partition only waits on `TFM_DP_SECRET_DIGEST_SIGNAL` and routes all
commands through `tfm_dp_secret_digest_ipc()`.

## IPC Protocol (Current)

### Common
- `in_vec[0]`: `cmd` (`uint32_t`)
- `in_vec[1]`: payload buffer (meaning depends on `cmd`)
- `in_vec[2]`: payload buffer (only used by AES flow; 16-byte IV)
- `out_vec[0]`: output buffer (meaning depends on `cmd`)
- All lengths are taken from `msg->in_size[]` / `msg->out_size[]`.

### `DP_CMD_SECRET_DIGEST`
- **Purpose**: SHA-256 digest of a fixed secret.
- **Input**:
	- `in_vec[0]`: `cmd` (`DP_CMD_SECRET_DIGEST`)
	- `in_vec[1]`: `secret_index` (`uint32_t`, 0..4)
- **Output**:
	- `out_vec[0]`: 32-byte digest buffer
- **Notes**:
	- The partition temporarily reconfigures SAU to allow NS access to SRAM1.
	- The first digest byte is overwritten with `0x75` before returning.

### `DP_CMD_DECRYPT_LATE_WEIGHTS` (current flow)
- **Purpose**: AES-128-CTR decrypt encrypted late weights into NS RAM.
- **Input**:
	- `in_vec[0]`: `cmd` (`DP_CMD_DECRYPT_LATE_WEIGHTS`)
	- `in_vec[1]`: ciphertext (late weights)
	- `in_vec[2]`: IV (16 bytes)
- **Output**:
	- `out_vec[0]`: plaintext buffer

### `DP_CMD_DECRYPT_MODEL` (deprecated)
- **Purpose**: legacy full-model decrypt.
- **Current behavior**: always returns `PSA_ERROR_NOT_SUPPORTED`.

## Crypto Details
- **Algorithm**: AES-128-CTR
- **Key**: static 16-byte key in `dummy_partition.c` (demo-only)
- **IV**: provided by NS via `late_wt_iv[]`

> For production: move keys to secure storage (ITS/PS), add integrity (AEAD/HMAC), and rotate keys.

## Files
- [dummy_partition.c](dummy_partition.c): command routing + AES-CTR decrypt
- [tfm_dummy_partition.yaml](tfm_dummy_partition.yaml): TF-M service manifest
- [tfm_manifest_list.yaml.in](tfm_manifest_list.yaml.in): manifest list for build

## Notes
Legacy model decryption is removed; `DP_CMD_DECRYPT_MODEL` returns `PSA_ERROR_NOT_SUPPORTED`.

