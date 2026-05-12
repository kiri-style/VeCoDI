/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DUMMY_PARTITION_H
#define DUMMY_PARTITION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PSA IPC Command IDs */
#define DP_CMD_SECRET_DIGEST        0
#define DP_CMD_DECRYPT_MODEL        2
#define DP_CMD_DECRYPT_LATE_WEIGHTS 3
#define DP_CMD_GET_MAX_INFERENCES   4
#define DP_CMD_CHECK_INFERENCE_ALLOWED 5
#define DP_CMD_INCREMENT_COUNTER    6
#define DP_CMD_RESET_COUNTER        7
#define DP_CMD_GET_BENCHMARK        8
#define DP_CMD_RUN_INFERENCE        9   /* Atomic: check + increment counter */
#define DP_CMD_COMPUTE_ENCLAVE_INFO 10  /* Compute EnclaveInfo hash */
#define DP_CMD_VALIDATE_AUTHORIZE   11  /* Authorize: validate authorization token and refresh the provisioned policy context */
#define DP_CMD_SET_MAX_INFERENCES   12  /* Override max inferences and reset counter */
#define DP_CMD_SAU_REGISTER         14  /* Register enclave RAM window: in[1]={base(4)+size(4)} */
#define DP_CMD_SAU_CONTROL          15  /* SAU control: in[1]=cmd(1B): 1=CLOSE_RAM, 2=OPEN_RAM, 3=CLOSE_MODEL_RO, 4=OPEN_MODEL_RO */
#define DP_CMD_GET_SAU_STATE        16  /* Return SAU state: state(1)+base(4)+size(4) */
#define DP_CMD_VALIDATE_BOOT_ENCLAVE_INFO 17  /* Recompute current EnclaveInfo and compare with boot-time sealed value */
#define DP_CMD_SAU_REGISTER_ROM     18  /* Register model ROM window: in[1]={base(4)+size(4)} */
#define DP_CMD_SAU_REGISTER_CODE    19  /* Register inference code window: in[1]={base(4)+size(4)} */
#define DP_CMD_SET_LATE_SECRET_HASH 20  /* Hash encrypted late weights into secure model_secret */
#define DP_CMD_GET_SAU_ROM_STATE    21  /* Return ROM SAU state: state(1)+base(4)+size(4) */
#define DP_CMD_FINALIZE_CREATE_ENCLAVE 24 /* Close enclave RAM after create-time setup */
#define DP_CMD_INF_START            25  /* Verify M_inf in Secure and open transaction window */
#define DP_CMD_INF_COMPLETE         26  /* Commit secure transaction and sign PoX */
#define DP_CMD_GET_DEVICE_PUBKEY    27  /* Return secure device public key (65-byte uncompressed) */
#define DP_CMD_SIGN_ATTEST_MSG      28  /* Sign SHA256(nonce||enclave_info) with secure device key */

/* M_update auth-state response returned to NS after validate:
 * c_limit(4) + pk_v(64) + model_id(4) + cert_len(4) + cert(n, max 128) = 204 bytes */
#define M_UPDATE_AUTH_RESP_MAX  204

/* Service ID for Dummy Partition */
#define TFM_DP_SERVICE_SID 0xFFFFF002

/* Maximum inferences per enclave (initial value; updated by M_update validation). */
#define MAX_INFERENCES_PER_ENCLAVE  0

/* AES-256 key for M_update message encryption (predefined in Secure Flash) */
#define M_UPDATE_AES256_KEY_SIZE 32

/* EnclaveInfo size (SHA-256 hash) */
#define ENCLAVE_INFO_SIZE 32

/* Authorize payload limits */
#define AUTHORIZE_NONCE_SIZE      12
#define AUTHORIZE_TAG_SIZE        16
#define AUTHORIZE_PK_V_SIZE       64
#define AUTHORIZE_CERT_MAX_SIZE   128
#define AUTHORIZE_PLAINTEXT_MIN   (4 + AUTHORIZE_PK_V_SIZE + ENCLAVE_INFO_SIZE + 4)
#define AUTHORIZE_PLAINTEXT_MAX   (AUTHORIZE_PLAINTEXT_MIN + AUTHORIZE_CERT_MAX_SIZE)

/* Create API (Shangri-La semantics)
 *
 * This command initializes a Shangri-La instance (an enclave in our context)
 * from its provisioned configuration. Input: s_id identifying the instance.
 *
 * Semantics (high-level):
 *  - Retrieve memory region descriptors for F (code), data_pub (public data),
 *    and enc_data_priv (encrypted private data) from the instance context.
 *  - Ephemerally mark the code and data_pub regions as Secure using the
 *    platform SAU and, where available, the security DMA controller so they
 *    are protected from Normal World CPU and Non-Secure DMA accesses.
 *  - If enc_data_priv is present: allocate a secure data_priv region, ensure
 *    the allocated region resides in Non-Secure RAM that does not overlap any
 *    memory-mapped peripheral regions, ephemerally mark it Secure, and
 *    decrypt enc_data_priv into data_priv using the instance decryption key
 *    (k_dec). The decrypted private data remains Secure and is not readable
 *    by Normal World peripherals or DMA.
 *  - After successful placement and decryption, set the Shangri-La
 *    lifecycle state to Inactive (populated but not yet executable).
 *
 * Remark: F and its data are Secure after create-time but are never executed
 * while Secure; F is atomically restored to Non-Secure immediately before
 * execution to preserve integrity and maintain separation between the
 * Shangri-La instance and the Secure World TCB.
 */

/* Execute/Run API (Shangri-La semantics)
 *
 * This command performs a single F (function/model) invocation in the
 * Shangri-La instance with full verification and proof of execution.
 *
 * Input parameters (user message):
 *  - Post-execution counter u (usage counter to validate)
 *  - Function input InF (inference input data)
 *  - Hash H(s_id) of the instance identifier
 *  - Signature Tu of the message, produced by the user
 *
 * Validation checks (all must pass):
 *  1. Instance is in Inactive lifecycle state
 *  2. Counter u is consistent: u = usage + 1 (anti-replay)
 *  3. Invocation does not exceed c_limit (authorized quota)
 *  4. Authenticity of Tu verified using pk_u (user's public key)
 *
 * Execution flow:
 *  1. Disable interrupts (atomic critical section)
 *  2. Set instance lifecycle state to Active
 *  3. Allocate dedicated stack at fixed location in Normal World RAM,
 *     ensuring it does not overlap memory-mapped peripheral regions
 *  4. Atomically mark F, data_pub, and data_priv as Non-Secure
 *     using SAU and security DMA controller
 *  5. Call F entry point with input InF in Normal World context
 *  6. Once F execution completes, control returns to Secure World
 *     (enforced by NSC at F's exit point)
 *  7. Erase the execution stack
 *  8. Restore F, data_pub, and data_priv back to Secure state
 *  9. Increment usage counter atomically
 * 10. Set lifecycle state back to Inactive
 * 11. Re-enable interrupts
 *
 * Proof of execution (PoX):
 *  - If proof is requested, Secure World generates T_proof by signing:
 *    PoX_input = (F, u, data_id, InF, OutF)
 *    T_proof = sign(PoX_input, sk_Dev)
 *    where sk_Dev is the Device-bound attestation key (ECC-256)
 *  - Returns (T_proof, OutF) to the caller
 *
 * Security guarantees:
 *  - F is never executed or modified in Secure state (isolation preserved)
 *  - Stack is ephemeral and erased after each execution
 *  - Quota enforced via atomic counter increment
 *  - User authorization (Tu) required per invocation
 *  - Device attestation (T_proof) proves device executed F
 */

/* Destroy API (Shangri-La semantics)
 *
 * This command tears down a Shangri-La instance and releases all resources.
 * Upon invocation, Secure World erases all sensitive data in data_priv.
 * It then marks F, data_pub, and data_priv regions as Non-Secure, releasing
 * the memory back to the Normal World. Finally, it sets the Shangri-La
 * lifecycle state to Non-Exist.
 *
 * Execution flow:
 *  1. Verify enclave is in Inactive state (not executing)
 *  2. Securely erase all sensitive data in data_priv (zeroize)
 *  3. Mark F, data_pub, and data_priv regions as Non-Secure
 *     using SAU and security DMA controller
 *  4. Release SAU windows: memory returned to Normal World control
 *  5. Reset lifecycle state to Non-Exist
 *  6. Clear all enclave metadata and authorization state
 *
 * Security guarantees:
 *  - Sensitive private data is irreversibly erased (zeroized)
 *  - All protections removed: instance no longer isolated
 *  - Normal World can access/modify released memory regions
 *  - No further inferences possible until next Create
 *  - Lifecycle state prevents accidental operations on destroyed instance
 */

#ifdef __cplusplus
}
#endif

#endif /* DUMMY_PARTITION_H */
