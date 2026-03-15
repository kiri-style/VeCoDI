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
#define DP_CMD_VALIDATE_M_UPDATE    11  /* Validate and decrypt M_update */
#define DP_CMD_SET_MAX_INFERENCES   12  /* Override max inferences and reset counter */
#define DP_CMD_SET_SESSION_KEY      13  /* Share ECDH session_key with Secure partition */
#define DP_CMD_SAU_REGISTER         14  /* Register enclave RAM window: in[1]={base(4)+size(4)} */
#define DP_CMD_SAU_CONTROL          15  /* SAU open/close: in[1]=cmd(1B): 1=CLOSE, 2=OPEN */
#define DP_CMD_GET_SAU_STATE        16  /* Return SAU state: state(1)+base(4)+size(4) */
#define DP_CMD_VALIDATE_BOOT_ENCLAVE_INFO 17  /* Recompute current EnclaveInfo and compare with boot-time sealed value */
#define DP_CMD_SAU_REGISTER_ROM     18  /* Register model ROM window: in[1]={base(4)+size(4)} */
#define DP_CMD_SAU_REGISTER_CODE    19  /* Register inference code window: in[1]={base(4)+size(4)} */
#define DP_CMD_SET_LATE_SECRET_HASH 20  /* Hash encrypted late weights into secure model_secret */

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

/* M_update payload limits */
#define M_UPDATE_NONCE_SIZE      12
#define M_UPDATE_TAG_SIZE        16
#define M_UPDATE_PK_V_SIZE       64
#define M_UPDATE_CERT_MAX_SIZE   128
#define M_UPDATE_PLAINTEXT_MIN   (4 + M_UPDATE_PK_V_SIZE + ENCLAVE_INFO_SIZE + 4)
#define M_UPDATE_PLAINTEXT_MAX   (M_UPDATE_PLAINTEXT_MIN + M_UPDATE_CERT_MAX_SIZE)

#ifdef __cplusplus
}
#endif

#endif /* DUMMY_PARTITION_H */
