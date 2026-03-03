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

/* Service ID for Dummy Partition */
#define TFM_DP_SERVICE_SID 0xFFFFF002

/* Maximum inferences per enclave (initial value; updated by M_update validation). */
#define MAX_INFERENCES_PER_ENCLAVE  0

/* AES-256 key for M_update message encryption (predefined in Secure Flash) */
#define M_UPDATE_AES256_KEY_SIZE 32
extern const uint8_t m_update_aes256_key[32];

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
