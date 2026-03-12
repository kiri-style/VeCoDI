/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "psa/service.h"
#include "psa_manifest/tfm_dummy_partition.h"
#include "dummy_partition.h"

#include "stm32l5xx_hal_secure_sram.h"
#include "secure_benchmark.h"

/*
 * Dummy Partition (Secure) - TF-M IPC service
 *
 * Responsibilities:
 *  - Provide crypto-backed services (digest, decrypt) to the Non-Secure side.
 *  - Optionally simulate enclave sealing and secure memory handling.
 *  - Route IPC requests and enforce basic argument validation.
 */

/* Secure SRAM configuration hook provided by platform layer. */
extern int tfm_platform_secure_sram(uint32_t base, uint32_t size);

/* Secure linker symbols for memory stats. */
extern char __bss_start__;
extern char __bss_end__;

/*
 * Print basic secure memory stats to help verify secure memory placement.
 */
static void print_secure_memory_stats(void)
{
    uint32_t bss_size = (uint32_t)(&__bss_end__ - &__bss_start__);

    printf("\n======= SECURE MEMORY STATS =======\n");
    printf("  BSS size:   %u bytes\n", bss_size);
    printf("  BSS range:  %p - %p\n", &__bss_start__, &__bss_end__);
    printf("===================================\n\n");
}

#define NUM_SECRETS 5

/* IPC command IDs exposed by this partition. */
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
#define DP_CMD_SET_SESSION_KEY      13  /* Receive ECDH session_key from NS */

/* EnclaveInfo size (SHA-256 hash) */
#define ENCLAVE_INFO_SIZE 32

/* Secure inference counter and dynamic max limit (protected). */
static uint32_t inference_counter_secure = 0;
static uint32_t max_inferences_per_enclave_secure = 0; /* Start at 0 until M_update accepted */

/* Anti-replay counter limit for M_update validation (secure state). */
static uint32_t last_accepted_counter_limit = 0;

/* Cached model identity for EnclaveInfo recomputation (secure state). */
static uint8_t current_model_pub[32];
static uint8_t current_model_secret[32];
static uint8_t current_code_hash[32];
static uint32_t current_model_id = 0;
static bool current_model_info_valid = false;

/* ECDH session key shared by NS after handshake — used to decrypt M_update. */
static uint8_t  secure_session_key[32] = {0};
static bool     secure_session_key_set  = false;

/* Authorization state extracted from M_update plaintext (authoritative Secure copy). */
static uint8_t  s_pk_v[64]    = {0};
static uint32_t s_model_id    = 0;
static uint8_t  s_cert[128]   = {0};
static uint32_t s_cert_len    = 0;
static bool     s_auth_valid  = false;

/* Fixed-size secret container used for digest service. */
struct dp_secret {
	uint8_t secret[16];
};

/* Static AES-CTR key used for late-weights decryption (128-bit). */
static const uint8_t aes_key[16] = {
    0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,
    0x1C,0x1D,0x1E,0x1F
};

/* Static AES-256 key for M_update message encryption (predefined in Secure Flash). */
static const uint8_t m_update_aes256_key[32] = {
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
    0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
};

/* M_update sizes and limits */
#define M_UPDATE_NONCE_SIZE      12
#define M_UPDATE_TAG_SIZE        16
#define M_UPDATE_PK_V_SIZE       64
#define M_UPDATE_CERT_MAX_SIZE   128
#define M_UPDATE_PLAINTEXT_MIN   (4 + M_UPDATE_PK_V_SIZE + ENCLAVE_INFO_SIZE + 4)
#define M_UPDATE_PLAINTEXT_MAX   (M_UPDATE_PLAINTEXT_MIN + M_UPDATE_CERT_MAX_SIZE)
#define M_UPDATE_CIPHERTEXT_MAX  (M_UPDATE_PLAINTEXT_MAX)
#define M_UPDATE_CIPHERTEXT_MIN  (M_UPDATE_PLAINTEXT_MIN)

/* Constant-time buffer comparison. Returns 1 if equal, 0 otherwise. */
static int secure_memequal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0);
}

/* Securely zero memory to avoid compiler optimizations. */
static void secure_memzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* Example secrets for digest requests. */
struct dp_secret secrets[NUM_SECRETS] = {
	{ {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
};

/* Callback signature used to return a digest to the caller. */
typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
                     uint32_t digest_size);

/*
 * Compute SHA-256 digest for a selected secret and return it via callback.
 */
static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
            size_t digest_size, size_t *p_digest_size,
            psa_write_callback_t callback, void *handle)
{
	uint8_t digest[32];
	psa_status_t status;

	/* Check that secret_index is valid. */
	if (secret_index >= NUM_SECRETS) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* Check that digest_size is valid. */
	if (digest_size != sizeof(digest)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	SECURE_BENCHMARK_START(digest_start);
	status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
				sizeof(secrets[secret_index].secret), digest,
				digest_size, p_digest_size);
	SECURE_BENCHMARK_END(digest_start, digest_compute_cycles);
	g_secure_metrics.digest_count++;

	if (status != PSA_SUCCESS) {
		return status;
	}
	if (*p_digest_size != digest_size) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	callback(handle, digest, digest_size);

	return PSA_SUCCESS;
}


/*
 * Compute EnclaveInfo = SHA-256(Model_pub || Model_secret || code || model_ID)
 * Binary concatenation of all fields.
 * 
 * Parameters:
 *  model_pub:     Model public key (32 bytes, ECDSA P-256)
 *  model_secret:  Model secret (32 bytes)
 *  code:          Model code/executable hash (32 bytes SHA-256)
 *  model_id:      Model ID (4 bytes, uint32_t)
 * Output:
 *  enclave_info:  32-byte SHA-256 hash
 */
static psa_status_t compute_enclave_info(
    const uint8_t *model_pub,      /* 32 bytes */
    const uint8_t *model_secret,   /* 32 bytes */
    const uint8_t *code,           /* 32 bytes */
    uint32_t model_id,             /* 4 bytes */
    uint8_t *enclave_info)         /* output: 32 bytes */
{
    psa_status_t status;
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
    size_t hash_len = 0;

    /* Binary concatenation: model_pub || model_secret || code || model_id (little-endian). */
    
    status = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Update with Model_pub (32 bytes). */
    status = psa_hash_update(&hash_op, model_pub, 32);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&hash_op);
        return status;
    }

    /* Update with Model_secret (32 bytes). */
    status = psa_hash_update(&hash_op, model_secret, 32);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&hash_op);
        return status;
    }

    /* Update with code hash (32 bytes). */
    status = psa_hash_update(&hash_op, code, 32);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&hash_op);
        return status;
    }

    /* Update with model_id (4 bytes, little-endian). */
    uint8_t id_bytes[4];
    id_bytes[0] = (model_id >> 0) & 0xFF;
    id_bytes[1] = (model_id >> 8) & 0xFF;
    id_bytes[2] = (model_id >> 16) & 0xFF;
    id_bytes[3] = (model_id >> 24) & 0xFF;
    
    status = psa_hash_update(&hash_op, id_bytes, 4);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&hash_op);
        return status;
    }

    /* Finalize SHA-256 hash. */
    status = psa_hash_finish(&hash_op, enclave_info, 32, &hash_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (hash_len != 32) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    return PSA_SUCCESS;
}

/*
 * Validate M_update payload in Secure World.
 *
 * Input vectors:
 *  in[0] = cmd (4 bytes)
 *  in[1] = nonce (12 bytes)
 *  in[2] = ciphertext (variable size)
 *  in[3] = tag (16 bytes)
 *
 * Operation:
 *  - AES-256-GCM decrypt with m_update_aes256_key
 *  - Parse plaintext: c_limit || pk_v || enclave_info || cert_len || cert
 *  - Recompute EnclaveInfo and compare (constant-time)
 *  - Anti-replay: c_limit must be strictly increasing
 */
static psa_status_t tfm_dp_validate_m_update(psa_msg_t *msg)
{
    psa_status_t status = PSA_SUCCESS;

    if (!secure_session_key_set) {
        printf("[SECURE] M_update rejected: session_key not set\n");
        return PSA_ERROR_BAD_STATE;
    }
    if (!current_model_info_valid) {
        printf("[SECURE] M_update rejected: EnclaveInfo not yet computed\n");
        return PSA_ERROR_BAD_STATE;
    }

    /* in[1] = full raw packet: nonce(12) || ciphertext || tag(16) */
    size_t pkt_len = msg->in_size[1];
    if (pkt_len < (size_t)(M_UPDATE_NONCE_SIZE + M_UPDATE_TAG_SIZE + M_UPDATE_PLAINTEXT_MIN) ||
        pkt_len > (size_t)(M_UPDATE_NONCE_SIZE + M_UPDATE_CIPHERTEXT_MAX + M_UPDATE_TAG_SIZE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* out[0] must fit: c_limit(4)+pk_v(64)+model_id(4)+cert_len(4)+cert(max 128) = 204 */
    if (msg->out_size[0] < (4U + M_UPDATE_PK_V_SIZE + 4U + 4U)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Read full packet (nonce || ciphertext || tag) */
    uint8_t packet[M_UPDATE_NONCE_SIZE + M_UPDATE_CIPHERTEXT_MAX + M_UPDATE_TAG_SIZE];
    psa_read(msg->handle, 1, packet, pkt_len);

    uint8_t *nonce   = packet;
    size_t   ct_len  = pkt_len - M_UPDATE_NONCE_SIZE - M_UPDATE_TAG_SIZE;
    /* ciphertext||tag sit contiguously right after nonce */
    uint8_t *ct_tag  = packet + M_UPDATE_NONCE_SIZE;

    /* AES-256-GCM decrypt with stored session_key */
    uint8_t plaintext[M_UPDATE_PLAINTEXT_MAX];
    size_t  plaintext_len = 0;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) { return status; }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_key_id_t key_id;
    status = psa_import_key(&attr, secure_session_key, 32, &key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) { return status; }

    status = psa_aead_decrypt(
        key_id, PSA_ALG_GCM,
        nonce, M_UPDATE_NONCE_SIZE,
        NULL, 0,
        ct_tag, ct_len + M_UPDATE_TAG_SIZE,
        plaintext, sizeof(plaintext),
        &plaintext_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        printf("[SECURE] M_update AES-GCM decrypt failed: %d\n", (int)status);
        secure_memzero(plaintext, sizeof(plaintext));
        secure_memzero(packet, pkt_len);
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    /* Parse plaintext: c_limit(4) | pk_v(64) | enclave_info(32) | cert_len(4) | cert(n) */
    if (plaintext_len < M_UPDATE_PLAINTEXT_MIN || plaintext_len > M_UPDATE_PLAINTEXT_MAX) {
        secure_memzero(plaintext, sizeof(plaintext));
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t   off      = 0;
    uint32_t c_limit  = 0;
    uint32_t cert_len_val = 0;

    memcpy(&c_limit,       &plaintext[off], 4); off += 4;
    uint8_t *pk_v_ptr          = &plaintext[off]; off += M_UPDATE_PK_V_SIZE;
    uint8_t *enclave_info_rcvd = &plaintext[off]; off += ENCLAVE_INFO_SIZE;
    memcpy(&cert_len_val,  &plaintext[off], 4); off += 4;

    if (cert_len_val > M_UPDATE_CERT_MAX_SIZE || (off + cert_len_val) != plaintext_len) {
        secure_memzero(plaintext, sizeof(plaintext));
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    uint8_t *cert_ptr = &plaintext[off];

    /* Recompute EnclaveInfo and compare (constant-time). */
    uint8_t enclave_info_cur[ENCLAVE_INFO_SIZE];
    status = compute_enclave_info(current_model_pub, current_model_secret,
                                  current_code_hash, current_model_id,
                                  enclave_info_cur);
    if (status != PSA_SUCCESS) {
        secure_memzero(plaintext, sizeof(plaintext));
        return status;
    }
    if (!secure_memequal(enclave_info_rcvd, enclave_info_cur, ENCLAVE_INFO_SIZE)) {
        printf("[SECURE] M_update EnclaveInfo mismatch\n");
        secure_memzero(plaintext, sizeof(plaintext));
        secure_memzero(enclave_info_cur, sizeof(enclave_info_cur));
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Anti-replay: c_limit must be strictly increasing. */
    if (c_limit <= last_accepted_counter_limit) {
        secure_memzero(plaintext, sizeof(plaintext));
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* All checks passed — update Secure state atomically. */
    last_accepted_counter_limit       = c_limit;
    max_inferences_per_enclave_secure = c_limit;
    inference_counter_secure          = 0;

    /* Store auth fields in Secure (authoritative copy). */
    memcpy(s_pk_v, pk_v_ptr, M_UPDATE_PK_V_SIZE);
    s_cert_len = cert_len_val;
    memcpy(s_cert, cert_ptr, cert_len_val);
    s_model_id = 0;
    if (cert_len_val >= 4U) {
        s_model_id = (uint32_t)cert_ptr[0]
                   | ((uint32_t)cert_ptr[1] << 8)
                   | ((uint32_t)cert_ptr[2] << 16)
                   | ((uint32_t)cert_ptr[3] << 24);
    }
    s_auth_valid = true;

    printf("[SECURE] M_update OK: c_limit=%u, model_id=%u, cert_len=%u\n",
           c_limit, s_model_id, s_cert_len);

    /* Build auth-state response: c_limit(4) + pk_v(64) + model_id(4) + cert_len(4) + cert(n) */
    uint8_t resp[4U + M_UPDATE_PK_V_SIZE + 4U + 4U + M_UPDATE_CERT_MAX_SIZE];
    size_t  roff = 0;
    memcpy(resp + roff, &c_limit,    4); roff += 4;
    memcpy(resp + roff, s_pk_v,      M_UPDATE_PK_V_SIZE); roff += M_UPDATE_PK_V_SIZE;
    memcpy(resp + roff, &s_model_id, 4); roff += 4;
    memcpy(resp + roff, &s_cert_len, 4); roff += 4;
    if (s_cert_len > 0U) {
        memcpy(resp + roff, s_cert, s_cert_len); roff += s_cert_len;
    }

    if (msg->out_size[0] >= roff) {
        psa_write(msg->handle, 0, resp, roff);
    }

    /* Zeroize sensitive data. */
    secure_memzero(plaintext,        sizeof(plaintext));
    secure_memzero(packet,           pkt_len);
    secure_memzero(enclave_info_cur, sizeof(enclave_info_cur));
    secure_memzero(resp,             sizeof(resp));

    return PSA_SUCCESS;
}

/*
 * Decrypt late weights using AES-CTR.
 * Input:  encrypted blob (in[1]) + IV (in[2])
 * Output: decrypted bytes (out[0])
 */
static psa_status_t tfm_dp_decrypt_late_weights(psa_msg_t *msg)
{
    if (msg->in_size[1] == 0 || msg->out_size[0] == 0 || msg->in_size[2] != 16) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    SECURE_BENCHMARK_START(aes_start);
    
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CTR);

    psa_key_id_t key_id;
    status = psa_import_key(&attr, aes_key, sizeof(aes_key), &key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        return status;
    }

    uint8_t iv[16];
    psa_read(msg->handle, 2, iv, sizeof(iv));

    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    status = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CTR);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return status;
    }

    status = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&op);
        psa_destroy_key(key_id);
        return status;
    }

    size_t total = msg->in_size[1];
    size_t processed = 0;
    uint8_t in_buf[256];
    uint8_t out_buf[256];

    while (processed < total) {
        size_t chunk = (total - processed > sizeof(in_buf)) ? sizeof(in_buf) : (total - processed);
        psa_read(msg->handle, 1, in_buf, chunk);

        size_t out_len = 0;
        status = psa_cipher_update(&op, in_buf, chunk, out_buf, sizeof(out_buf), &out_len);
        if (status != PSA_SUCCESS) {
            psa_cipher_abort(&op);
            psa_destroy_key(key_id);
            return status;
        }

        psa_write(msg->handle, 0, out_buf, out_len);
        processed += chunk;
    }

    size_t finish_len = 0;
    status = psa_cipher_finish(&op, out_buf, sizeof(out_buf), &finish_len);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&op);
        psa_destroy_key(key_id);
        return status;
    }

    if (finish_len > 0) {
        psa_write(msg->handle, 0, out_buf, finish_len);
    }

    psa_destroy_key(key_id);
    
    SECURE_BENCHMARK_END(aes_start, aes_decrypt_cycles);
    g_secure_metrics.aes_decrypt_count++;
    
    return PSA_SUCCESS;
}

/* Handler signature for IPC calls. */
typedef psa_status_t (*dp_func_t)(psa_msg_t *);

#define SRAM1_START  0x20000000
#define SRAM1_END    0x20010000

/* SAU helper utilities for temporary NS access to SRAM1. */
__always_inline void rtpox_sau_disable(void){
    // Disable SAU
    SAU->CTRL &= ~SAU_CTRL_ENABLE_Msk ;
}

__always_inline void rtpox_sau_enable(void){
    // Enable SAU
    SAU->CTRL |= SAU_CTRL_ENABLE_Msk ;
}

__always_inline void rtpox_configure_sau_nonsecure(uint32_t address_init, uint32_t address_end, uint32_t region_number){
    SAU->RNR  = region_number;
    SAU->RBAR = address_init & SAU_RBAR_BADDR_Msk;
    SAU->RLAR = (address_end & SAU_RLAR_LADDR_Msk) & ~SAU_RLAR_ENABLE_Msk;
    __DSB();
    __ISB();
}

__always_inline void rtpox_configure_sau_secure(uint32_t address_init, uint32_t address_end, uint32_t region_number){
    SAU->RNR  = region_number;
    SAU->RBAR = address_init & SAU_RBAR_BADDR_Msk;
    SAU->RLAR = (address_end & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk;
    __DSB();
    __ISB();
}

/* Write digest back to caller, ensuring NS can read SRAM1 region. */
static void psa_write_digest(void *handle, uint8_t *digest,
                 uint32_t digest_size)
{
    rtpox_sau_disable();    
	rtpox_configure_sau_nonsecure(SRAM1_START, SRAM1_END, 6);
    rtpox_sau_enable();   
	digest[0] = 0x75;
	psa_write((psa_handle_t)handle, 0, digest, digest_size);
}

/*
 * IPC dispatcher for secret digest and other partition commands.
 */
static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
{
    uint32_t cmd;

    if (msg->in_size[0] != sizeof(cmd)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    psa_read(msg->handle, 0, &cmd, sizeof(cmd));

    switch (cmd)
    {
        case DP_CMD_SECRET_DIGEST:
        {
            uint32_t secret_index;

            if (msg->in_size[1] != sizeof(secret_index)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            psa_read(msg->handle, 1,
                     &secret_index,
                     sizeof(secret_index));

            return tfm_dp_secret_digest(
                secret_index,
                msg->out_size[0],
                &msg->out_size[0],
                psa_write_digest,
                (void *)msg->handle);
        }

        case DP_CMD_DECRYPT_LATE_WEIGHTS:
            return tfm_dp_decrypt_late_weights(msg);

    case DP_CMD_DECRYPT_MODEL:
        printf("[SECURE] Model decryption is deprecated (AES-only flow).\n");
        return PSA_ERROR_NOT_SUPPORTED;

    case DP_CMD_GET_MAX_INFERENCES:
        {
            SECURE_BENCHMARK_START(get_max_start);
            uint32_t max_inf = max_inferences_per_enclave_secure;
            psa_write(msg->handle, 0, &max_inf, sizeof(max_inf));
            SECURE_BENCHMARK_END(get_max_start, get_max_cycles);
            g_secure_metrics.counter_operations++;
            printf("[SECURE] Returned max inferences: %u\n", max_inf);
            return PSA_SUCCESS;
        }

    case DP_CMD_CHECK_INFERENCE_ALLOWED:
        {
            SECURE_BENCHMARK_START(check_start);
            uint32_t allowed = (inference_counter_secure + 1 <= max_inferences_per_enclave_secure) ? 1 : 0;
            psa_write(msg->handle, 0, &allowed, sizeof(allowed));
            SECURE_BENCHMARK_END(check_start, check_allowed_cycles);
            g_secure_metrics.counter_operations++;
            printf("[SECURE] Check inference allowed: counter=%u, max=%u, allowed=%u\n", 
                   inference_counter_secure, max_inferences_per_enclave_secure, allowed);
            return PSA_SUCCESS;
        }

    case DP_CMD_INCREMENT_COUNTER:
        {
            SECURE_BENCHMARK_START(inc_start);
            inference_counter_secure++;
            SECURE_BENCHMARK_END(inc_start, increment_cycles);
            g_secure_metrics.counter_operations++;
            printf("[SECURE] Inference counter incremented: %u\n", inference_counter_secure);
            return PSA_SUCCESS;
        }

    case DP_CMD_RESET_COUNTER:
        {
            SECURE_BENCHMARK_START(reset_start);
            inference_counter_secure = 0;
            SECURE_BENCHMARK_END(reset_start, reset_cycles);
            g_secure_metrics.counter_operations++;
            printf("[SECURE] Inference counter reset to 0\n");
            return PSA_SUCCESS;
        }
    
    case DP_CMD_GET_BENCHMARK:
        {
            /* Return Secure benchmark metrics to NS */
            if (msg->out_size[0] != sizeof(g_secure_metrics)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            
            /* Update memory usage before sending */
            secure_benchmark_get_memory_usage(&g_secure_metrics.ram_used_bytes,
                                             &g_secure_metrics.ram_total_bytes,
                                             &g_secure_metrics.flash_used_bytes,
                                             &g_secure_metrics.flash_total_bytes);
            
            psa_write(msg->handle, 0, &g_secure_metrics, sizeof(g_secure_metrics));
            printf("[SECURE] Benchmark metrics sent to NS\n");
            return PSA_SUCCESS;
        }
    
    case DP_CMD_RUN_INFERENCE:
        {
            /* Atomic operation: Check if inference allowed + Increment counter */
            uint32_t allowed = (inference_counter_secure + 1 <= max_inferences_per_enclave_secure) ? 1 : 0;
            
            if (allowed) {
                /* Increment counter atomically */
                inference_counter_secure++;
                  printf("[SECURE] Inference ALLOWED and counter incremented: %u/%u\n", 
                      inference_counter_secure, max_inferences_per_enclave_secure);
            } else {
                  printf("[SECURE] Inference DENIED (counter limit reached: %u/%u)\n",
                      inference_counter_secure, max_inferences_per_enclave_secure);
            }
            
            /* Write result back to NS */
            if (msg->out_size[0] != sizeof(allowed)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            psa_write(msg->handle, 0, &allowed, sizeof(allowed));
            g_secure_metrics.counter_operations++;
            
            return PSA_SUCCESS;
        }

    case DP_CMD_COMPUTE_ENCLAVE_INFO:
        {
            /* Compute EnclaveInfo = SHA-256(Model_pub || Model_secret || code || model_ID)
             * Input format:
             *  in[0] = cmd (4 bytes)
             *  in[1] = combined_data = model_pub(32) || model_secret(32) || code(32) = 96 bytes
             *  in[2] = model_id (4 bytes)
             * Output:
             *  out[0] = enclave_info (32 bytes)
             */
            printf("[SECURE] DP_CMD_COMPUTE_ENCLAVE_INFO received\n");
            printf("[SECURE]   in_size[0]=%zu (cmd), in_size[1]=%zu (combined), in_size[2]=%zu (model_id)\n",
                   msg->in_size[0], msg->in_size[1], msg->in_size[2]);
            printf("[SECURE]   out_size[0]=%zu (enclave_info)\n", msg->out_size[0]);
            
            /* Validate input and output sizes */
            if (msg->in_size[1] != 96 || msg->in_size[2] != 4) {
                printf("[SECURE]   ERROR: Invalid input sizes (expected 96 and 4, got %zu and %zu)\n", 
                       msg->in_size[1], msg->in_size[2]);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            if (msg->out_size[0] != 32) {
                printf("[SECURE]   ERROR: Invalid output size\n");
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint8_t combined_data[96];
            uint32_t model_id;
            uint8_t enclave_info[32];

            /* Read from buffer indices 1-2 (skipping command at index 0) */
            psa_read(msg->handle, 1, combined_data, 96);
            psa_read(msg->handle, 2, &model_id, 4);

            /* Extract components from combined data */
            uint8_t *model_pub = &combined_data[0];       /* bytes 0-31 */
            uint8_t *model_secret = &combined_data[32];   /* bytes 32-63 */
            uint8_t *code = &combined_data[64];           /* bytes 64-95 */

            /* Cache current model identity for later EnclaveInfo validation. */
            memcpy(current_model_pub, model_pub, 32);
            memcpy(current_model_secret, model_secret, 32);
            memcpy(current_code_hash, code, 32);
            current_model_id = model_id;
            current_model_info_valid = true;

            printf("[SECURE] Computing EnclaveInfo for model_id=%u\n", model_id);
            
            psa_status_t status = compute_enclave_info(model_pub, model_secret, code, model_id, enclave_info);
            if (status != PSA_SUCCESS) {
                printf("[SECURE]   ERROR: compute_enclave_info failed: %d\n", status);
                return status;
            }

            psa_write(msg->handle, 0, enclave_info, 32);
            printf("[SECURE]   ✓ EnclaveInfo computed successfully\n");
            printf("[SECURE]   EnclaveInfo (first 16 bytes): ");
            for (int i = 0; i < 16; i++) printf("%02X ", enclave_info[i]);
            printf("\n");
            return PSA_SUCCESS;
        }

    case DP_CMD_SET_SESSION_KEY:
        {
            /* NS shares ECDH-derived session_key so Secure can decrypt M_update. */
            if (msg->in_size[1] != 32U) {
                printf("[SECURE] DP_CMD_SET_SESSION_KEY: bad size %zu\n", msg->in_size[1]);
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            psa_read(msg->handle, 1, secure_session_key, 32);
            secure_session_key_set = true;
            s_auth_valid = false;  /* new session invalidates previous M_update */
            printf("[SECURE] DP_CMD_SET_SESSION_KEY: session key stored\n");
            return PSA_SUCCESS;
        }

    case DP_CMD_VALIDATE_M_UPDATE:
        {
            printf("[SECURE] DP_CMD_VALIDATE_M_UPDATE received\n");
            printf("[SECURE]   in_size[0]=%zu (nonce), in_size[1]=%zu (ciphertext), in_size[2]=%zu (tag)\n",
                   msg->in_size[0], msg->in_size[1], msg->in_size[2]);
            return tfm_dp_validate_m_update(msg);
        }

    case DP_CMD_SET_MAX_INFERENCES:
        {
            uint32_t new_max = 0;

            if (msg->in_size[1] != sizeof(new_max)) {
                printf("[SECURE] DP_CMD_SET_MAX_INFERENCES invalid size=%zu\n", msg->in_size[1]);
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            psa_read(msg->handle, 1, &new_max, sizeof(new_max));
            if (new_max == 0U) {
                printf("[SECURE] DP_CMD_SET_MAX_INFERENCES invalid value=0\n");
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            max_inferences_per_enclave_secure = new_max;
            inference_counter_secure = 0U;
            g_secure_metrics.counter_operations++;

            printf("[SECURE] Max inferences overridden: max=%u, counter reset\n", new_max);
            return PSA_SUCCESS;
        }

    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}



/*
 * Generic signal handler for TF-M IPC lifecycle (connect/call/disconnect).
 */
static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	status = psa_get(signal, &msg);
	switch (msg.type) {
	case PSA_IPC_CONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	default:
		psa_panic();
	}
}



/*
 * Partition entry point: waits for incoming IPC signals and dispatches.
 */
psa_status_t tfm_dp_req_mngr_init(void)
{
	psa_signal_t signals = 0;

    printf("\n[SECURE INIT] Dummy partition init\n");
    print_secure_memory_stats();
    
    /* Initialize Secure benchmark system */
    secure_benchmark_init();

	while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

        if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
            dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
                            tfm_dp_secret_digest_ipc);
        }
    
        else {
            psa_panic();
        }
    }

	return PSA_ERROR_SERVICE_FAILURE;
}