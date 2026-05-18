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
#define DP_CMD_VALIDATE_AUTHORIZE   11  /* Validate Authorize (plaintext M_update, verify T_o signature) */
#define DP_CMD_SET_MAX_INFERENCES   12  /* Override max inferences and reset counter */
#define DP_CMD_VALIDATE_BOOT_ENCLAVE_INFO 17  /* Recompute current EnclaveInfo and compare with boot-time sealed value */
#define DP_CMD_SAU_REGISTER_ROM     18  /* Register model ROM window */
#define DP_CMD_SAU_REGISTER_CODE    19  /* Register inference code window */
#define DP_CMD_SET_LATE_SECRET_HASH 20  /* Hash encrypted late weights as model_secret */
#define DP_CMD_CREATE_ENCLAVE       22  /* Secure create: decrypt + register + reset counter (RAM still open) */
#define DP_CMD_DESTROY_ENCLAVE      23  /* Secure destroy: close SAU + reset state */
#define DP_CMD_FINALIZE_CREATE_ENCLAVE 24 /* Secure finalize create: close enclave RAM */
#define DP_CMD_INF_START            25  /* Verify M_inf in Secure and open transaction window */
#define DP_CMD_INF_COMPLETE         26  /* Commit secure transaction and sign PoX */
#define DP_CMD_GET_DEVICE_PUBKEY    27  /* Return secure device public key (65-byte uncompressed) */
#define DP_CMD_SIGN_ATTEST_MSG      28  /* Sign SHA256(nonce||enclave_info) with secure device key */

/* EnclaveInfo size (SHA-256 hash) */
#define ENCLAVE_INFO_SIZE 32

/* Secure inference counter and dynamic max limit (protected). */
static uint32_t inference_counter_secure = 0;
static uint32_t max_inferences_per_enclave_secure = 0; /* Start at 0 until Authorize accepted */
static bool shangri_la_created_secure = false;

/* Anti-replay counter limit for Authorize validation (secure state). */
static uint32_t last_accepted_counter_limit = 0;

/* Cached model identity for EnclaveInfo recomputation (secure state). */
static uint8_t current_model_pub[32];
static uint8_t current_model_secret[32];
static uint8_t current_code_hash[32];
static uint32_t current_model_id = 0;
static bool current_model_info_valid = false;
static bool current_model_secret_valid = false;
static uint8_t current_enclave_info[ENCLAVE_INFO_SIZE];
static bool current_enclave_info_valid = false;
static uint8_t boot_enclave_info[ENCLAVE_INFO_SIZE];
static bool boot_enclave_info_valid = false;

/* Registered NS FLASH windows used to bind EnclaveInfo to real artifacts. */
static uint32_t sau_rom_base = 0U;
static uint32_t sau_rom_size = 0U;
static bool     sau_rom_registered = false;
static uint32_t sau_code_base = 0U;
static uint32_t sau_code_size = 0U;
static bool     sau_code_registered = false;

/* Default secure-only model identity (used when host does not provide details). */
static const uint32_t default_model_id = 0x00000001U;

static psa_status_t compute_enclave_info(
    const uint8_t *model_pub,
    const uint8_t *model_secret,
    const uint8_t *code,
    uint32_t model_id,
    uint8_t *enclave_info);

static void init_secure_model_identity(void)
{
    memset(current_model_pub, 0, sizeof(current_model_pub));
    memset(current_model_secret, 0, sizeof(current_model_secret));
    memset(current_code_hash, 0, sizeof(current_code_hash));
    current_model_id = default_model_id;
    current_model_info_valid = true;
    current_model_secret_valid = false;
    current_enclave_info_valid = false;
    boot_enclave_info_valid = false;

    printf("[SECURE] Model identity context initialized (model_id=%u)\n", current_model_id);
}

/* Static session key used to decrypt M_inf (verified inference) payloads with AES-256-GCM. */
static const uint8_t secure_session_key[32] = {
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
    0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
};

/* Authorization state extracted from Authorize plaintext (authoritative Secure copy). */
static uint8_t  s_pk_u[64]    = {0};  /* User public key (not certificate) */
static uint32_t s_model_id    = 0;
static bool     s_auth_valid  = false;

/* Secure-only device signing key and transient inference transaction state. */
static psa_key_id_t s_device_sign_key_id = 0;
static uint8_t      s_device_pubkey[65] = {0};
static bool         s_device_key_ready = false;
static bool         s_tx_active = false;
static uint32_t     s_tx_id = 0U;
static uint8_t      s_tx_code_hash[32] = {0};
static uint32_t     s_tx_model_id = 0U;

static void reset_secure_inference_tx_state(void)
{
    s_tx_active = false;
    memset(s_tx_code_hash, 0, sizeof(s_tx_code_hash));
    s_tx_model_id = 0U;
}

static psa_status_t init_secure_device_signing_key(void)
{
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        return st;
    }

    if (s_device_key_ready && s_device_sign_key_id != 0U) {
        return PSA_SUCCESS;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_generate_key(&attr, &s_device_sign_key_id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        return st;
    }

    size_t pk_len = 0U;
    st = psa_export_public_key(s_device_sign_key_id,
                               s_device_pubkey,
                               sizeof(s_device_pubkey),
                               &pk_len);
    if (st != PSA_SUCCESS || pk_len != sizeof(s_device_pubkey)) {
        if (s_device_sign_key_id != 0U) {
            psa_destroy_key(s_device_sign_key_id);
            s_device_sign_key_id = 0;
        }
        return (st == PSA_SUCCESS) ? PSA_ERROR_GENERIC_ERROR : st;
    }

    s_device_key_ready = true;
    return PSA_SUCCESS;
}

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

/* Authorize sizes and limits (M_update is now plaintext, not encrypted) */
#define AUTHORIZE_PK_U_SIZE       64  /* User public key */
#define AUTHORIZE_SIGNATURE_SIZE  64  /* ECDSA P-256 signature (r||s) */
#define AUTHORIZE_PLAINTEXT_SIZE  (AUTHORIZE_PK_U_SIZE + 4 + ENCLAVE_INFO_SIZE + AUTHORIZE_SIGNATURE_SIZE)

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

static psa_status_t hash_region_chunked(const uint8_t *ptr, size_t len, uint8_t out_hash[32])
{
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        return status;
    }

    const size_t chunk_size = 512U;
    size_t processed = 0U;
    while (processed < len) {
        size_t chunk = (len - processed > chunk_size) ? chunk_size : (len - processed);
        status = psa_hash_update(&op, ptr + processed, chunk);
        if (status != PSA_SUCCESS) {
            psa_hash_abort(&op);
            return status;
        }
        processed += chunk;
    }

    size_t hash_len = 0U;
    status = psa_hash_finish(&op, out_hash, 32U, &hash_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (hash_len != 32U) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    return PSA_SUCCESS;
}

static psa_status_t refresh_model_pub_from_rom(void)
{
    if (!sau_rom_registered || sau_rom_size == 0U) {
        /* NS SAU registration is disabled by hardened policy.
         * Keep EnclaveInfo computation available using a deterministic fallback. */
        memset(current_model_pub, 0, sizeof(current_model_pub));
        return PSA_SUCCESS;
    }
    const uint8_t *rom_ptr = (const uint8_t *)(uintptr_t)sau_rom_base;
    return hash_region_chunked(rom_ptr, sau_rom_size, current_model_pub);
}

static psa_status_t refresh_code_hash_from_registered_code(void)
{
    if (!sau_code_registered || sau_code_size == 0U) {
        /* NS SAU registration is disabled by hardened policy.
         * Keep EnclaveInfo computation available using a deterministic fallback. */
        memset(current_code_hash, 0, sizeof(current_code_hash));
        return PSA_SUCCESS;
    }
    const uint8_t *code_ptr = (const uint8_t *)(uintptr_t)sau_code_base;
    return hash_region_chunked(code_ptr, sau_code_size, current_code_hash);
}

static psa_status_t recompute_current_enclave_info(void)
{
    if (!current_model_info_valid || !current_model_secret_valid) {
        return PSA_ERROR_BAD_STATE;
    }

    psa_status_t st = refresh_model_pub_from_rom();
    if (st != PSA_SUCCESS) {
        return st;
    }

    st = refresh_code_hash_from_registered_code();
    if (st != PSA_SUCCESS) {
        return st;
    }

    st = compute_enclave_info(current_model_pub,
                              current_model_secret,
                              current_code_hash,
                              current_model_id,
                              current_enclave_info);
    if (st == PSA_SUCCESS) {
        current_enclave_info_valid = true;
    }
    return st;
}

static psa_status_t seal_boot_enclave_info_once(void)
{
    if (boot_enclave_info_valid) {
        return PSA_SUCCESS;
    }

    psa_status_t st = recompute_current_enclave_info();
    if (st != PSA_SUCCESS) {
        return st;
    }

    memcpy(boot_enclave_info, current_enclave_info, ENCLAVE_INFO_SIZE);
    boot_enclave_info_valid = true;
    printf("[SECURE] Boot-time EnclaveInfo sealed\n");
    return PSA_SUCCESS;
}

static psa_status_t validate_current_enclave_info_against_boot(uint8_t *match_out)
{
    if (match_out == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t st = seal_boot_enclave_info_once();
    if (st != PSA_SUCCESS) {
        return st;
    }

    st = recompute_current_enclave_info();
    if (st != PSA_SUCCESS) {
        return st;
    }

    *match_out = secure_memequal(current_enclave_info,
                                 boot_enclave_info,
                                 ENCLAVE_INFO_SIZE) ? 1U : 0U;
    return PSA_SUCCESS;
}

/*
 * Secure-side implementation of the Authorize API.
 *
 * This command updates the access policy of a provisioned Shangri-La.
 * It validates the authorization material, refreshes the stored user
 * public key and invocation limit, and keeps the Secure copy of the
 * policy state authoritative.
 *
 * OLD DOCUMENTATION - Kept for reference only
 * (Algorithm now uses plaintext M_update with signature verification)
 */

/*
 * Decrypt late weights using AES-CTR.
 * Input:  encrypted blob (in[1]) + IV (in[2])
 * Output: decrypted bytes (out[0])
 */
static psa_status_t tfm_dp_decrypt_late_weights(psa_msg_t *msg)
{
    if (msg->in_size[1] == 0 || msg->out_size[0] == 0 || msg->in_size[2] < 16) {
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

/* model_secret = SHA-256(encrypted late weights). */
static psa_status_t tfm_dp_set_late_secret_hash(psa_msg_t *msg)
{
    if (msg->in_size[1] == 0U) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t in_buf[256];
    size_t total = msg->in_size[1];
    size_t processed = 0U;

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        return status;
    }

    while (processed < total) {
        size_t chunk = (total - processed > sizeof(in_buf)) ? sizeof(in_buf) : (total - processed);
        psa_read(msg->handle, 1, in_buf, chunk);
        status = psa_hash_update(&op, in_buf, chunk);
        if (status != PSA_SUCCESS) {
            psa_hash_abort(&op);
            return status;
        }
        processed += chunk;
    }

    size_t hash_len = 0U;
    status = psa_hash_finish(&op, current_model_secret, sizeof(current_model_secret), &hash_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (hash_len != sizeof(current_model_secret)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    current_model_secret_valid = true;
    current_enclave_info_valid = false;
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

/* =====================================================================
 * SAU DYNAMIC RAM ENCLAVE ISOLATION
 * TF-M Region 1  = original NS-RAM coverage (saved at init)
 * SAU_REGION_BEFORE (6) = NS split below enclave RAM window
 * SAU_REGION_AFTER  (7) = NS split above enclave RAM window
 *
 * CLOSED: Region 1 disabled, Regions 6+7 cover everything except
 *         the enclave window => enclave range defaults to Secure.
 * OPEN:   Regions 6+7 disabled, Region 1 restored => full NS RAM.
 * ===================================================================== */

#define SAU_REGION_NS_FLASH  0U   /* TF-M NS-flash region (region 0) – we shrink/restore it */
#define SAU_REGION_NS_RAM    1U   /* TF-M NS-data region (region 1) */
/* Regions 2-4 are TF-M's NSC veneer, peripherals, package — DO NOT TOUCH */
/* Free regions available for custom isolation: 5, 6, 7 */
#define SAU_REGION_FLASH_AFTER  5U /* NS flash after protected model_ro window (free region) */
#define SAU_REGION_BEFORE    6U   /* our NS before-enclave RAM region */
#define SAU_REGION_AFTER     7U   /* our NS after-enclave RAM region  */

static uint32_t sau_enclave_base       = 0U;
static uint32_t sau_enclave_size       = 0U;
static bool     sau_enclave_registered = false;
static bool     sau_enclave_open       = true;  /* tracks current state */
static bool     sau_model_ro_open      = true;  /* tracks model_ro flash window state */

/* Limits of TF-M's NS-RAM SAU region (Region 1), read at init. */
static uint32_t sau_ns_ram_base  = 0U;
static uint32_t sau_ns_ram_limit = 0U;
static uint32_t sau_ns_flash_base  = 0U;
static uint32_t sau_ns_flash_limit = 0U;
static bool     sau_ns_flash_open = true;

/* STM32L5 commonly uses secure/non-secure flash alias delta 0x04000000
 * (e.g. 0x08000000 <-> 0x0C000000). */
#define FLASH_ALIAS_DELTA 0x04000000U

static bool range_within(uint32_t base, uint32_t size, uint32_t low, uint32_t high)
{
    if (size == 0U) {
        return false;
    }
    uint32_t limit = base + size - 1U;
    if (limit < base) {
        return false;
    }
    return (base >= low && limit <= high);
}

/* Normalize caller-provided flash base to current NS flash alias range. */
static bool normalize_flash_base_to_ns_alias(uint32_t *base_io, uint32_t size)
{
    uint32_t b = *base_io;

    if (range_within(b, size, sau_ns_flash_base, sau_ns_flash_limit)) {
        return true;
    }

    /* Try secure->non-secure alias conversion. */
    if (b <= (UINT32_MAX - FLASH_ALIAS_DELTA)) {
        uint32_t plus = b + FLASH_ALIAS_DELTA;
        if (range_within(plus, size, sau_ns_flash_base, sau_ns_flash_limit)) {
            *base_io = plus;
            return true;
        }
    }

    /* Try non-secure->secure alias conversion (for completeness). */
    if (b >= FLASH_ALIAS_DELTA) {
        uint32_t minus = b - FLASH_ALIAS_DELTA;
        if (range_within(minus, size, sau_ns_flash_base, sau_ns_flash_limit)) {
            *base_io = minus;
            return true;
        }
    }

    return false;
}

/* Write a SAU region: base and limit both 32-byte-aligned boundaries,
 * enable=1 => Non-Secure (NSC=0), enable=0 => disabled (=> Secure default). */
static void sau_write_region(uint32_t idx, uint32_t base,
                              uint32_t limit, int enable)
{
    SAU->RNR  = idx;
    SAU->RBAR = base  & SAU_RBAR_BADDR_Msk;
    SAU->RLAR = (limit & SAU_RLAR_LADDR_Msk)
                | (enable ? SAU_RLAR_ENABLE_Msk : 0U);
    __DSB();
    __ISB();
}

/* Disable a SAU region (clears ENABLE bit, leaves RBAR/RLAR address intact). */
static void sau_disable_region(uint32_t idx)
{
    SAU->RNR  = idx;
    SAU->RLAR &= ~SAU_RLAR_ENABLE_Msk;
    __DSB();
    __ISB();
}

/* Called once at partition startup: read & save TF-M's NS-RAM region. */
static void sau_partition_init(void)
{
    SAU->RNR = SAU_REGION_NS_FLASH;
    uint32_t frbar = SAU->RBAR;
    uint32_t frlar = SAU->RLAR;
    sau_ns_flash_base  = frbar & SAU_RBAR_BADDR_Msk;
    sau_ns_flash_limit = (frlar & SAU_RLAR_LADDR_Msk) | 0x1FU;

    SAU->RNR = SAU_REGION_NS_RAM;
    uint32_t rbar = SAU->RBAR;
    uint32_t rlar = SAU->RLAR;
    sau_ns_ram_base  = rbar & SAU_RBAR_BADDR_Msk;
    /* Reconstruct full limit: RLAR[31:5] with bits[4:0]=0x1F */
    sau_ns_ram_limit = (rlar & SAU_RLAR_LADDR_Msk) | 0x1FU;
    printf("[SECURE SAU] NS-RAM region %u: 0x%08X..0x%08X (en=%u)\n",
           SAU_REGION_NS_RAM, sau_ns_ram_base, sau_ns_ram_limit,
           (unsigned)((rlar & SAU_RLAR_ENABLE_Msk) ? 1U : 0U));
    printf("[SECURE SAU] NS-FLASH region %u: 0x%08X..0x%08X (en=%u)\n",
           SAU_REGION_NS_FLASH, sau_ns_flash_base, sau_ns_flash_limit,
           (unsigned)((frlar & SAU_RLAR_ENABLE_Msk) ? 1U : 0U));
        printf("[SECURE SAU] Flash isolation: region 0 shrink + region %u for AFTER\n",
            SAU_REGION_FLASH_AFTER);
        printf("[SECURE SAU] RAM isolation: regions %u (BEFORE) and %u (AFTER)\n",
            SAU_REGION_BEFORE, SAU_REGION_AFTER);
}

/* CLOSE: split NS-RAM region so the enclave window becomes Secure. */
static psa_status_t sau_close_enclave(void)
{
    if (!sau_enclave_registered) {
        printf("[SECURE SAU] CLOSE: enclave not registered\n");
        return PSA_ERROR_BAD_STATE;
    }
    uint32_t enc_base  = sau_enclave_base;
    uint32_t enc_limit = sau_enclave_base + sau_enclave_size - 1U;

    /* 32-byte alignment required by SAU (bits[4:0] of base must be 0;  */
    /* bits[4:0] of limit must be 0x1F, i.e. limit+1 is 32-byte aligned) */
    if ((enc_base & 0x1FU) != 0U || ((enc_limit + 1U) & 0x1FU) != 0U) {
        printf("[SECURE SAU] CLOSE: alignment error base=0x%08X limit=0x%08X\n",
               enc_base, enc_limit);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* 1. Disable the three regions first (idempotent). */
    sau_disable_region(SAU_REGION_NS_RAM);
    sau_disable_region(SAU_REGION_BEFORE);
    sau_disable_region(SAU_REGION_AFTER);

    /* 2. NS region A: [ns_ram_base .. enc_base-1] */
    if (enc_base > sau_ns_ram_base) {
        sau_write_region(SAU_REGION_BEFORE,
                         sau_ns_ram_base,
                         enc_base - 1U,
                         1 /* NS, enabled */);
    }

    /* 3. Enclave window [enc_base .. enc_limit] => covered by NO enabled region
     *    => defaults to Secure => NS access triggers BusFault -> HardFault */

    /* 4. NS region C: [enc_limit+1 .. ns_ram_limit] */
    if ((enc_limit + 1U) <= sau_ns_ram_limit) {
        sau_write_region(SAU_REGION_AFTER,
                         enc_limit + 1U,
                         sau_ns_ram_limit,
                         1 /* NS, enabled */);
    }

    sau_enclave_open = false;
    printf("[SECURE SAU] CLOSED: enclave 0x%08X..0x%08X = Secure\n",
           enc_base, enc_limit);
    return PSA_SUCCESS;
}

/* OPEN: restore full NS-RAM region so the enclave window is accessible from NS. */
static psa_status_t sau_open_enclave(void)
{
    if (!sau_enclave_registered) {
        printf("[SECURE SAU] OPEN: enclave not registered\n");
        return PSA_ERROR_BAD_STATE;
    }

    /* 1. Disable split regions. */
    sau_disable_region(SAU_REGION_BEFORE);
    sau_disable_region(SAU_REGION_AFTER);

    /* 2. Restore original full NS-RAM region (TF-M Region 1). */
    sau_write_region(SAU_REGION_NS_RAM,
                     sau_ns_ram_base,
                     sau_ns_ram_limit,
                     1 /* NS, enabled */);

    sau_enclave_open = true;
    printf("[SECURE SAU] OPEN: enclave 0x%08X..0x%08X = Non-Secure\n",
           sau_enclave_base,
           sau_enclave_base + sau_enclave_size - 1U);
    return PSA_SUCCESS;
}

/* CLOSE model_ro flash window: make [sau_rom_base .. sau_rom_base+sau_rom_size-1] Secure.
 * Strategy: shrink region 0 (NS_FLASH) to [NS_flash_base..rom_base-1],
 * use region 5 (FLASH_AFTER) for [rom_limit+1..NS_flash_limit].
 * Regions 2 (NSC veneer) and 3 (peripherals) are intentionally left untouched. */
static psa_status_t sau_close_model_ro(void)
{
    if (!sau_rom_registered || sau_rom_size == 0U) {
        printf("[SECURE SAU] CLOSE MODEL_RO: window not registered\n");
        return PSA_ERROR_BAD_STATE;
    }

    uint32_t rom_base  = sau_rom_base;
    uint32_t rom_limit = sau_rom_base + sau_rom_size - 1U;

    if ((rom_base & 0x1FU) != 0U || ((rom_limit + 1U) & 0x1FU) != 0U) {
        printf("[SECURE SAU] CLOSE MODEL_RO: alignment error base=0x%08X limit=0x%08X\n",
               rom_base, rom_limit);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (rom_base < sau_ns_flash_base || rom_limit > sau_ns_flash_limit) {
        printf("[SECURE SAU] CLOSE MODEL_RO: range out of NS flash [0x%08X..0x%08X]\n",
               sau_ns_flash_base, sau_ns_flash_limit);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Safety: never allow closing the entire NS flash by mistake. */
    if (rom_base == sau_ns_flash_base && rom_limit == sau_ns_flash_limit) {
        printf("[SECURE SAU] CLOSE MODEL_RO: refuses full-NS-flash close\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Safety: model_ro protected window must not overlap inference_ro code window. */
    if (sau_code_registered && sau_code_size > 0U) {
        uint32_t code_base = sau_code_base;
        uint32_t code_limit = sau_code_base + sau_code_size - 1U;
        bool overlap = !(rom_limit < code_base || rom_base > code_limit);
        if (overlap) {
            printf("[SECURE SAU] CLOSE MODEL_RO: overlap with inference_ro [0x%08X..0x%08X]\n",
                   code_base, code_limit);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    bool has_before = (rom_base > sau_ns_flash_base);
    bool has_after  = ((rom_limit + 1U) <= sau_ns_flash_limit);

    /* Clean up FLASH_AFTER region first. */
    sau_disable_region(SAU_REGION_FLASH_AFTER);

    /* NS flash before model_ro: shrink region 0 to [sau_ns_flash_base .. rom_base-1].
     * If nothing precedes model_ro, disable region 0 entirely. */
    if (has_before) {
        sau_write_region(SAU_REGION_NS_FLASH,
                         sau_ns_flash_base,
                         rom_base - 1U,
                         1 /* NS, enabled */);
    } else {
        sau_disable_region(SAU_REGION_NS_FLASH);
    }

    /* model_ro itself is uncovered => defaults Secure. */

    /* NS flash after model_ro: use free region 5. */
    if (has_after) {
        sau_write_region(SAU_REGION_FLASH_AFTER,
                         rom_limit + 1U,
                         sau_ns_flash_limit,
                         1 /* NS, enabled */);
    }

    sau_model_ro_open = false;
    printf("[SECURE SAU] CLOSED MODEL_RO: 0x%08X..0x%08X = Secure\n",
           rom_base, rom_limit);
    return PSA_SUCCESS;
}

/* OPEN model_ro flash window: restore full NS flash region (TF-M Region 0). */
static psa_status_t sau_open_model_ro(void)
{
    if (!sau_rom_registered || sau_rom_size == 0U) {
        printf("[SECURE SAU] OPEN MODEL_RO: window not registered\n");
        return PSA_ERROR_BAD_STATE;
    }

    sau_disable_region(SAU_REGION_FLASH_AFTER);  /* disable region 5 (AFTER split) */

    sau_write_region(SAU_REGION_NS_FLASH,
                     sau_ns_flash_base,
                     sau_ns_flash_limit,
                     1 /* NS, enabled */);

    sau_model_ro_open = true;
    printf("[SECURE SAU] OPEN MODEL_RO: 0x%08X..0x%08X = Non-Secure\n",
           sau_rom_base, sau_rom_base + sau_rom_size - 1U);
    return PSA_SUCCESS;
}

/* Keep RAM and model_ro flash protection in lockstep. */
static psa_status_t sau_sync_enclave_and_model_ro(bool open)
{
    SECURE_BENCHMARK_START(sync_start);
    psa_status_t st = PSA_SUCCESS;

    if (open) {
        if (sau_enclave_registered && !sau_enclave_open) {
            st = sau_open_enclave();
            if (st != PSA_SUCCESS) {
                return st;
            }
        }
        if (sau_rom_registered && !sau_model_ro_open) {
            st = sau_open_model_ro();
            if (st != PSA_SUCCESS) {
                return st;
            }
        }
    } else {
        if (sau_enclave_registered && sau_enclave_open) {
            st = sau_close_enclave();
            if (st != PSA_SUCCESS) {
                return st;
            }
        }
        if (sau_rom_registered && sau_model_ro_open) {
            st = sau_close_model_ro();
            if (st != PSA_SUCCESS) {
                return st;
            }
        }
    }

    if (open) {
        SECURE_BENCHMARK_END(sync_start, sau_sync_open_cycles);
        g_secure_metrics.sau_sync_open_count++;
    } else {
        SECURE_BENCHMARK_END(sync_start, sau_sync_close_cycles);
        g_secure_metrics.sau_sync_close_count++;
    }

    return PSA_SUCCESS;
}

/* Make full NS flash Secure by disabling region 0 coverage. */
static psa_status_t secure_ns_flash(void)
{
    SECURE_BENCHMARK_START(sau_flash_close_start);
    /* Ensure no extra NS flash split region remains active. */
    sau_disable_region(SAU_REGION_FLASH_AFTER);

    SAU->RNR = SAU_REGION_NS_FLASH;
    SAU->RBAR = (sau_ns_flash_base & SAU_RBAR_BADDR_Msk);
    SAU->RLAR = (sau_ns_flash_limit & SAU_RLAR_LADDR_Msk) & ~SAU_RLAR_ENABLE_Msk;
    __DSB();
    __ISB();

    sau_ns_flash_open = false;
    SECURE_BENCHMARK_END(sau_flash_close_start, sau_flash_close_cycles);
    g_secure_metrics.sau_flash_close_count++;
    printf("[SECURE SAU] NS FLASH CLOSED: 0x%08X..0x%08X now Secure\n",
           sau_ns_flash_base, sau_ns_flash_limit);
    return PSA_SUCCESS;
}

/* Restore full NS flash Non-Secure by enabling region 0 coverage. */
static psa_status_t insecure_ns_flash(void)
{
    SECURE_BENCHMARK_START(sau_flash_open_start);
    sau_disable_region(SAU_REGION_FLASH_AFTER);

    SAU->RNR  = SAU_REGION_NS_FLASH;
    SAU->RBAR = (sau_ns_flash_base & SAU_RBAR_BADDR_Msk);
    SAU->RLAR = (sau_ns_flash_limit & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk;
    __DSB();
    __ISB();

    sau_ns_flash_open = true;
    SECURE_BENCHMARK_END(sau_flash_open_start, sau_flash_open_cycles);
    g_secure_metrics.sau_flash_open_count++;
    printf("[SECURE SAU] NS FLASH OPEN: 0x%08X..0x%08X now Non-Secure\n",
           sau_ns_flash_base, sau_ns_flash_limit);
    return PSA_SUCCESS;
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
            return PSA_ERROR_NOT_SUPPORTED;

    case DP_CMD_DECRYPT_MODEL:
        return PSA_ERROR_NOT_SUPPORTED;

    /* ========================================================================
     * CREATE API (Shangri-La semantics)
     * ========================================================================
     * See dummy_partition.h for complete API documentation.
     * ======================================================================== */
    case DP_CMD_CREATE_ENCLAVE:
        {
            /* Create API handler (Shangri-La) - Algorithm mapping
             * Alg L13: Function Create(s_id) entry -> this handler
             * Alg L14: Hs_id <- Hash(s_id) -> the dispatcher has already routed
             *          this request to the enclave-specific secure context
             * Alg L15: if Hs_id not in CT_X then -> require a registered enclave window
             * Alg L16: return failure -> reject invalid / unregistered inputs
             * Alg L17: parse (F, data_pub, enc_data_priv) from s_id -> read the
             *          enclave window descriptor carried by the message
             * Alg L18: mark (F, data_pub, data_priv) as Secure -> register the SAU window
             * Alg L19: data_priv <- AuthDec(CTX[Hs_id].kdec, enc_data_priv) -> decrypt late weights
             * Alg L20: CT_X[Hs_id].state <- Init -> populate secure state and reset counters
             */
            SECURE_BENCHMARK_START(create_cmd_start);
            printf("[SECURE] CREATE: in_size[0]=%zu in_size[1]=%zu in_size[2]=%zu in_size[3]=%zu out_size[0]=%zu\n",
                   msg->in_size[0], msg->in_size[1], msg->in_size[2], msg->in_size[3], msg->out_size[0]);

            psa_status_t st = tfm_dp_decrypt_late_weights(msg);
            if (st != PSA_SUCCESS) {
                printf("[SECURE] CREATE: decrypt failed st=%d\n", (int)st);
                return st;
            }

            /* Alg L17: parse (F, data_pub, enc_data_priv) from s_id. */
            uint32_t raw_base = 0U;
            uint32_t raw_size = 0U;

            /* Accept either the preferred in[3] layout or the legacy in[2] tail. */
            if (msg->in_size[3] == 8U) {
                uint32_t params[2] = {0U, 0U};
                psa_read(msg->handle, 3, params, sizeof(params));
                raw_base = params[0];
                raw_size = params[1];

                printf("[SECURE SAU] CREATE: raw params from in[3] base=0x%08X size=0x%08X\n",
                       raw_base, raw_size);
            }
            else if (msg->in_size[2] >= 24U) {
                uint32_t params[2] = {0U, 0U};
                psa_read(msg->handle, 2, params, sizeof(params));
                raw_base = params[0];
                raw_size = params[1];

                printf("[SECURE SAU] CREATE: raw params from in[2] tail base=0x%08X size=0x%08X\n",
                       raw_base, raw_size);
            }
            else {
                printf("[SECURE SAU] CREATE: missing enclave window parameters\n");
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            /* Alg L18: mark (F, data_pub, data_priv) as Secure. */
            if (raw_size == 0U) {
                printf("[SECURE SAU] CREATE: invalid enclave size=0\n");
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint32_t raw_limit = raw_base + raw_size - 1U;
            if (raw_limit < raw_base) {
                printf("[SECURE SAU] CREATE: overflow in enclave range\n");
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            /* SAU requires 32-byte alignment; cover the full requested range. */
            uint32_t base = raw_base & ~0x1FU;
            uint32_t limit = raw_limit | 0x1FU;

            if (base < sau_ns_ram_base || limit > sau_ns_ram_limit || limit < base) {
                printf("[SECURE SAU] CREATE: out-of-range Shangri-La RAM window 0x%08X..0x%08X (NS RAM=0x%08X..0x%08X)\n",
                       base, limit, sau_ns_ram_base, sau_ns_ram_limit);
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            sau_enclave_base = base;
            sau_enclave_size = (limit - base) + 1U;
            sau_enclave_registered = true;
            sau_enclave_open = true;
            printf("[SECURE SAU] CREATE: registered Shangri-La RAM window 0x%08X..0x%08X\n",
                   base, limit);

            if (!sau_enclave_registered) {
                printf("[SECURE SAU] CREATE: Shangri-La RAM window not registered\n");
                return PSA_ERROR_BAD_STATE;
            }

            /* Alg L19: data_priv <- AuthDec(CTX[Hs_id].kdec, enc_data_priv). */
            st = sau_sync_enclave_and_model_ro(true);
            if (st != PSA_SUCCESS) {
                return st;
            }

            /* Alg L20: CT_X[Hs_id].state <- Init. */
            inference_counter_secure = 0U;
            shangri_la_created_secure = true;
            reset_secure_inference_tx_state();
            g_secure_metrics.counter_operations++;
            SECURE_BENCHMARK_END(create_cmd_start, create_enclave_cycles);
            g_secure_metrics.create_enclave_count++;
            printf("[SECURE] Shangri-La instance created: single-path Create complete, RAM window still open (await finalize)\n");
            return PSA_SUCCESS;
        }

    case DP_CMD_FINALIZE_CREATE_ENCLAVE:
        {
            /* Secure-side API implementation for NS DP_CMD_FINALIZE_CREATE_ENCLAVE. */
            SECURE_BENCHMARK_START(finalize_cmd_start);
            if (!sau_enclave_registered) {
                printf("[SECURE SAU] FINALIZE CREATE: enclave window not registered\n");
                return PSA_ERROR_BAD_STATE;
            }

            psa_status_t st = sau_sync_enclave_and_model_ro(false);
            if (st != PSA_SUCCESS) {
                return st;
            }

            g_secure_metrics.counter_operations++;
            SECURE_BENCHMARK_END(finalize_cmd_start, finalize_create_cycles);
            g_secure_metrics.finalize_create_count++;
            printf("[SECURE] Finalize create: RAM window closed\n");
            return PSA_SUCCESS;
        }

    /* ========================================================================
     * DESTROY API (Shangri-La semantics)
     * ========================================================================
     * See dummy_partition.h for complete API documentation.
     * ======================================================================== */
    case DP_CMD_DESTROY_ENCLAVE:
        {
            /* Destroy API handler (Shangri-La) - Algorithm mapping
             * Algorithm: Function Destroy(Hs_id)
             * Alg L41: Function Destroy(Hs_id) entry -> this handler (DP_CMD_DESTROY_ENCLAVE)
             * Alg L42: if Hs_id ∉ CT_X then -> here we check enclave existence / lifecycle
             * Alg L43: abort -> return success or error as appropriate
             * Alg L44: erase data_priv -> zeroize secure private region
             * Alg L45: mark (F, data_pub, data_priv) as Non-secure -> release SAU windows
             * Alg L46: CT_X[Hs_id].state ← Non-Exist -> clear lifecycle/auth state
             */
            SECURE_BENCHMARK_START(destroy_cmd_start);
            psa_status_t st = PSA_SUCCESS;

            /* Alg L42: If Hs_id not in CT_X then abort
             * In this implementation the CT_X presence is represented by
             * `shangri_la_created_secure` (lifecycle flag) and `s_auth_valid` for auth state.
             * Check lifecycle first and return success if no Shangri-La instance exists (idempotent).
             */
            if (!shangri_la_created_secure) {
                /* Alg L43: Abort (idempotent success) */
                SECURE_BENCHMARK_END(destroy_cmd_start, destroy_enclave_cycles);
                g_secure_metrics.destroy_enclave_count++;
                printf("[SECURE] Destroy: Shangri-La instance not created, returning success\n");
                return PSA_SUCCESS;
            }

            /* Alg L44: Erase sensitive private data (data_priv) while region is secure */
            printf("[SECURE] Destroying Shangri-La instance: erasing sensitive data...\n");

            /* Actual zeroization and reset of transient transaction state */
            inference_counter_secure = 0U; /* reset usage counter */
            reset_secure_inference_tx_state();

            /* If we have an enclave RAM window registered, zeroize it now while
             * it is still marked Secure. This ensures data_priv (and any other
             * sensitive region within the enclave RAM) is irreversibly erased
             * before returning the memory to Normal World control.
             */
            if (sau_enclave_registered && sau_enclave_size > 0U) {
                void *enclave_ram = (void *)(uintptr_t)sau_enclave_base;
                secure_memzero(enclave_ram, (size_t)sau_enclave_size);
                printf("[SECURE] Shangri-La RAM region zeroized (base=0x%08X, size=%u)\n",
                       (unsigned int)sau_enclave_base, (unsigned int)sau_enclave_size);
            }

            /* Alg L45: Mark F, data_pub, data_priv as Non-Secure by releasing SAU windows.
             * Call `sau_sync_enclave_and_model_ro(true)` to hand memory back to Normal World.
             */
            if (sau_enclave_registered || sau_rom_registered) {
                st = sau_sync_enclave_and_model_ro(true);
                if (st != PSA_SUCCESS) {
                    printf("[SECURE] Destroy: SAU restore failed\n");
                    return st;
                }
                printf("[SECURE] SAU windows released to Normal World\n");
            }

            /* Alg L46: Update CT_X[Hs_id].state := Non-Exist
             * Here we clear the authoritative Secure-state: lifecycle and auth fields.
             */
            shangri_la_created_secure = false;
            s_auth_valid = false;
            memset(s_pk_u, 0, sizeof(s_pk_u));
            s_model_id = 0;
            max_inferences_per_enclave_secure = 0;

            g_secure_metrics.counter_operations++;
            SECURE_BENCHMARK_END(destroy_cmd_start, destroy_enclave_cycles);
            g_secure_metrics.destroy_enclave_count++;
            printf("[SECURE] Shangri-La instance destroyed: lifecycle → Non-Exist, SAU windows closed\n");
            return PSA_SUCCESS;
        }

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
        return PSA_ERROR_NOT_SUPPORTED;

    case DP_CMD_INCREMENT_COUNTER:
        return PSA_ERROR_NOT_SUPPORTED;

    case DP_CMD_RESET_COUNTER:
        return PSA_ERROR_NOT_SUPPORTED;
    
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
    
    /* ========================================================================
     * EXECUTE/RUN API (Shangri-La semantics)
     * ========================================================================
     * See dummy_partition.h for complete API documentation.
     * ======================================================================== */
    
    
    /*
     * EXECUTE -> CODE MAPPING
     * Algorithm: Function Execute(u, In, Hs_id, proof, Tu)
     *
     * Alg L21 (function entry):           -> case DP_CMD_RUN_INFERENCE: (this handler)
     *                                      Location: dummy_partition.c around this line.
     * Alg L22 (Hs_id ∉ CT_X ?):            -> precondition check: `if (!s_auth_valid || !shangri_la_created_secure)`
     *                                      Location: dummy_partition.c:1446
     * Alg L23 (abort):                    -> sets `result = PSA_ERROR_BAD_STATE; goto inf_phase0_out;`
     *                                      Location: dummy_partition.c:1447-1448
     * Alg L24 (CT_X[Hs_id] retrieval):    -> use of stored auth fields `s_pk_u`, `s_model_id`
     *                                      Extract model_id from M_inf and compare: dummy_partition.c:1496-1533
     * Alg L25 (state/usage/limit/seq):    -> quota check `if (inference_counter_secure + 1U > max_inferences_per_enclave_secure)`
     *                                      Location: dummy_partition.c:1458
     *                                      -> sequence check `if (req_tx_id != s_tx_id)` (phase 1)
     *                                      Location: dummy_partition.c:1631
     * Alg L26 (abort):                    -> various `goto inf_phase0_out` or `goto inf_phase1_out` sites after checks
     *                                      Examples: dummy_partition.c:1460, 1632-1633
     * Alg L27 (Verify(pk_u, Tu, ...)):    -> ECDSA verify using verifier pubkey: `psa_verify_hash(...)`
     *                                      Location: dummy_partition.c:1552
     * Alg L28 (abort):                    -> verification failure handling + `goto inf_phase0_out`
     *                                      Location: dummy_partition.c:1558-1563
     * Alg L29 (disable interrupts):       -> open SAU and prepare NS execution: `sau_sync_enclave_and_model_ro(true)`
     *                                      Location: dummy_partition.c:1567
     * Alg L30 (CT_X[].state ← Active):    -> mark transaction active and store nonce: `s_tx_active = true; s_tx_id++` 
     *                                      Location: dummy_partition.c:1574
     * Alg L31 (allocate stack):           -> SAU open / runtime stack usage implicit during NS execution
     *                                      (SAU open at dummy_partition.c:1567; tx return at dummy_partition.c:1593)
     * Alg L32 (mark Non-secure):          -> performed by SAU open call above (dummy_partition.c:1567)
     * Alg L33 (OutF ← execute entry):     -> phase 0 returns `tx_id` to host so NS can execute the entry
     *                                      Return: `psa_write(..., &tx_id, ...)` at dummy_partition.c:1593
     * Alg L34 (erase stack):              -> clear transaction nonce and sensitive buffers after commit
     *                                      Example: `memset(s_tx_nonce, 0, ...)` at dummy_partition.c:1684
     * Alg L35 (mark Secure):              -> close SAU: `sau_sync_enclave_and_model_ro(false)` at dummy_partition.c:1680
     * Alg L36 (update CT_X usage/state):  -> increment and reset: `inference_counter_secure++` and `s_tx_active = false`
     *                                      Locations: dummy_partition.c:1678, 1682
     * Alg L37 (enable interrupts):       -> implied by SAU close / end of critical section (dummy_partition.c:1680)
     * Alg L38 (if proof then ...):       -> PoX assembly: `pox_msg[...] = ...` starting at dummy_partition.c:1637
     * Alg L39 (Tproof ← Sign(...)):       -> sign PoX: `psa_sign_hash(...)` at dummy_partition.c:1664
     * Alg L40 (return (OutF, Tproof)):    -> signature written to host: `psa_write(msg->handle, 0, sig, sizeof(sig))` at dummy_partition.c:1691
     *
     * Notes:
     * - 'Line' references above are file-local and may shift as the file is edited; use the
     *   code snippets (function/variable names) to find the exact logic if lines change.
     */
    case DP_CMD_RUN_INFERENCE:
        {
            /*
             * Execute/Run API handler (Shangri-La semantics) - unified two-phase flow.
             * Maps to Algorithm: Function Execute(u, In, Hs_id, proof, Tu)
             * Algorithm lines mapping:
             *  - Line 21: function entry -> this handler (DP_CMD_RUN_INFERENCE)
             *  - Line 22: Hs_id presence check -> precondition: `s_auth_valid` and `shangri_la_created_secure`
             *  - Line 24: CT_X[Hs_id] retrieval -> use of `s_pk_u`, `s_model_id`
             *  - Line 25: state/usage/limit checks -> quota check `inference_counter_secure + 1 <= max_inferences_per_enclave_secure`
             *  - Line 27: Verify(pk_u, Tu, ...) -> ECDSA verify of M_inf using `s_pk_u` (psa_verify_hash)
             *  - Lines 29-33: disable interrupts / set Active / open SAU / mark NS memory -> `sau_sync_enclave_and_model_ro(true)` and `s_tx_active` setup
             *  - Line 33: execute entry -> NS-side execution happens while SAU is open; phase 0 returns `tx_id` for commit
             *  - Lines 34-37: erase stack / resecure memory / update CT_X -> in phase 1 we close SAU (`sau_sync_enclave_and_model_ro(false)`) and increment `inference_counter_secure`
             *  - Lines 38-40: optional proof/signature -> PoX generation and `psa_sign_hash` in phase 1; signature returned to host
             */
            /* Secure-side implementation: Execute/Run API (Shangri-La) - UNIFIED */
            uint8_t phase = 1U;
            if (msg->in_size[1] == 1U) {
                psa_read(msg->handle, 1, &phase, 1U);
            }

            if (phase > 1U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (phase == 0U) {
                /* PHASE 0: PRECHECK - Validate user authorization + open SAU */
                
                SECURE_BENCHMARK_START(inf_start_cycles_start);
                psa_status_t result = PSA_SUCCESS;
                uint8_t m_inf[100];
                uint8_t req_code_hash[32];
                uint8_t msg_hash[32];
                size_t hash_len = 0U;
                uint32_t tx_id = 0U;

                /* Validate input/output sizes: M_inf is 100 bytes plaintext, output is tx_id (uint32_t) */
                if (msg->in_size[1] != 1U || msg->in_size[2] != sizeof(m_inf) || msg->out_size[0] != sizeof(tx_id)) {
                    result = PSA_ERROR_INVALID_ARGUMENT;
                    goto inf_phase0_out;
                }

                /* ALG L22: If Hs_id not in CT_X then abort (checked via s_auth_valid/shangri_la_created_secure) */
                /* Preconditions: Shangri-La instance created and authorization valid */
                if (!s_auth_valid || !shangri_la_created_secure) {
                    result = PSA_ERROR_BAD_STATE;
                    goto inf_phase0_out;
                }

                /* Recover from stale transaction state if needed */
                if (s_tx_active) {
                    (void)sau_sync_enclave_and_model_ro(false);
                    reset_secure_inference_tx_state();
                }

                /* ALG L25: Check state/usage/limit: ensure usage+1 <= limit */
                /* Check quota: counter + 1 <= c_limit */
                if (inference_counter_secure + 1U > max_inferences_per_enclave_secure) {
                    result = PSA_ERROR_NOT_PERMITTED;
                    goto inf_phase0_out;
                }

                /* Read plaintext M_inf: model_id(4) || code_hash(32) || signature(64) = 100 bytes */
                psa_read(msg->handle, 2, m_inf, sizeof(m_inf));
                
                psa_status_t st = psa_crypto_init();
                if (st != PSA_SUCCESS) {
                    result = st;
                    goto inf_phase0_out;
                }

                /* ALG L24: Retrieve CT_X[Hs_id] fields (model identity). Extract model_id and F hash from M_inf */
                /* Extract model_id from M_inf */
                uint32_t req_model_id = (uint32_t)m_inf[0]
                                      | ((uint32_t)m_inf[1] << 8)
                                      | ((uint32_t)m_inf[2] << 16)
                                      | ((uint32_t)m_inf[3] << 24);
                memcpy(req_code_hash, m_inf + 4U, sizeof(req_code_hash));

                if (s_model_id != 0U && req_model_id != s_model_id) {
                    result = PSA_ERROR_INVALID_ARGUMENT;
                    goto inf_phase0_out;
                }

                st = refresh_code_hash_from_registered_code();
                if (st != PSA_SUCCESS || memcmp(req_code_hash, current_code_hash, sizeof(current_code_hash)) != 0) {
                    secure_memzero(m_inf, sizeof(m_inf));
                    result = PSA_ERROR_INVALID_ARGUMENT;
                    goto inf_phase0_out;
                }

                /* Hash M_inf for signature verification */
                st = psa_hash_compute(PSA_ALG_SHA_256,
                                      m_inf,
                                      36U,
                                      msg_hash,
                                      sizeof(msg_hash),
                                      &hash_len);
                if (st != PSA_SUCCESS || hash_len != sizeof(msg_hash)) {
                    secure_memzero(m_inf, sizeof(m_inf));
                    result = PSA_ERROR_GENERIC_ERROR;
                    goto inf_phase0_out;
                }

                /* ALG L27: Verify(pk_u, Tu, u||In||Hs_id||proof) -- verify user's signature Tu using pk_u */
                /* Verify user's signature Tu using pk_u */
                uint8_t pk_v_full[65];
                pk_v_full[0] = 0x04U;
                memcpy(pk_v_full + 1U, s_pk_u, 64U);

                psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
                psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
                psa_set_key_bits(&attr, 256);
                psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
                psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

                psa_key_id_t pk_v_id = 0;
                st = psa_import_key(&attr, pk_v_full, sizeof(pk_v_full), &pk_v_id);
                psa_reset_key_attributes(&attr);
                if (st != PSA_SUCCESS) {
                    secure_memzero(m_inf, sizeof(m_inf));
                    result = PSA_ERROR_INVALID_SIGNATURE;
                    goto inf_phase0_out;
                }

                /* ALG L28: Abort if verification fails */
                st = psa_verify_hash(pk_v_id,
                                     PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                     msg_hash,
                                     sizeof(msg_hash),
                                     m_inf + 36U,
                                     64U);
                psa_destroy_key(pk_v_id);
                if (st != PSA_SUCCESS) {
                    secure_memzero(m_inf, sizeof(m_inf));
                    result = PSA_ERROR_INVALID_SIGNATURE;
                    goto inf_phase0_out;
                }

                /* ALG L29: Disable interrupts / open execution region (SAU) for NS execution */
                /* All validation passed: open SAU windows for NS execution */
                st = sau_sync_enclave_and_model_ro(true);
                if (st != PSA_SUCCESS) {
                    result = st;
                    goto inf_phase0_out;
                }

                /* ALG L30: Set CT_X[Hs_id].state := Active (mark transaction active) and store F hash */
                /* Mark transaction as active and store F hash for PoX generation */
                s_tx_active = true;
                s_tx_id++;
                if (s_tx_id == 0U) {
                    s_tx_id = 1U;
                }
                tx_id = s_tx_id;
                memcpy(s_tx_code_hash, req_code_hash, sizeof(s_tx_code_hash));
                s_tx_model_id = req_model_id;

                secure_memzero(m_inf, sizeof(m_inf));

            inf_phase0_out:
                SECURE_BENCHMARK_END(inf_start_cycles_start, inf_start_cycles);
                if (result == PSA_SUCCESS) {
                    g_secure_metrics.inf_start_count++;
                } else {
                    tx_id = 0U;  /* Return 0 on error instead of allowing */
                }
                /* ALG L33: Return tx_id (OutF) so NS can perform the execution while SAU is open */
                psa_write(msg->handle, 0, &tx_id, sizeof(tx_id));
                g_secure_metrics.counter_operations++;
                return result == PSA_SUCCESS ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;

            } else {
                /* PHASE 1: COMMIT - Generate PoX + close SAU + increment counter */
                
                SECURE_BENCHMARK_START(inf_complete_cycles_start);
                psa_status_t result = PSA_SUCCESS;
                uint8_t req[5];
                uint8_t pox_hash[32];
                uint8_t pox_msg[4U + 32U + 1U];
                size_t pox_hash_len = 0U;
                size_t pox_msg_len = 0U;
                size_t sig_len = 0U;
                uint8_t sig[64];
                psa_status_t st = PSA_SUCCESS;

                /* Validate input/output sizes */
                if (msg->in_size[2] != sizeof(req) || msg->out_size[0] != sizeof(sig)) {
                    result = PSA_ERROR_INVALID_ARGUMENT;
                    goto inf_phase1_out;
                }

                /* Preconditions: transaction must be active and device key ready */
                if (!s_tx_active || !s_device_key_ready) {
                    result = PSA_ERROR_BAD_STATE;
                    goto inf_phase1_out;
                }

                /* Read inference output result */
                psa_read(msg->handle, 2, req, sizeof(req));
                uint32_t req_tx_id = (uint32_t)req[0]
                                   | ((uint32_t)req[1] << 8)
                                   | ((uint32_t)req[2] << 16)
                                   | ((uint32_t)req[3] << 24);
                uint8_t output_class = req[4];

                /* Verify transaction ID matches */
                if (req_tx_id != s_tx_id) {
                    result = PSA_ERROR_INVALID_ARGUMENT;
                    goto inf_phase1_out;
                }

                /* ALG L38: If proof requested, assemble PoX material (model_id || F_binary_hash || output) */
                /* Generate PoX: sign (model_id || F_binary_hash || output) */
                pox_msg[pox_msg_len++] = (uint8_t)(s_tx_model_id & 0xFFU);
                pox_msg[pox_msg_len++] = (uint8_t)((s_tx_model_id >> 8) & 0xFFU);
                pox_msg[pox_msg_len++] = (uint8_t)((s_tx_model_id >> 16) & 0xFFU);
                pox_msg[pox_msg_len++] = (uint8_t)((s_tx_model_id >> 24) & 0xFFU);

                st = refresh_code_hash_from_registered_code();
                if (st != PSA_SUCCESS) {
                    result = PSA_ERROR_GENERIC_ERROR;
                    goto inf_phase1_out;
                }

                memcpy(pox_msg + pox_msg_len, s_tx_code_hash, sizeof(s_tx_code_hash));
                pox_msg_len += sizeof(s_tx_code_hash);

                pox_msg[pox_msg_len++] = output_class;

                /* Hash PoX message */
                st = psa_hash_compute(PSA_ALG_SHA_256,
                                      pox_msg,
                                      pox_msg_len,
                                      pox_hash,
                                      sizeof(pox_hash),
                                      &pox_hash_len);
                if (st != PSA_SUCCESS || pox_hash_len != sizeof(pox_hash)) {
                    result = PSA_ERROR_GENERIC_ERROR;
                    goto inf_phase1_out;
                }

                /* ALG L39: Sign the PoX with device key (T_proof := Sign(skDev, PoX)) */
                /* Sign PoX with device key sk_Dev */
                st = psa_sign_hash(s_device_sign_key_id,
                                   PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                   pox_hash,
                                   sizeof(pox_hash),
                                   sig,
                                   sizeof(sig),
                                   &sig_len);
                if (st != PSA_SUCCESS || sig_len != sizeof(sig)) {
                    result = PSA_ERROR_GENERIC_ERROR;
                    goto inf_phase1_out;
                }

                /* ALG L36: Update CT_X[Hs_id].usage := u and set state := Inactive (increment usage) */
                /* Atomically increment counter and close SAU */
                inference_counter_secure++;
                g_secure_metrics.counter_operations++;

                /* ALG L35: Mark memory Secure again (close SAU) */
                (void)sau_sync_enclave_and_model_ro(false);

                /* ALG L36/L34: Clear transient stack/nonce/state */
                s_tx_active = false;
                memset(s_tx_code_hash, 0, sizeof(s_tx_code_hash));
                s_tx_model_id = 0U;

            inf_phase1_out:
                SECURE_BENCHMARK_END(inf_complete_cycles_start, inf_complete_cycles);
                if (result == PSA_SUCCESS) {
                    g_secure_metrics.inf_complete_count++;
                }
                /* ALG L40: Return (OutF, T_proof) -> write signature back to host */
                psa_write(msg->handle, 0, sig, sizeof(sig));
                return result == PSA_SUCCESS ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
            }
        }

    case DP_CMD_COMPUTE_ENCLAVE_INFO:
        {
            /* Compute EnclaveInfo = SHA-256(Model_pub || Model_secret || code || model_ID)
             * Secure-only mode:
             *   in[0] = cmd only (host never provides model details)
             * The value is returned from secure metadata/cache and does not require
             * runtime enclave creation or an open SAU execution region.
             * Output:
             *  out[0] = enclave_info (32 bytes)
             */
            printf("[SECURE] DP_CMD_COMPUTE_ENCLAVE_INFO received\n");
            printf("[SECURE]   in_size[0]=%zu (cmd), in_size[1]=%zu (combined), in_size[2]=%zu (model_id)\n",
                   msg->in_size[0], msg->in_size[1], msg->in_size[2]);
            printf("[SECURE]   out_size[0]=%zu (enclave_info)\n", msg->out_size[0]);

            /* Validate output size */
            if (msg->out_size[0] != 32) {
                printf("[SECURE]   ERROR: Invalid output size\n");
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (msg->in_size[1] != 0U || msg->in_size[2] != 0U) {
                printf("[SECURE]   ERROR: host-provided model data is not allowed\n");
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (!current_model_info_valid) {
                init_secure_model_identity();
            }

            psa_status_t st = seal_boot_enclave_info_once();
            if (st != PSA_SUCCESS) {
                printf("[SECURE]   ERROR: secure boot EnclaveInfo not ready (%d)\n", (int)st);
                return st;
            }

            psa_write(msg->handle, 0, boot_enclave_info, 32);
            printf("[SECURE]   ✓ EnclaveInfo returned from secure cache\n");
            printf("[SECURE]   EnclaveInfo (first 16 bytes): ");
            for (int i = 0; i < 16; i++) printf("%02X ", boot_enclave_info[i]);
            printf("\n");
            return PSA_SUCCESS;
        }

    /* ========================================================================
     * AUTHORIZE API (Shangri-La semantics)
     * ========================================================================
     * See dummy_partition.h for complete API documentation.
     * ======================================================================== */
    case DP_CMD_VALIDATE_AUTHORIZE:
         {
             /*
              * Authorize API handler (inlined implementation).
              * Maps to Algorithm: Function Authorize(pk_u, limit, Hs_id, To)
              * Algorithm lines mapping:
              *  - Line 6: function entry  -> this handler (DP_CMD_VALIDATE_AUTHORIZE)
              *  - Line 7: check presence  -> EnclaveInfo / host identity check
              *  - Line 9: verify/update  -> Signature verification (To) + anti-replay check
              *  - Line 10: update CT_X    -> update stored user pk and limit (s_pk_u, last_accepted_counter_limit)
              * 
              * M_update structure (plaintext, not encrypted):
              *  - pk_u (64 bytes): user public key
              *  - limit (4 bytes): inference limit
              *  - H_{s_id} (32 bytes): enclave info hash
              *  - T_o (64 bytes): signature over pk_u || limit (ECDSA P-256)
              */
             printf("[SECURE] DP_CMD_VALIDATE_AUTHORIZE received\n");
             printf("[SECURE]   in_size[1]=%zu (M_update plaintext)\n", msg->in_size[1]);
             
             SECURE_BENCHMARK_START(authorize_start);
             psa_status_t status = PSA_SUCCESS;

             /* Alg line 6: function precondition - ensure model identity context exists */
             if (!current_model_info_valid) {
                 printf("[SECURE] Authorize rejected: model identity context unavailable\n");
                 return PSA_ERROR_BAD_STATE;
             }

             /* in[1] = M_update plaintext: pk_u(64) | limit(4) | H_{s_id}(32) | T_o(64) = 164 bytes */
             size_t m_update_len = msg->in_size[1];
             printf("[SECURE] M_update received, size=%zu bytes\n", m_update_len);
             if (m_update_len != AUTHORIZE_PLAINTEXT_SIZE) {
                 printf("[SECURE] M_update invalid size: got %zu, expected %zu\n", 
                        m_update_len, AUTHORIZE_PLAINTEXT_SIZE);
                 return PSA_ERROR_INVALID_ARGUMENT;
             }
             
             /* out[0] must fit: limit(4) + pk_u(64) = 68 bytes */
             if (msg->out_size[0] < (4U + AUTHORIZE_PK_U_SIZE)) {
                 return PSA_ERROR_INVALID_ARGUMENT;
             }

             /* Read M_update plaintext. */
             uint8_t m_update[AUTHORIZE_PLAINTEXT_SIZE];
             psa_read(msg->handle, 1, m_update, m_update_len);

             /* Parse M_update: pk_u(64) | limit(4) | H_{s_id}(32) | T_o(64) */
             size_t off = 0;
             uint8_t *pk_u_ptr             = &m_update[off]; off += AUTHORIZE_PK_U_SIZE;
             uint32_t c_limit              = 0;
             memcpy(&c_limit,              &m_update[off], 4); off += 4;
             uint8_t *enclave_info_rcvd   = &m_update[off]; off += ENCLAVE_INFO_SIZE;
             uint8_t *signature_ptr        = &m_update[off]; /* T_o: 64 bytes */

             printf("[SECURE] M_update parsed: limit=%u, enclave_info_ptr=%p, signature_ptr=%p\n",
                    c_limit, enclave_info_rcvd, signature_ptr);

             /*
              * Alg line 7: ensure H_{s_id} (enclave_info) matches
              * the expected, sealed boot-time EnclaveInfo. Abort if mismatch.
              */
             status = seal_boot_enclave_info_once();
             if (status != PSA_SUCCESS) {
                 secure_memzero(m_update, sizeof(m_update));
                 return status;
             }
             if (!secure_memequal(enclave_info_rcvd, boot_enclave_info, ENCLAVE_INFO_SIZE)) {
                 printf("[SECURE] M_update EnclaveInfo mismatch\n");
                 secure_memzero(m_update, sizeof(m_update));
                 return PSA_ERROR_INVALID_ARGUMENT;
             }

             /*
              * Alg line 9: Verify(...) -- verify signature T_o over (pk_u || limit)
              * Signature verification ensures integrity and authenticity of M_update.
              */
             status = psa_crypto_init();
             if (status != PSA_SUCCESS) {
                 secure_memzero(m_update, sizeof(m_update));
                 return status;
             }

             /* Import the user public key (pk_u) for signature verification. */
             /* The signature T_o is generated by the user with their private key (sk_u). */
             /* PSA expects ECC public keys in uncompressed point format: 0x04 || X(32) || Y(32) = 65 bytes */
             uint8_t pk_u_ec_point[65];
             pk_u_ec_point[0] = 0x04;  /* Uncompressed point marker */
             memcpy(&pk_u_ec_point[1], pk_u_ptr, AUTHORIZE_PK_U_SIZE);  /* X||Y (64 bytes) */

             psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
             psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
             psa_set_key_bits(&attr, 256);
             psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
             psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

             psa_key_id_t verify_key_id;
             status = psa_import_key(&attr, pk_u_ec_point, sizeof(pk_u_ec_point), &verify_key_id);
             psa_reset_key_attributes(&attr);
             if (status != PSA_SUCCESS) {
                 printf("[SECURE] Failed to import user public key for verification: %d\n", (int)status);
                 secure_memzero(m_update, sizeof(m_update));
                 secure_memzero(pk_u_ec_point, sizeof(pk_u_ec_point));
                 return status;
             }

             /* Hash the message (pk_u || limit) for signature verification. */
             uint8_t msg_to_sign[AUTHORIZE_PK_U_SIZE + 4];
             memcpy(msg_to_sign, pk_u_ptr, AUTHORIZE_PK_U_SIZE);
             memcpy(msg_to_sign + AUTHORIZE_PK_U_SIZE, &c_limit, 4);

             uint8_t msg_hash[32];  /* SHA-256 */
             size_t hash_len = 0;
             status = psa_hash_compute(PSA_ALG_SHA_256,
                                       msg_to_sign, sizeof(msg_to_sign),
                                       msg_hash, sizeof(msg_hash),
                                       &hash_len);
             if (status != PSA_SUCCESS) {
                 printf("[SECURE] Failed to hash message: %d\n", (int)status);
                 psa_destroy_key(verify_key_id);
                 secure_memzero(m_update, sizeof(m_update));
                 secure_memzero(msg_to_sign, sizeof(msg_to_sign));
                 return status;
             }

             /* Verify signature. */
             status = psa_verify_hash(verify_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                      msg_hash, hash_len,
                                      signature_ptr, AUTHORIZE_SIGNATURE_SIZE);
             psa_destroy_key(verify_key_id);

             if (status != PSA_SUCCESS) {
                 printf("[SECURE] Authorize signature verification failed: %d\n", (int)status);
                 secure_memzero(m_update, sizeof(m_update));
                 secure_memzero(pk_u_ec_point, sizeof(pk_u_ec_point));
                 secure_memzero(msg_to_sign, sizeof(msg_to_sign));
                 secure_memzero(msg_hash, sizeof(msg_hash));
                 return PSA_ERROR_INVALID_SIGNATURE;
             }

             /*
              * Alg line 9 (cont): anti-replay / policy check: reject if new limit
              * is not strictly greater than the stored limit.
              */
             if (c_limit <= last_accepted_counter_limit) {
                 printf("[SECURE] Anti-replay check failed: limit %u <= previous %u\n",
                        c_limit, last_accepted_counter_limit);
                 secure_memzero(m_update, sizeof(m_update));
                 secure_memzero(msg_to_sign, sizeof(msg_to_sign));
                 secure_memzero(msg_hash, sizeof(msg_hash));
                 return PSA_ERROR_NOT_PERMITTED;
             }

             /*
              * Alg line 10: update the certificate table entry CT_X[H_{s_id}]
              * with the new user public key (pk_u) and limit.
              */
             /* All checks passed — update Secure state atomically. */
             last_accepted_counter_limit       = c_limit;
             max_inferences_per_enclave_secure = c_limit;
             inference_counter_secure          = 0;

             /* Store user pubkey in Secure (authoritative copy). */
             memcpy(s_pk_u, pk_u_ptr, AUTHORIZE_PK_U_SIZE);
             s_model_id = 0;  /* Model ID not part of new M_update format */
             s_auth_valid = true;

             printf("[SECURE] Authorize OK: limit=%u, sig verified\n", c_limit);

             /* Build response: limit(4) + pk_u(64) */
             uint8_t resp[4U + AUTHORIZE_PK_U_SIZE];
             size_t roff = 0;
             memcpy(resp + roff, &c_limit, 4); roff += 4;
             memcpy(resp + roff, s_pk_u, AUTHORIZE_PK_U_SIZE); roff += AUTHORIZE_PK_U_SIZE;

             if (msg->out_size[0] >= roff) {
                 psa_write(msg->handle, 0, resp, roff);
             }

             /* Zeroize sensitive data. */
             secure_memzero(m_update, sizeof(m_update));
             secure_memzero(pk_u_ec_point, sizeof(pk_u_ec_point));
             secure_memzero(msg_to_sign, sizeof(msg_to_sign));
             secure_memzero(msg_hash, sizeof(msg_hash));
             secure_memzero(resp, sizeof(resp));

             SECURE_BENCHMARK_END(authorize_start, authorize_cycles);
             g_secure_metrics.authorize_count++;

             return PSA_SUCCESS;
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

    case DP_CMD_SAU_REGISTER:
        return PSA_ERROR_NOT_SUPPORTED;

    case DP_CMD_SAU_CONTROL:
        return PSA_ERROR_NOT_SUPPORTED;

    case DP_CMD_GET_SAU_STATE:
        {
            if (msg->out_size[0] < 9U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint8_t out[9] = {0};
            out[0] = sau_enclave_registered ? (sau_enclave_open ? 1U : 2U) : 0U;
            out[1] = (uint8_t)(sau_enclave_base & 0xFFU);
            out[2] = (uint8_t)((sau_enclave_base >> 8) & 0xFFU);
            out[3] = (uint8_t)((sau_enclave_base >> 16) & 0xFFU);
            out[4] = (uint8_t)((sau_enclave_base >> 24) & 0xFFU);
            out[5] = (uint8_t)(sau_enclave_size & 0xFFU);
            out[6] = (uint8_t)((sau_enclave_size >> 8) & 0xFFU);
            out[7] = (uint8_t)((sau_enclave_size >> 16) & 0xFFU);
            out[8] = (uint8_t)((sau_enclave_size >> 24) & 0xFFU);
            psa_write(msg->handle, 0, out, sizeof(out));
            return PSA_SUCCESS;
        }

    case DP_CMD_VALIDATE_BOOT_ENCLAVE_INFO:
        {
            if (msg->out_size[0] < 1U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint8_t match = 0U;
            psa_status_t st = validate_current_enclave_info_against_boot(&match);
            if (st != PSA_SUCCESS) {
                printf("[SECURE] current-vs-boot EnclaveInfo validation failed: %d\n", (int)st);
                return st;
            }

            psa_write(msg->handle, 0, &match, sizeof(match));
            printf("[SECURE] current-vs-boot EnclaveInfo match=%u\n", match);
            return PSA_SUCCESS;
        }

    case DP_CMD_SAU_REGISTER_ROM:
        {
            if (msg->in_size[1] != 8U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint32_t params[2] = {0U, 0U};
            psa_read(msg->handle, 1, params, sizeof(params));

            uint32_t raw_base = params[0];
            uint32_t raw_size = params[1];
            if (raw_size == 0U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (!normalize_flash_base_to_ns_alias(&raw_base, raw_size)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint32_t raw_limit = raw_base + raw_size - 1U;
            if (raw_limit < raw_base) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint32_t base = raw_base & ~0x1FU;
            uint32_t limit = raw_limit | 0x1FU;
            if (base < sau_ns_flash_base || limit > sau_ns_flash_limit || limit < base) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            sau_rom_base = base;
            sau_rom_size = (limit - base) + 1U;
            sau_rom_registered = true;
            sau_model_ro_open = true;
            printf("[SECURE SAU] REGISTER ROM: 0x%08X..0x%08X\n", base, limit);
            return PSA_SUCCESS;
        }

    case DP_CMD_SAU_REGISTER_CODE:
        {
            if (msg->in_size[1] != 8U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint32_t params[2] = {0U, 0U};
            psa_read(msg->handle, 1, params, sizeof(params));

            uint32_t raw_base = params[0];
            uint32_t raw_size = params[1];
            if (raw_size == 0U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            if (!normalize_flash_base_to_ns_alias(&raw_base, raw_size)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint32_t raw_limit = raw_base + raw_size - 1U;
            if (raw_limit < raw_base) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint32_t base = raw_base & ~0x1FU;
            uint32_t limit = raw_limit | 0x1FU;
            if (base < sau_ns_flash_base || limit > sau_ns_flash_limit || limit < base) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            sau_code_base = base;
            sau_code_size = (limit - base) + 1U;
            sau_code_registered = true;
            printf("[SECURE SAU] REGISTER CODE: 0x%08X..0x%08X\n", base, limit);
            return PSA_SUCCESS;
        }

    case DP_CMD_SET_LATE_SECRET_HASH:
        {
            return tfm_dp_set_late_secret_hash(msg);
        }

    case DP_CMD_GET_SAU_ROM_STATE:
        {
            if (msg->out_size[0] < 9U) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            uint8_t out[9] = {0};
            out[0] = sau_rom_registered ? (sau_model_ro_open ? 1U : 2U) : 0U;
            out[1] = (uint8_t)(sau_rom_base & 0xFFU);
            out[2] = (uint8_t)((sau_rom_base >> 8) & 0xFFU);
            out[3] = (uint8_t)((sau_rom_base >> 16) & 0xFFU);
            out[4] = (uint8_t)((sau_rom_base >> 24) & 0xFFU);
            out[5] = (uint8_t)(sau_rom_size & 0xFFU);
            out[6] = (uint8_t)((sau_rom_size >> 8) & 0xFFU);
            out[7] = (uint8_t)((sau_rom_size >> 16) & 0xFFU);
            out[8] = (uint8_t)((sau_rom_size >> 24) & 0xFFU);
            psa_write(msg->handle, 0, out, sizeof(out));
            return PSA_SUCCESS;
        }

    case DP_CMD_GET_DEVICE_PUBKEY:
        {
            if (msg->out_size[0] != sizeof(s_device_pubkey) || !s_device_key_ready) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            psa_write(msg->handle, 0, s_device_pubkey, sizeof(s_device_pubkey));
            return PSA_SUCCESS;
        }

    case DP_CMD_SIGN_ATTEST_MSG:
        {
            uint8_t msg_buf[64];
            uint8_t digest[32];
            uint8_t sig[64];
            size_t digest_len = 0U;
            size_t sig_len = 0U;

            if (msg->in_size[1] != sizeof(msg_buf) || msg->out_size[0] != sizeof(sig) || !s_device_key_ready) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            psa_read(msg->handle, 1, msg_buf, sizeof(msg_buf));

            psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256,
                                               msg_buf,
                                               sizeof(msg_buf),
                                               digest,
                                               sizeof(digest),
                                               &digest_len);
            if (st != PSA_SUCCESS || digest_len != sizeof(digest)) {
                return PSA_ERROR_GENERIC_ERROR;
            }

            st = psa_sign_hash(s_device_sign_key_id,
                               PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                               digest,
                               sizeof(digest),
                               sig,
                               sizeof(sig),
                               &sig_len);
            if (st != PSA_SUCCESS || sig_len != sizeof(sig)) {
                return PSA_ERROR_GENERIC_ERROR;
            }

            psa_write(msg->handle, 0, sig, sizeof(sig));
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

    /* Initialize secure-only model identity and cache EnclaveInfo in S world. */
    init_secure_model_identity();

    psa_status_t key_st = init_secure_device_signing_key();
    if (key_st != PSA_SUCCESS) {
        printf("[SECURE INIT] Device signing key init failed: %d\n", (int)key_st);
        return key_st;
    }

    /* Scan and save TF-M's NS-RAM SAU region limits for runtime splits. */
    sau_partition_init();

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