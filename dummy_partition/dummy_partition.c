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

/* Security policy: maximum inferences per enclave */
#define MAX_INFERENCES_PER_ENCLAVE  3

/* Secure inference counter (protected) */
static uint32_t inference_counter_secure = 0;

/* Fixed-size secret container used for digest service. */
struct dp_secret {
	uint8_t secret[16];
};

/* Static AES-CTR key used for late-weights decryption. */
static const uint8_t aes_key[16] = {
    0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,
    0x1C,0x1D,0x1E,0x1F
};

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
            uint32_t max_inf = MAX_INFERENCES_PER_ENCLAVE;
            psa_write(msg->handle, 0, &max_inf, sizeof(max_inf));
            SECURE_BENCHMARK_END(get_max_start, get_max_cycles);
            g_secure_metrics.counter_operations++;
            printf("[SECURE] Returned max inferences: %u\n", max_inf);
            return PSA_SUCCESS;
        }

    case DP_CMD_CHECK_INFERENCE_ALLOWED:
        {
            SECURE_BENCHMARK_START(check_start);
            uint32_t allowed = (inference_counter_secure + 1 <= MAX_INFERENCES_PER_ENCLAVE) ? 1 : 0;
            psa_write(msg->handle, 0, &allowed, sizeof(allowed));
            SECURE_BENCHMARK_END(check_start, check_allowed_cycles);
            g_secure_metrics.counter_operations++;
            printf("[SECURE] Check inference allowed: counter=%u, max=%u, allowed=%u\n", 
                   inference_counter_secure, MAX_INFERENCES_PER_ENCLAVE, allowed);
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