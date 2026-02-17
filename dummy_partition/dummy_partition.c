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

extern int tfm_platform_secure_sram(uint32_t base, uint32_t size);

/* Secure linker symbols for memory stats */
extern char __bss_start__;
extern char __bss_end__;

static void print_secure_memory_stats(void)
{
    uint32_t bss_size = (uint32_t)(&__bss_end__ - &__bss_start__);

    printf("\n======= SECURE MEMORY STATS =======\n");
    printf("  BSS size:   %u bytes\n", bss_size);
    printf("  BSS range:  %p - %p\n", &__bss_start__, &__bss_end__);
    printf("===================================\n\n");
}

#define NUM_SECRETS 5
/* Enclave commands */

#define DP_CMD_SECRET_DIGEST   0
#define DP_CMD_SEAL_ENCLAVE    1
#define DP_CMD_DECRYPT_MODEL  2

struct dp_secret {
	uint8_t secret[16];
};

static const uint8_t aes_key[16] = {
    0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,
    0x1C,0x1D,0x1E,0x1F
};

struct dp_secret secrets[NUM_SECRETS] = {
	{ {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
	{ {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
};

typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
				     uint32_t digest_size);

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

	status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
				sizeof(secrets[secret_index].secret), digest,
				digest_size, p_digest_size);

	if (status != PSA_SUCCESS) {
		return status;
	}
	if (*p_digest_size != digest_size) {
		return PSA_ERROR_PROGRAMMER_ERROR;
	}

	callback(handle, digest, digest_size);

	return PSA_SUCCESS;
}

static psa_status_t tfm_dp_enclave_seal(psa_msg_t *msg)
{
    printf("\n--- SECURE: SEAL ENCLAVE + DECRYPT ---\n");
    printf("[SECURE] Request from NS to seal enclave\n");
    printf("[SECURE] msg->in_size[0] = %u (cmd)\n", (uint32_t)msg->in_size[0]);
    printf("[SECURE] msg->in_size[1] = %u (encrypted model)\n", (uint32_t)msg->in_size[1]);
    printf("[SECURE] msg->out_size[0] = %u (enclave buffer)\n", (uint32_t)msg->out_size[0]);
    print_secure_memory_stats();
    
    /* Decrypt model into NS enclave memory */
    if (msg->in_size[1] > 0 && msg->out_size[0] > 0) {
        printf("[SECURE] Decrypting model with XOR cipher...\n");
        printf("[SECURE] XOR Key: 0x42\n");
        
        #define XOR_KEY 0x42
        
        size_t model_len = msg->in_size[1];
        size_t enclave_size = msg->out_size[0];
        size_t processed = 0;
        uint8_t buffer[256];
        
        if (model_len > enclave_size) {
            printf("[SECURE] ✗ Model too large (%u > %u bytes)\n", 
                   (uint32_t)model_len, (uint32_t)enclave_size);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        
        printf("[SECURE] Starting decryption loop (chunk size: %u bytes)...\n", (uint32_t)sizeof(buffer));
        
        /* Decrypt model chunk by chunk and write to NS enclave */
        while (processed < model_len) {
            size_t chunk = (model_len - processed > sizeof(buffer)) ?
                           sizeof(buffer) : (model_len - processed);
            
            /* Read encrypted chunk from ROM */
            psa_read(msg->handle, 1, buffer, chunk);
            
            /* XOR decrypt */
            for (size_t i = 0; i < chunk; i++) {
                buffer[i] ^= XOR_KEY;
            }
            
            /* Write decrypted chunk to NS enclave memory */
            psa_write(msg->handle, 0, buffer, chunk);
            
            processed += chunk;
            
            if (processed % 1024 == 0 || processed == model_len) {
                uint32_t percent = (uint32_t)((processed * 100U) / model_len);
                printf("[SECURE] Progress: %u / %u bytes (%u%%)\n", 
                       (uint32_t)processed, (uint32_t)model_len, percent);
            }
        }
        
        printf("[SECURE] ✓ Model decrypted: %u bytes\n", (uint32_t)model_len);
    } else {
        printf("[SECURE] No model to decrypt (skipping)\n");
    }
    
    printf("[SECURE] Simulating hardware protection...\n");
    /* Ici on pourrait configurer MPU/SAU pour protéger enclave_memory */
    printf("[SECURE] ✓ Enclave locked (simulated)\n");
    printf("--- END SEAL ENCLAVE ---\n\n");
    
    return PSA_SUCCESS;
}

typedef psa_status_t (*dp_func_t)(psa_msg_t *);

#define SRAM1_START  0x20000000
#define SRAM1_END    0x20010000

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

static void psa_write_digest(void *handle, uint8_t *digest,
			     uint32_t digest_size)
{
    rtpox_sau_disable();    
	rtpox_configure_sau_nonsecure(SRAM1_START, SRAM1_END, 6);
    rtpox_sau_enable();   
	digest[0] = 0x75;
	psa_write((psa_handle_t)handle, 0, digest, digest_size);
}

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

        case DP_CMD_SEAL_ENCLAVE:
            return tfm_dp_enclave_seal(msg);

    case DP_CMD_DECRYPT_MODEL:
    {
        printf("[SECURE] Decrypting model with XOR cipher...\n");
        
        /* Simple XOR decryption (matches encrypt_model.py) */
        #define XOR_KEY 0x42
        
        size_t in_len = msg->in_size[1];
        size_t processed = 0;
        uint8_t buffer[256];  // Process in chunks
        
        while (processed < in_len) {
            size_t chunk = (in_len - processed > sizeof(buffer)) ?
                           sizeof(buffer) : (in_len - processed);
            
            /* Read encrypted chunk from NS */
            psa_read(msg->handle, 1, buffer, chunk);
            
            /* XOR decrypt */
            for (size_t i = 0; i < chunk; i++) {
                buffer[i] ^= XOR_KEY;
            }
            
            /* Write decrypted chunk back to NS enclave memory */
            psa_write(msg->handle, 0, buffer, chunk);
            
            processed += chunk;
        }
        
        printf("[SECURE] ✓ Model decrypted: %u bytes\n", (uint32_t)in_len);
        return PSA_SUCCESS;
    }

        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}



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



psa_status_t tfm_dp_req_mngr_init(void)
{
	psa_signal_t signals = 0;

    printf("\n[SECURE INIT] Dummy partition init\n");
    print_secure_memory_stats();

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