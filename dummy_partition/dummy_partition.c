/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>

#include "psa/service.h"
#include "psa_manifest/tfm_dummy_partition.h"

#include "stm32l5xx_hal_secure_sram.h"

extern int tfm_platform_secure_sram(uint32_t base, uint32_t size);
#define CMD_GET_TOKEN_AND_OPEN   0x01
#define CMD_CLOSE_ACCESS         0x02
#define CMD_VERIFY_TOKEN 0x03
#define CMD_OPEN_MODEL_ACCESS   0x10
#define CMD_CLOSE_MODEL_ACCESS  0x11
#define CMD_RUN_INFERENCE       0x20
#define CMD_OPEN_INFERENCE_ACCESS   0x30
#define CMD_CLOSE_INFERENCE_ACCESS  0x31

/* ===== IRQn declarations ===== */
#include "core_cm33.h"

#define NS_INFERENCE_IRQn EXTI15_IRQn


static void secure_allow_model_access(uint32_t start, uint32_t size);
static void secure_deny_model_access(uint32_t start, uint32_t size);
static void secure_allow_inference_access(uint32_t start, uint32_t size);
static void secure_deny_inference_access(uint32_t start, uint32_t size);

/* ===== Model region descriptor (shared with NS) ===== */
struct model_region_desc {
    uint32_t start;
    uint32_t size;
};

struct inference_region_desc {
    uint32_t start;
    uint32_t size;
};



/* ========= GLOBAL STATE ========= */
static bool model_access_granted = false;
/* ========= Secure token state ========= */
#define INFERENCE_TOKEN_MAGIC 0xA5A5A5A5

static uint32_t g_token = 0;
static bool g_token_valid = false;

static psa_status_t generate_token(uint32_t *token)
{
    if (!token) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    g_token = INFERENCE_TOKEN_MAGIC;
    g_token_valid = true;
    
    

    *token = g_token;
    return PSA_SUCCESS;
}

#define NUM_SECRETS 5

struct dp_secret {
	uint8_t secret[16];
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
    /* =========================================================
     * CAS 1 : DEMANDE LEGACY — TOKEN SEUL
     * in  = 0
     * out = uint32_t token
     * ========================================================= */
    if (msg->in_size[0] == 0 &&
        msg->out_size[0] == sizeof(uint32_t)) {

        psa_status_t status = generate_token(&g_token);
        if (status != PSA_SUCCESS) {
            return status;
        }

        psa_write(msg->handle, 0, &g_token, sizeof(g_token));
        return PSA_SUCCESS;
    }

    /* =========================================================
     * CAS 2 : COMMANDE AVEC ARGUMENT
     * in[0] = uint32_t cmd
     * ========================================================= */
    if (msg->in_size[0] == sizeof(uint32_t)) {

        uint32_t cmd;
        size_t num = psa_read(msg->handle, 0, &cmd, sizeof(cmd));
        if (num != sizeof(cmd)) {
            return PSA_ERROR_PROGRAMMER_ERROR;
        }

        /* ===== GET TOKEN ===== */
        if (cmd == CMD_GET_TOKEN_AND_OPEN) {

            if (msg->out_size[0] != sizeof(uint32_t)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            psa_status_t status = generate_token(&g_token);
            if (status != PSA_SUCCESS) {
                return status;
            }

            psa_write(msg->handle, 0, &g_token, sizeof(g_token));
            return PSA_SUCCESS;
        }

        /* ===== VERIFY TOKEN ===== */
        if (cmd == CMD_VERIFY_TOKEN) {

            if (msg->in_size[1] != sizeof(uint32_t)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            uint32_t token;
            psa_read(msg->handle, 1, &token, sizeof(token));

            if (!g_token_valid || token != g_token) {
                return PSA_ERROR_NOT_PERMITTED;
            }

            return PSA_SUCCESS;
        }

        /* ===== OPEN MODEL ACCESS ===== */
        if (cmd == CMD_OPEN_MODEL_ACCESS) {

            if (msg->in_size[1] != sizeof(struct model_region_desc)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            struct model_region_desc desc;
            psa_read(msg->handle, 1, &desc, sizeof(desc));

            if (desc.size == 0) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            secure_allow_model_access(desc.start, desc.size);
            return PSA_SUCCESS;
        }

        /* ===== CLOSE MODEL ACCESS ===== */
        if (cmd == CMD_CLOSE_MODEL_ACCESS) {

            if (msg->in_size[1] != sizeof(struct model_region_desc)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            struct model_region_desc desc;
            psa_read(msg->handle, 1, &desc, sizeof(desc));

            secure_deny_model_access(desc.start, desc.size);
            return PSA_SUCCESS;
        }

        /* ===== OPEN INFERENCE ACCESS ===== */
        if (cmd == CMD_OPEN_INFERENCE_ACCESS) {

            if (msg->in_size[1] != sizeof(struct inference_region_desc)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            struct inference_region_desc desc;
            psa_read(msg->handle, 1, &desc, sizeof(desc));

            if (desc.size == 0) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }

            secure_allow_inference_access(desc.start, desc.size);
            return PSA_SUCCESS;
        }

        /* ===== CLOSE INFERENCE ACCESS ===== */
        if (cmd == CMD_CLOSE_INFERENCE_ACCESS) {

            if (msg->in_size[1] != sizeof(struct inference_region_desc)) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            struct inference_region_desc desc;
            psa_read(msg->handle, 1, &desc, sizeof(desc));

            secure_deny_inference_access(desc.start, desc.size);
            return PSA_SUCCESS;
        }
        /* ===== RUN INFERENCE (Option 2) ===== */
        if (cmd == CMD_RUN_INFERENCE) {

            if (!g_token_valid) {
                return PSA_ERROR_NOT_PERMITTED;
            }

            if (!model_access_granted) {
                return PSA_ERROR_NOT_PERMITTED;
            }

            /* déclencher l’exécution NS */
            NVIC_SetPendingIRQ(NS_INFERENCE_IRQn);

            return PSA_SUCCESS;
        }

        /* ===== CLOSE TOKEN ===== */
        if (cmd == CMD_CLOSE_ACCESS) {
            g_token_valid = false;
            g_token = 0;
            return PSA_SUCCESS;
        }

        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* =========================================================
     * CAS 3 : COMPORTEMENT EXISTANT — DIGEST
     * ========================================================= */
    if (msg->in_size[0] != sizeof(uint32_t)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    uint32_t secret_index;
    size_t num = psa_read(msg->handle, 0,
                          &secret_index,
                          sizeof(secret_index));
    if (num != sizeof(secret_index)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    return tfm_dp_secret_digest(secret_index,
                                msg->out_size[0],
                                &msg->out_size[0],
                                psa_write_digest,
                                (void *)msg->handle);
}
static void dp_signal_handle(psa_signal_t signal,
                 dp_func_t pfn)
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
    NVIC_DisableIRQ(NS_INFERENCE_IRQn);
    NVIC_ClearPendingIRQ(NS_INFERENCE_IRQn);

    /* rendre l’IRQ Non-Secure */
    NVIC_SetTargetState(NS_INFERENCE_IRQn);

    NVIC_EnableIRQ(NS_INFERENCE_IRQn);

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
		if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
			dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
					 tfm_dp_secret_digest_ipc);
		} else {
			psa_panic();
		}
	}

	return PSA_ERROR_SERVICE_FAILURE;
}
/* ===== TEMPORAIRE : placeholder mémoire modèle ===== */
/* À remplacer plus tard par la vraie zone du modèle */
/* ===== Model RO linker symbols (from NS image) ===== */

#define MODEL_SAU_REGION   7
/*static void secure_allow_model_access(void)
{
    rtpox_sau_disable();
*/
    /* Autoriser le NS à lire le modèle */
    /*rtpox_configure_sau_nonsecure(
        MODEL_FLASH_START,
        MODEL_FLASH_END,
        MODEL_SAU_REGION
    );

    rtpox_sau_enable();
    model_access_granted = true;
*/

   /* uint32_t start = (uint32_t)&__model_ro_start;
    uint32_t end   = (uint32_t)&__model_ro_end;

    rtpox_configure_sau_nonsecure(
        start,
        end,
        MODEL_SAU_REGION
    );
    printf("[SECURE] model_ro start=0x%08lx end=0x%08lx size=%lu\n",
       (unsigned long)start,
       (unsigned long)end,
       (unsigned long)(end - start));
    }

static void secure_deny_model_access(void)
{
    rtpox_sau_disable();
/*
    /* Re-rendre la zone Secure */
    /*rtpox_configure_sau_secure(
        MODEL_FLASH_START,
        MODEL_FLASH_END,
        MODEL_SAU_REGION
    );
*/
    /*uint32_t start = (uint32_t)&__model_ro_start;
    uint32_t end   = (uint32_t)&__model_ro_end;

    rtpox_configure_sau_secure(
        start,
        end,
        MODEL_SAU_REGION
    );
    rtpox_sau_enable();
    model_access_granted = false;
}*/

static void secure_allow_model_access(uint32_t start, uint32_t size)
{
    uint32_t end = start + size;

    rtpox_sau_disable();

    rtpox_configure_sau_nonsecure(
        start,
        end,
        MODEL_SAU_REGION
    );

    rtpox_sau_enable();

    model_access_granted = true;
}
static void secure_deny_model_access(uint32_t start, uint32_t size)
{
    uint32_t end = start + size;

    rtpox_sau_disable();

    rtpox_configure_sau_secure(
        start,
        end,
        MODEL_SAU_REGION
    );

    rtpox_sau_enable();

    model_access_granted = false;
}

#define INFERENCE_SAU_REGION  5   // libre, différent du modèle

static bool inference_access_granted = false;

static void secure_allow_inference_access(uint32_t start, uint32_t size)
{
    uint32_t end = start + size;

    rtpox_sau_disable();

    rtpox_configure_sau_nonsecure(
        start,
        end,
        INFERENCE_SAU_REGION
    );

    rtpox_sau_enable();

    inference_access_granted = true;
}

static void secure_deny_inference_access(uint32_t start, uint32_t size)
{
    uint32_t end = start + size;

    rtpox_sau_disable();

    rtpox_configure_sau_secure(
        start,
        end,
        INFERENCE_SAU_REGION
    );

    rtpox_sau_enable();

    inference_access_granted = false;
}