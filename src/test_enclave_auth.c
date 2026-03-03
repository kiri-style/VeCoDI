/*
 * Test: Enclave Authorization Protocol - EnclaveInfo + Provider M_update
 *
 * This test validates:
 * 1. EnclaveInfo computation via PSA IPC (Secure)
 * 2. M_update message generation via Provider Simulator (NS)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <psa/client.h>
#include <psa/crypto.h>

/* TFM manifest includes - defined in build */
#define TFM_DP_SERVICE_SID 0xFFFFF002
#define TFM_DP_SECRET_DIGEST_SIGNAL 1

#include "provider_sim.h"

/* PSA command constants */
#define DP_CMD_GET_MAX_INFERENCES  4
#define DP_CMD_COMPUTE_ENCLAVE_INFO 10
#define DP_CMD_VALIDATE_M_UPDATE    11

/* Test constants */
#define CIFAR_MODEL_ID 0x00000001
#define CIFAR_NEW_LIMIT 10

/* Simulate CIFAR model components */
static const uint8_t test_model_pub[32] = {
    0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,
    0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,
    0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,
    0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF
};

static const uint8_t test_model_secret[32] = {
    0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,
    0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,
    0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,
    0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF
};

static const uint8_t test_code_hash[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};

static const uint8_t test_cert[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};

/* Query current max inferences from Secure world. */
static psa_status_t ns_get_max_inferences(uint32_t *max_out)
{
    if (!max_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_handle_t handle = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        printf("[TEST] ERROR: Failed to connect to secure service\n");
        return PSA_ERROR_CONNECTION_REFUSED;
    }

    uint32_t cmd = DP_CMD_GET_MAX_INFERENCES;
    struct psa_invec in_vec = { .base = &cmd, .len = sizeof(cmd) };
    struct psa_outvec out_vec = { .base = max_out, .len = sizeof(*max_out) };

    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
    psa_close(handle);

    return status;
}

/*
 * Example Non-Secure wrapper for DP_CMD_VALIDATE_M_UPDATE
 *
 * Inputs:
 *  - nonce: 12 bytes
 *  - ciphertext: variable length (104..232 bytes)
 *  - tag: 16 bytes
 *
 * Output:
 *  - psa_status_t result (PSA_SUCCESS on valid M_update)
 */
static psa_status_t __attribute__((unused)) ns_validate_m_update(
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag)
{
    psa_handle_t handle = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        printf("[TEST] ERROR: Failed to connect to secure service\n");
        return PSA_ERROR_CONNECTION_REFUSED;
    }

    uint32_t cmd = DP_CMD_VALIDATE_M_UPDATE;

    struct psa_invec in_vec[4];
    in_vec[0].base = &cmd;
    in_vec[0].len  = sizeof(cmd);
    in_vec[1].base = nonce;
    in_vec[1].len  = 12;
    in_vec[2].base = ciphertext;
    in_vec[2].len  = ciphertext_len;
    in_vec[3].base = tag;
    in_vec[3].len  = 16;

    psa_status_t status = psa_call(handle, PSA_IPC_CALL, in_vec, 4, NULL, 0);
    psa_close(handle);

    return status;
}

/**
 * Compute EnclaveInfo via PSA IPC
 */
static int test_enclave_info_computation(uint8_t *enclave_info_out)
{
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║       PHASE 1: ENCLAVE INFO COMPUTATION (SECURE)     ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    printf("[TEST] Computing EnclaveInfo via PSA IPC...\n");
    printf("[TEST] Input Components:\n");
    printf("[TEST]   - Model_pub (32 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", test_model_pub[i]);
    printf("...\n");
    printf("[TEST]   - Model_secret (32 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", test_model_secret[i]);
    printf("...\n");
    printf("[TEST]   - code (SHA-256, 32 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", test_code_hash[i]);
    printf("...\n");
    printf("[TEST]   - model_ID: 0x%08X\n", CIFAR_MODEL_ID);
    printf("[TEST] Binary formula: SHA-256(Model_pub || Model_secret || code || model_ID)\n\n");

    /* Call Secure partition */
    psa_handle_t handle = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        printf("[TEST] ✗ ERROR: PSA connect failed\n");
        return -1;
    }

    printf("[TEST] PSA connection established\n");

    /* Pack data into a single buffer to respect PSA_MAX_IOVEC=4 limit
     * Format: model_pub(32) || model_secret(32) || code(32) = 96 bytes
     */
    uint8_t combined_data[96];
    memcpy(&combined_data[0], test_model_pub, 32);
    memcpy(&combined_data[32], test_model_secret, 32);
    memcpy(&combined_data[64], test_code_hash, 32);
    
    uint32_t cmd = DP_CMD_COMPUTE_ENCLAVE_INFO;
    uint32_t model_id_param = CIFAR_MODEL_ID;
    
    struct psa_invec in_vec[] = {
        {.base = &cmd, .len = sizeof(cmd)},
        {.base = combined_data, .len = 96},
        {.base = &model_id_param, .len = 4}
    };

    struct psa_outvec out_vec[] = {
        {.base = enclave_info_out, .len = 32}
    };

    printf("[TEST] Sending DP_CMD_COMPUTE_ENCLAVE_INFO (cmd=10) to Secure...\n");
    printf("[TEST]   Input buffers: 3 (cmd + combined_data[96] + model_id)\n");
    printf("[TEST]   Output buffers: 1 (32-byte hash)\n");
    
    psa_status_t status = psa_call(handle, PSA_IPC_CALL, in_vec, 3, out_vec, 1);
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printf("[TEST] ✗ ERROR: PSA call failed with status %d\n", status);
        printf("[TEST]   Note: Status -129 = PSA_ERROR_PROGRAMMER_ERROR\n");
        printf("[TEST]   Note: Status -141 = PSA_ERROR_INVALID_ARGUMENT\n");
        return -1;
    }

    printf("[TEST] ✓ PSA call successful\n");
    printf("\n[TEST] EnclaveInfo OUTPUT (SHA-256 hash):\n");
    printf("[TEST]   Full (32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", enclave_info_out[i]);
        if ((i + 1) % 8 == 0) printf("\n[TEST]                ");
    }
    printf("\n");

    printf("[TEST] ✓ SUCCESS: EnclaveInfo computed in Secure partition\n\n");
    return 0;
}

/**
 * Generate M_update message
 */
static int test_m_update_generation(const uint8_t *enclave_info)
{
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║    PHASE 2: M_UPDATE GENERATION (NON-SECURE)         ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    printf("[TEST] Initializing Provider Simulator...\n");
    provider_sim_init();

    printf("[TEST] Generating M_update message...\n");
    printf("[TEST] Parameters:\n");
    printf("[TEST]   - New counter limit (c_limit): %u\n", CIFAR_NEW_LIMIT);
    printf("[TEST]   - EnclaveInfo (received from Secure): %u bytes\n", 32);
    printf("[TEST]   - Certificate: %zu bytes\n", sizeof(test_cert));
    printf("[TEST]   - Encryption: AES-256-GCM\n\n");

    m_update_message_t m_update = {0};
    int result = provider_sim_generate_m_update(
        CIFAR_NEW_LIMIT,
        enclave_info,
        test_cert,
        sizeof(test_cert),
        &m_update);

    if (result != 0) {
        printf("[TEST] ✗ ERROR: M_update generation failed\n");
        return -1;
    }

    printf("\n[TEST] ✓ SUCCESS: M_update message generated\n");
    printf("[TEST] Output Message:\n");
    printf("[TEST]   - Ciphertext size: %zu bytes\n", m_update.ciphertext_len);
    printf("[TEST]   - Nonce (12 bytes):    ");
    for (int i = 0; i < 12; i++) printf("%02X ", m_update.nonce[i]);
    printf("\n");
    printf("[TEST]   - Auth tag (16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02X ", m_update.tag[i]);
    printf("\n");
    printf("[TEST]   - Total message: %zu + 12 + 16 = %zu bytes\n\n",
           m_update.ciphertext_len, m_update.ciphertext_len + 28);

    uint32_t max_before = 0;
    if (ns_get_max_inferences(&max_before) == PSA_SUCCESS) {
        printf("[TEST] Current max inferences (before M_update): %u\n", max_before);
    }

    printf("[TEST] Validating M_update in Secure World...\n");
    psa_status_t validate_status = ns_validate_m_update(
        m_update.nonce,
        m_update.ciphertext,
        m_update.ciphertext_len,
        m_update.tag);

    if (validate_status != PSA_SUCCESS) {
        printf("[TEST] ✗ ERROR: Secure validation failed: %d\n", validate_status);
        return -1;
    }

    printf("[TEST] ✓ SUCCESS: Secure validation passed\n");

    uint32_t max_after = 0;
    if (ns_get_max_inferences(&max_after) == PSA_SUCCESS) {
        printf("[TEST] Current max inferences (after M_update): %u\n", max_after);
        if (max_after != CIFAR_NEW_LIMIT) {
            printf("[TEST] ✗ ERROR: max_inferences not updated (expected %u)\n", CIFAR_NEW_LIMIT);
            return -1;
        }
    }

    printf("\n");

    return 0;
}

/**
 * Main test entry point
 */
int test_enclave_authorization_protocol(void)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║     ENCLAVE AUTHORIZATION PROTOCOL - FULL TEST        ║\n");
    printf("║                                                        ║\n");
    printf("║  Phase 1: EnclaveInfo computation in Secure world     ║\n");
    printf("║  Phase 2: M_update generation in Non-Secure world     ║\n");
    printf("║  Phase 3: M_update validation in Secure world         ║\n");
    printf("║                                                        ║\n");
    printf("║  Binary Formula: SHA-256(Model_pub || Model_secret || ║\n");
    printf("║                  code || model_ID)                    ║\n");
    printf("║  Encryption: AES-256-GCM with session key             ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");

    uint8_t enclave_info[32] = {0};

    /* Phase 1: Compute EnclaveInfo */
    if (test_enclave_info_computation(enclave_info) != 0) {
        printf("\n╔════════════════════════════════════════════════════════╗\n");
        printf("║              TEST FAILED AT PHASE 1                  ║\n");
        printf("║        EnclaveInfo computation in Secure            ║\n");
        printf("╚════════════════════════════════════════════════════════╝\n\n");
        return -1;
    }

    /* Phase 2: Generate M_update */
    if (test_m_update_generation(enclave_info) != 0) {
        printf("\n╔════════════════════════════════════════════════════════╗\n");
        printf("║              TEST FAILED AT PHASE 2                  ║\n");
        printf("║      M_update generation in Non-Secure world       ║\n");
        printf("╚════════════════════════════════════════════════════════╝\n\n");
        return -1;
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║              ALL TESTS PASSED ✓                       ║\n");
    printf("║                                                        ║\n");
    printf("║  ✓ EnclaveInfo computed successfully in Secure        ║\n");
    printf("║  ✓ M_update generated and encrypted in NS             ║\n");
    printf("║  ✓ Protocol validation complete                       ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");

    return 0;
}
