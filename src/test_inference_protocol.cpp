#include "inference_protocol.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <psa/crypto.h>

// Test Data: Hardcoded ECDSA P-256 Keys (from provider_sim)

// Verifier's ECDSA P-256 private key (32 bytes)
static const uint8_t test_verifier_sk[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// Device's ECDSA P-256 private key (32 bytes)
static const uint8_t test_device_sk[32] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
};

// Verifier's ECDSA P-256 public key (64 bytes)
static const uint8_t test_verifier_pk[64] = {
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
    0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0
};

// Device's ECDSA P-256 public key (64 bytes)
static const uint8_t test_device_pk[64] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60
};

// Provider's ECDSA P-256 public key (64 bytes)
static const uint8_t test_provider_pk[64] = {
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
    0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0
};

// Small test input (64 bytes) -- kept for reference, not transmitted in M_inf
static uint8_t test_model_id[MODEL_ID_SIZE] = {0x12, 0x34, 0x56, 0x78};
static uint8_t test_cert[CERT_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static void init_test_data(void) {
    /* nothing to initialise for now */
}

/*=============================================================================
 * Test: Inference Protocol (M_inf -> PoX)
 *=============================================================================*/

/*=============================================================================
 * Test: Inference Protocol (M_inf -> PoX) - Simplified
 *=============================================================================*/

extern "C" int test_inference_protocol(void) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║    INFERENCE PROTOCOL TEST (M_inf / PoX)              ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");

    init_test_data();

    // Initialize PSA once for all keys
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[TEST] ✗ PSA crypto init failed: %d\n", status);
        return -1;
    }

    // Step 1: Generate verifier keypair
    printf("\n[TEST] ===== STEP 1: GENERATE VERIFIER KEYPAIR =====\n");
    
    psa_key_attributes_t verifier_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&verifier_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&verifier_attr, 256);
    psa_set_key_usage_flags(&verifier_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&verifier_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t verifier_key_id;
    status = psa_generate_key(&verifier_attr, &verifier_key_id);
    if (status != PSA_SUCCESS) {
        printf("[TEST] ✗ Failed to generate verifier key: %d\n", status);
        return -1;
    }
    printf("[TEST] ✓ Verifier keypair generated\n");

    // Step 2: Generate device keypair
    printf("\n[TEST] ===== STEP 2: GENERATE DEVICE KEYPAIR =====\n");
    
    psa_key_attributes_t device_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&device_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&device_attr, 256);
    psa_set_key_usage_flags(&device_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&device_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t device_key_id;
    status = psa_generate_key(&device_attr, &device_key_id);
    if (status != PSA_SUCCESS) {
        printf("[TEST] ✗ Failed to generate device key: %d\n", status);
        psa_destroy_key(verifier_key_id);
        return -1;
    }
    printf("[TEST] ✓ Device keypair generated\n");

    // Step 3: Generate M_inf
    printf("\n[TEST] ===== STEP 3: VERIFIER GENERATES M_INF =====\n");
    m_inf_t m_inf = {};
    
    // Generate nonce
    status = psa_generate_random(m_inf.nonce, NONCE_SIZE);
    if (status != PSA_SUCCESS) {
        printf("[TEST] ✗ Failed to generate nonce: %d\n", status);
        psa_destroy_key(verifier_key_id);
        psa_destroy_key(device_key_id);
        return -1;
    }
    
    memcpy(m_inf.model_id, test_model_id, MODEL_ID_SIZE);

    // Message to sign: nonce || model_id
    uint8_t msg_to_sign[NONCE_SIZE + MODEL_ID_SIZE];
    memcpy(&msg_to_sign[0], m_inf.nonce, NONCE_SIZE);
    memcpy(&msg_to_sign[NONCE_SIZE], m_inf.model_id, MODEL_ID_SIZE);

    size_t msg_len = NONCE_SIZE + MODEL_ID_SIZE;
    size_t sig_len = 0;

    status = psa_sign_message(verifier_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             msg_to_sign, msg_len,
                             m_inf.signature, ECDSA_SIG_SIZE, &sig_len);
    
    if (status != PSA_SUCCESS || sig_len != ECDSA_SIG_SIZE) {
        printf("[TEST] ✗ Failed to sign M_inf: %d (sig_len=%zu)\n", status, sig_len);
        psa_destroy_key(verifier_key_id);
        psa_destroy_key(device_key_id);
        return -1;
    }

    printf("[TEST] ✓ M_inf generated and signed (%zu bytes total)\n", sizeof(m_inf_t));
    printf("[PROTO] Nonce: ");
    for (int i = 0; i < NONCE_SIZE; i++) printf("%02X ", m_inf.nonce[i]);
    printf("\n[PROTO] Signature (first 16B): ");
    for (int i = 0; i < 16; i++) printf("%02X ", m_inf.signature[i]);
    printf("\n");

    // Step 4: Device executes inference (simulated)
    printf("\n[TEST] ===== STEP 4: DEVICE EXECUTES INFERENCE =====\n");
    uint8_t inference_result = 6;
    printf("[DEVICE] Inference result: %d\n", inference_result);

    // Step 5: Generate Proof of Execution
    printf("\n[TEST] ===== STEP 5: DEVICE GENERATES PoX =====\n");
    
    proof_of_execution_t pox = {};
    memcpy(pox.model_id, m_inf.model_id, MODEL_ID_SIZE);
    memcpy(pox.cert, test_cert, CERT_SIZE);
    memcpy(pox.nonce, m_inf.nonce, NONCE_SIZE);
    pox.output = inference_result;

    // Message to sign for PoX: model_id || cert || nonce || output
    uint8_t pox_msg[MODEL_ID_SIZE + CERT_SIZE + NONCE_SIZE + 1];
    size_t pox_offset = 0;
    memcpy(&pox_msg[pox_offset], pox.model_id, MODEL_ID_SIZE);
    pox_offset += MODEL_ID_SIZE;
    memcpy(&pox_msg[pox_offset], pox.cert, CERT_SIZE);
    pox_offset += CERT_SIZE;
    memcpy(&pox_msg[pox_offset], pox.nonce, NONCE_SIZE);
    pox_offset += NONCE_SIZE;
    pox_msg[pox_offset] = pox.output;

    size_t pox_msg_len = MODEL_ID_SIZE + CERT_SIZE + NONCE_SIZE + 1;
    size_t pox_sig_len = 0;

    status = psa_sign_message(device_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             pox_msg, pox_msg_len,
                             pox.signature, ECDSA_SIG_SIZE, &pox_sig_len);
    
    if (status != PSA_SUCCESS || pox_sig_len != ECDSA_SIG_SIZE) {
        printf("[TEST] ✗ Failed to sign PoX: %d (sig_len=%zu)\n", status, pox_sig_len);
        psa_destroy_key(verifier_key_id);
        psa_destroy_key(device_key_id);
        return -1;
    }

    printf("[TEST] ✓ PoX generated and signed (%zu bytes total)\n", sizeof(proof_of_execution_t));
    printf("[PROTO] Output: %d\n", pox.output);
    printf("[PROTO] Signature (first 16B): ");
    for (int i = 0; i < 16; i++) printf("%02X ", pox.signature[i]);
    printf("\n");

    // Cleanup
    psa_destroy_key(verifier_key_id);
    psa_destroy_key(device_key_id);

    // Summary
    printf("\n");
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║         INFERENCE PROTOCOL TEST PASSED ✓               ║\n");
    printf("║                                                        ║\n");
    printf("║  ✓ Verifier keypair generated                         ║\n");
    printf("║  ✓ Device keypair generated                           ║\n");
    printf("║  ✓ M_inf generated and signed                         ║\n");
    printf("║  ✓ Device executed inference                          ║\n");
    printf("║  ✓ PoX generated and signed                           ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");

    return 0;
}
