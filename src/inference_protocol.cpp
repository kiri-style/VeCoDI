#include "inference_protocol.h"
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

/*=============================================================================
 * Helper: Print hex values
 *=============================================================================*/

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("[PROTO] %s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02X ", data[i]);
    }
    if (len > 16) printf("... ");
    printf("(%zu bytes)\n", len);
}

/*=============================================================================
 * Device-Side: Verify M_inf
 *=============================================================================*/

int verify_m_inf(const m_inf_t *m_inf, const uint8_t verifier_pk[64]) {
    if (!m_inf || !verifier_pk) {
        printf("[ERROR] Invalid input to verify_m_inf\n");
        return 0;
    }

    printf("[DEVICE] ========== VERIFY M_INF ==========\n");
    print_hex("Nonce", m_inf->nonce, NONCE_SIZE);
    print_hex("Model ID", m_inf->model_id, MODEL_ID_SIZE);
    print_hex("Signature", m_inf->signature, ECDSA_SIG_SIZE);

    // Initialize PSA
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[ERROR] PSA crypto init failed: %d\n", status);
        return 0;
    }

    // Import verifier's public key for ECDSA verification
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t verifier_key_id;
    status = psa_import_key(&attributes, verifier_pk, 64, &verifier_key_id);
    if (status != PSA_SUCCESS) {
        printf("[ERROR] Failed to import verifier public key: %d\n", status);
        return 0;
    }

    // Prepare message to verify: nonce || model_id
    uint8_t message_to_verify[NONCE_SIZE + MODEL_ID_SIZE];
    memcpy(&message_to_verify[0], m_inf->nonce, NONCE_SIZE);
    memcpy(&message_to_verify[NONCE_SIZE], m_inf->model_id, MODEL_ID_SIZE);

    size_t message_len = NONCE_SIZE + MODEL_ID_SIZE;
    printf("[DEVICE] Message to verify: %zu bytes\n", message_len);

    // Verify signature
    status = psa_verify_message(verifier_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                message_to_verify, message_len,
                                m_inf->signature, ECDSA_SIG_SIZE);

    psa_destroy_key(verifier_key_id);

    if (status == PSA_SUCCESS) {
        printf("[DEVICE] ✓ M_inf signature verification SUCCESS\n");
        return 1;
    } else {
        printf("[DEVICE] ✗ M_inf signature verification FAILED: %d\n", status);
        return 0;
    }
}

/*=============================================================================
 * Device-Side: Generate Proof of Execution
 *=============================================================================*/

int generate_proof_of_execution(
    const m_inf_t *m_inf,
    uint8_t inference_output,
    const uint8_t device_sk[32],
    const uint8_t cert[CERT_SIZE],
    proof_of_execution_t *pox) {

    if (!m_inf || !device_sk || !cert || !pox) {
        printf("[ERROR] Invalid input to generate_proof_of_execution\n");
        return -1;
    }

    printf("[DEVICE] ========== GENERATE PoX ==========\n");
    printf("[DEVICE] Inference output: %d\n", inference_output);

    // Initialize PSA
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[ERROR] PSA crypto init failed: %d\n", status);
        return -1;
    }

    // Prepare PoX structure
    memcpy(pox->model_id, m_inf->model_id, MODEL_ID_SIZE);
    memcpy(pox->cert, cert, CERT_SIZE);
    memcpy(pox->nonce, m_inf->nonce, NONCE_SIZE);
    pox->output = inference_output;

    // Message to sign: model_id || cert || nonce || output
    uint8_t message_to_sign[MODEL_ID_SIZE + CERT_SIZE + NONCE_SIZE + CIFAR10_OUTPUT_SIZE];
    size_t offset = 0;

    memcpy(&message_to_sign[offset], pox->model_id, MODEL_ID_SIZE);
    offset += MODEL_ID_SIZE;
    memcpy(&message_to_sign[offset], pox->cert, CERT_SIZE);
    offset += CERT_SIZE;
    memcpy(&message_to_sign[offset], pox->nonce, NONCE_SIZE);
    offset += NONCE_SIZE;
    message_to_sign[offset] = pox->output;

    size_t message_len = MODEL_ID_SIZE + CERT_SIZE + NONCE_SIZE + 1;
    printf("[DEVICE] Message to sign: %zu bytes\n", message_len);
    printf("[DEVICE]   Structure: model_id(4) || cert(16) || nonce(12) || output(1)\n");

    // Import device private key for signing
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t device_key_id;
    status = psa_import_key(&attributes, device_sk, 32, &device_key_id);
    if (status != PSA_SUCCESS) {
        printf("[ERROR] Failed to import device private key: %d\n", status);
        return -1;
    }

    // Sign message
    size_t sig_len = 0;
    status = psa_sign_message(device_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             message_to_sign, message_len,
                             pox->signature, ECDSA_SIG_SIZE, &sig_len);

    psa_destroy_key(device_key_id);

    if (status != PSA_SUCCESS) {
        printf("[ERROR] Failed to sign PoX: %d\n", status);
        return -1;
    }

    if (sig_len != ECDSA_SIG_SIZE) {
        printf("[ERROR] Invalid signature length: %zu (expected %d)\n", sig_len, ECDSA_SIG_SIZE);
        return -1;
    }

    print_hex("PoX Signature", pox->signature, ECDSA_SIG_SIZE);
    printf("[DEVICE] ✓ PoX generated successfully\n");
    return 0;
}

/*=============================================================================
 * Provider-Side: Generate M_inf
 *=============================================================================*/

int generate_m_inf(
    const uint8_t model_id[MODEL_ID_SIZE],
    const uint8_t verifier_sk[32],
    m_inf_t *m_inf) {

    if (!model_id || !verifier_sk || !m_inf) {
        printf("[ERROR] Invalid input to generate_m_inf\n");
        return -1;
    }

    printf("[VERIFIER] ========== GENERATE M_INF ==========\n");

    // Initialize PSA
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[ERROR] PSA crypto init failed: %d\n", status);
        return -1;
    }

    // Generate random nonce
    status = psa_generate_random(m_inf->nonce, NONCE_SIZE);
    if (status != PSA_SUCCESS) {
        printf("[ERROR] Failed to generate nonce: %d\n", status);
        return -1;
    }
    print_hex("Generated nonce", m_inf->nonce, NONCE_SIZE);

    // Copy model_id (input image is NOT transmitted)
    memcpy(m_inf->model_id, model_id, MODEL_ID_SIZE);

    // Message to sign: nonce || model_id
    uint8_t message_to_sign[NONCE_SIZE + MODEL_ID_SIZE];
    memcpy(&message_to_sign[0], m_inf->nonce, NONCE_SIZE);
    memcpy(&message_to_sign[NONCE_SIZE], model_id, MODEL_ID_SIZE);

    size_t message_len = NONCE_SIZE + MODEL_ID_SIZE;
    printf("[VERIFIER] Message to sign: %zu bytes\n", message_len);
    printf("[VERIFIER]   Structure: nonce(12) || model_id(4)\n");

    // Import verifier private key for signing
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t verifier_key_id;
    status = psa_import_key(&attributes, verifier_sk, 32, &verifier_key_id);
    if (status != PSA_SUCCESS) {
        printf("[ERROR] Failed to import verifier private key: %d\n", status);
        return -1;
    }

    // Sign message
    size_t sig_len = 0;
    status = psa_sign_message(verifier_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             message_to_sign, message_len,
                             m_inf->signature, ECDSA_SIG_SIZE, &sig_len);

    psa_destroy_key(verifier_key_id);

    if (status != PSA_SUCCESS) {
        printf("[ERROR] Failed to sign M_inf: %d\n", status);
        return -1;
    }

    if (sig_len != ECDSA_SIG_SIZE) {
        printf("[ERROR] Invalid signature length: %zu (expected %d)\n", sig_len, ECDSA_SIG_SIZE);
        return -1;
    }

    print_hex("M_inf signature", m_inf->signature, ECDSA_SIG_SIZE);
    printf("[VERIFIER] ✓ M_inf generated successfully (%zu bytes total)\n", 
           sizeof(m_inf_t));
    return 0;
}

/*=============================================================================
 * Provider-Side: Verify Proof of Execution
 *=============================================================================*/

int verify_proof_of_execution(
    const proof_of_execution_t *pox,
    const uint8_t device_pk[64],
    const uint8_t provider_pk[64]) {

    if (!pox || !device_pk || !provider_pk) {
        printf("[ERROR] Invalid input to verify_proof_of_execution\n");
        return 0;
    }

    printf("[VERIFIER] ========== VERIFY PoX ==========\n");
    print_hex("Model ID", pox->model_id, MODEL_ID_SIZE);
    print_hex("Nonce", pox->nonce, NONCE_SIZE);
    print_hex("Output", &pox->output, 1);
    print_hex("PoX signature", pox->signature, ECDSA_SIG_SIZE);

    // Initialize PSA
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[ERROR] PSA crypto init failed: %d\n", status);
        return 0;
    }

    // Import device public key for verification
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t device_key_id;
    status = psa_import_key(&attributes, device_pk, 64, &device_key_id);
    if (status != PSA_SUCCESS) {
        printf("[ERROR] Failed to import device public key: %d\n", status);
        return 0;
    }

    // Message that should have been signed: model_id || cert || nonce || output
    uint8_t message_to_verify[MODEL_ID_SIZE + CERT_SIZE + NONCE_SIZE + CIFAR10_OUTPUT_SIZE];
    size_t offset = 0;

    memcpy(&message_to_verify[offset], pox->model_id, MODEL_ID_SIZE);
    offset += MODEL_ID_SIZE;
    memcpy(&message_to_verify[offset], pox->cert, CERT_SIZE);
    offset += CERT_SIZE;
    memcpy(&message_to_verify[offset], pox->nonce, NONCE_SIZE);
    offset += NONCE_SIZE;
    message_to_verify[offset] = pox->output;

    size_t message_len = MODEL_ID_SIZE + CERT_SIZE + NONCE_SIZE + 1;

    // Verify device's PoX signature
    status = psa_verify_message(device_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                message_to_verify, message_len,
                                pox->signature, ECDSA_SIG_SIZE);

    psa_destroy_key(device_key_id);

    if (status != PSA_SUCCESS) {
        printf("[VERIFIER] ✗ Device signature verification FAILED: %d\n", status);
        return 0;
    }

    printf("[VERIFIER] ✓ Device signature verified\n");

    // TODO: In production, also verify provider cert with provider_pk
    // For now, we assume cert is valid (hardcoded in simulation)
    printf("[VERIFIER] ✓ Provider certificate validated (assumed valid in simulation)\n");

    return 1;
}
