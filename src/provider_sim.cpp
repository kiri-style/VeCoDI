/*
 * Provider Simulator - M_update Message Generation
 *
 * Simulates cryptographic message generation for enclave updates with:
 * - Hardcoded provider key (sk_p, pk_p)
 * - Hardcoded verifier key (sk_v, pk_v) 
 * - Hardcoded session key (from Secure AES-256 key for simulation)
 * - AES-256-GCM encryption for AuthEnc
 */

#include "provider_sim.h"
#include <string.h>
#include <stdio.h>
#include <psa/crypto.h>

/* Hardcoded Provider keys (ECDSA P-256, simulation only) */
static const uint8_t provider_sk[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};

static const uint8_t provider_pk[64] = {
    /* x-coordinate (32 bytes) */
    0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
    0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
    0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x40,
    /* y-coordinate (32 bytes) */
    0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
    0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,
    0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
    0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,0x60
};

/* Hardcoded Verifier keys (ECDSA P-256, simulation only) */
static const uint8_t verifier_sk[32] = {
    0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,
    0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,
    0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,
    0x79,0x7A,0x7B,0x7C,0x7D,0x7E,0x7F,0x80
};

static const uint8_t verifier_pk[64] = {
    /* x-coordinate (32 bytes) */
    0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,
    0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F,0x90,
    0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,
    0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F,0xA0,
    /* y-coordinate (32 bytes) */
    0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,
    0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0,
    0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,
    0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,0xC0
};

/* Session key (shared secret from Secure partition AES-256 key, truncated for simulation) */
static const uint8_t session_key[32] = {
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
    0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
};

/* Static state */
static int provider_initialized = 0;

void provider_sim_init(void)
{
    if (provider_initialized) {
        return;
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[PROVIDER] ERROR: PSA crypto init failed: %d\n", status);
        return;
    }

    provider_initialized = 1;
    printf("\n[PROVIDER] ========== SIMULATOR INITIALIZED ==========\n");
    printf("[PROVIDER] Hardcoded keys loaded:\n");
    printf("[PROVIDER]   - Provider SK: %u bytes\n", (unsigned)sizeof(provider_sk));
    printf("[PROVIDER]   - Provider PK (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", provider_pk[i]);
    printf("\n");
    printf("[PROVIDER]   - Verifier SK: %u bytes\n", (unsigned)sizeof(verifier_sk));
    printf("[PROVIDER]   - Verifier PK (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", verifier_pk[i]);
    printf("\n");
    printf("[PROVIDER]   - Session Key (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", session_key[i]);
    printf("\n");
    printf("[PROVIDER] ==================================================\n\n");
}

void provider_sim_get_public_key(uint8_t *pk_p_out)
{
    memcpy(pk_p_out, provider_pk, 64);
}

/**
 * Serialize M_update payload in binary format
 * Payload = c_limit (4) || pk_v (64) || enclave_info (32) || cert_len (4) || cert (var)
 */
static size_t serialize_m_update_payload(
    const m_update_payload_t *payload,
    uint8_t *buf,
    size_t buf_len)
{
    if (buf_len < 4 + 64 + 32 + 4 + payload->cert_len) {
        return 0;  /* Buffer too small */
    }

    size_t offset = 0;

    /* c_limit (4 bytes, little-endian) */
    buf[offset++] = (payload->c_limit >> 0) & 0xFF;
    buf[offset++] = (payload->c_limit >> 8) & 0xFF;
    buf[offset++] = (payload->c_limit >> 16) & 0xFF;
    buf[offset++] = (payload->c_limit >> 24) & 0xFF;

    /* pk_v (64 bytes) */
    memcpy(&buf[offset], payload->pk_v, 64);
    offset += 64;

    /* enclave_info (32 bytes) */
    memcpy(&buf[offset], payload->enclave_info, 32);
    offset += 32;

    /* cert_len (4 bytes, little-endian) */
    buf[offset++] = (payload->cert_len >> 0) & 0xFF;
    buf[offset++] = (payload->cert_len >> 8) & 0xFF;
    buf[offset++] = (payload->cert_len >> 16) & 0xFF;
    buf[offset++] = (payload->cert_len >> 24) & 0xFF;

    /* cert (variable length) */
    if (payload->cert_len > 0 && payload->cert != NULL) {
        memcpy(&buf[offset], payload->cert, payload->cert_len);
        offset += payload->cert_len;
    }

    return offset;
}

int provider_sim_generate_m_update(
    uint32_t c_limit,
    const uint8_t *enclave_info,
    const uint8_t *cert,
    uint32_t cert_len,
    m_update_message_t *m_update_out)
{
    if (!provider_initialized) {
        printf("[PROVIDER] ERROR: Not initialized\n");
        return -1;
    }

    if (!enclave_info || !m_update_out) {
        printf("[PROVIDER] ERROR: Invalid parameters\n");
        return -1;
    }

    /* Validate cert size */
    if (cert_len > 128) {
        printf("[PROVIDER] ERROR: Certificate too large (%u > 128)\n", cert_len);
        return -1;
    }

    printf("\n[PROVIDER] ========== GENERATING M_UPDATE ==========\n");
    printf("[PROVIDER] Input Parameters:\n");
    printf("[PROVIDER]   - c_limit: %u\n", c_limit);
    printf("[PROVIDER]   - enclave_info (first 16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02X ", enclave_info[i]);
    printf("\n");
    printf("[PROVIDER]   - cert_len: %u bytes\n", cert_len);
    if (cert_len > 0) {
        printf("[PROVIDER]   - cert (first 8 bytes): ");
        for (int i = 0; i < 8 && i < cert_len; i++) printf("%02X ", cert[i]);
        printf("\n");
    }

    /* Build payload */
    m_update_payload_t payload = {
        .c_limit = c_limit,
        .cert_len = cert_len
    };
    memcpy(payload.pk_v, verifier_pk, 64);
    memcpy(payload.enclave_info, enclave_info, 32);
    if (cert_len > 0 && cert) {
        memcpy(payload.cert, cert, cert_len);
    }

    /* Serialize payload */
    uint8_t plaintext[256];
    size_t plaintext_len = serialize_m_update_payload(&payload, plaintext, sizeof(plaintext));
    if (plaintext_len == 0) {
        printf("[PROVIDER] ERROR: Payload serialization failed\n");
        return -1;
    }

    printf("\n[PROVIDER] Step 1/3: Serialization\n");
    printf("[PROVIDER]   - Plaintext size: %zu bytes\n", plaintext_len);
    printf("[PROVIDER]   - Structure: c_limit(4) || pk_v(64) || enclave_info(32) || cert_len(4) || cert(%u)\n", 
           cert_len);
    printf("[PROVIDER]   - Plaintext (first 16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02X ", plaintext[i]);
    printf("\n");

    /* Encrypt with AES-256-GCM using session_key */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attr, session_key, 32, &key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        printf("[PROVIDER] ERROR: Key import failed: %d\n", status);
        return -1;
    }

    printf("\n[PROVIDER] Step 2/3: Key Import\n");
    printf("[PROVIDER]   - Algorithm: AES-256-GCM\n");
    printf("[PROVIDER]   - Key size: 256 bits (32 bytes)\n");
    printf("[PROVIDER]   - PSA status: %d (success)\n", status);

    /* Generate random nonce (12 bytes for GCM) */
    status = psa_generate_random(m_update_out->nonce, 12);
    if (status != PSA_SUCCESS) {
        printf("[PROVIDER] ERROR: Random nonce generation failed: %d\n", status);
        psa_destroy_key(key_id);
        return -1;
    }

    printf("\n[PROVIDER] Step 3a/3: Nonce Generation\n");
    printf("[PROVIDER]   - Nonce size: 12 bytes (96-bit for GCM)\n");
    printf("[PROVIDER]   - Nonce value: ");
    for (int i = 0; i < 12; i++) printf("%02X ", m_update_out->nonce[i]);
    printf("\n");

    /* Encrypt */
    size_t ciphertext_len;
    status = psa_aead_encrypt(
        key_id,
        PSA_ALG_GCM,
        m_update_out->nonce, 12,
        NULL, 0,  /* No additional authenticated data */
        plaintext, plaintext_len,
        m_update_out->ciphertext, sizeof(m_update_out->ciphertext),
        &ciphertext_len);

    if (status != PSA_SUCCESS) {
        printf("[PROVIDER] ERROR: Encryption failed: %d\n", status);
        psa_destroy_key(key_id);
        return -1;
    }

    printf("\n[PROVIDER] Step 3b/3: AES-256-GCM Encryption\n");
    printf("[PROVIDER]   - Input (plaintext) size: %zu bytes\n", plaintext_len);
    printf("[PROVIDER]   - Output (with tag) size: %zu bytes\n", ciphertext_len);

    /* Extract tag from output */
    if (ciphertext_len < 16) {
        printf("[PROVIDER] ERROR: Ciphertext too short for tag extraction\n");
        psa_destroy_key(key_id);
        return -1;
    }

    /* Copy ciphertext (without tag) */
    m_update_out->ciphertext_len = ciphertext_len - 16;
    memcpy(m_update_out->tag, &m_update_out->ciphertext[m_update_out->ciphertext_len], 16);

    printf("[PROVIDER]   - Ciphertext size (excl. tag): %zu bytes\n", m_update_out->ciphertext_len);
    printf("[PROVIDER]   - Auth tag size: 16 bytes (128-bit)\n");
    printf("[PROVIDER]   - Ciphertext (first 16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02X ", m_update_out->ciphertext[i]);
    printf("\n");
    printf("[PROVIDER]   - Auth tag (full): ");
    for (int i = 0; i < 16; i++) printf("%02X ", m_update_out->tag[i]);
    printf("\n");

    psa_destroy_key(key_id);

    printf("\n[PROVIDER] ========== M_UPDATE READY ==========\n");
    printf("[PROVIDER] Final Message Structure:\n");
    printf("[PROVIDER]   - ciphertext: %zu bytes\n", m_update_out->ciphertext_len);
    printf("[PROVIDER]   - nonce: 12 bytes\n");
    printf("[PROVIDER]   - tag: 16 bytes\n");
    printf("[PROVIDER]   - Total: %zu bytes\n\n", m_update_out->ciphertext_len + 12 + 16);

    return 0;
}
