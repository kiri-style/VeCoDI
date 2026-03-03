/*
 * Provider Simulator - M_update Message Generation
 *
 * Simulates a Model Provider generating cryptographically signed enclave update messages
 * with predefined keys (AES-256, ECDSA P-256).
 *
 * Protocol: M_update = AES-256-GCM(session_key, AuthEnc(C_limit || pk_v || EnclaveInfo || Cert))
 * For simulation: Using hardcoded session_key from Secure partition and AEAD encryption
 */

#ifndef PROVIDER_SIM_H
#define PROVIDER_SIM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* M_update message structure */
typedef struct {
    uint32_t c_limit;           /* New inference counter limit (4 bytes) */
    uint8_t pk_v[64];           /* Verifier public key - ECDSA P-256 (64 bytes: x||y) */
    uint8_t enclave_info[32];   /* Enclave information hash (32 bytes SHA-256) */
    uint8_t cert[128];          /* Certificate/signature (128 bytes) */
    uint32_t cert_len;          /* Actual certificate length */
} m_update_payload_t;

/* M_update message with encryption */
typedef struct {
    uint8_t ciphertext[256];    /* AES-256-GCM encrypted payload */
    size_t ciphertext_len;      /* Length of ciphertext */
    uint8_t nonce[12];          /* GCM nonce (96-bit) */
    uint8_t tag[16];            /* GCM authentication tag (128-bit) */
} m_update_message_t;

/**
 * Initialize provider simulator with predefined keys
 * Call this once at startup
 */
void provider_sim_init(void);

/**
 * Generate M_update message
 * 
 * @param c_limit: New inference counter limit
 * @param enclave_info: EnclaveInfo hash (32 bytes)
 * @param cert: Optional certificate data (can be NULL)
 * @param cert_len: Certificate length (0 if no certificate)
 * @param m_update_out: Output M_update encrypted message
 * @return: 0 on success, negative on error
 */
int provider_sim_generate_m_update(
    uint32_t c_limit,
    const uint8_t *enclave_info,
    const uint8_t *cert,
    uint32_t cert_len,
    m_update_message_t *m_update_out);

/**
 * Get provider's public key (for certificate verification)
 * 
 * @param pk_p_out: Output provider public key (64 bytes ECDSA P-256)
 */
void provider_sim_get_public_key(uint8_t *pk_p_out);

#ifdef __cplusplus
}
#endif

#endif /* PROVIDER_SIM_H */
