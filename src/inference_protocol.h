#ifndef INFERENCE_PROTOCOL_H
#define INFERENCE_PROTOCOL_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * Inference Protocol Structures (M_inf / PoX)
 *=============================================================================*/

#define MODEL_ID_SIZE           4       // uint32_t
#define NONCE_SIZE              12      // 12 bytes for nonce
#define ECDSA_SIG_SIZE          64      // ECDSA P-256 signature (r||s)
#define CERT_SIZE               16      // Simplified certificate
#define CIFAR10_OUTPUT_SIZE     1       // Single class (0-9)

/*=============================================================================
 * M_inf: Message from Verifier to Device
 *=============================================================================*/

typedef struct {
    uint8_t nonce[NONCE_SIZE];                          // Random 12 bytes
    uint8_t model_id[MODEL_ID_SIZE];                    // Model identifier
    uint8_t signature[ECDSA_SIG_SIZE];                  // Sign(sk_v, nonce||model_id)
} m_inf_t;

/*=============================================================================
 * PoX: Proof of Execution from Device to Verifier
 *=============================================================================*/

typedef struct {
    uint8_t model_id[MODEL_ID_SIZE];                    // Model identifier
    uint8_t cert[CERT_SIZE];                            // Cert(sk_p, model_id)
    uint8_t nonce[NONCE_SIZE];                          // Echo from M_inf
    uint8_t output;                                     // Inference result (0-9)
    uint8_t signature[ECDSA_SIG_SIZE];                  // Sign(sk_d, above fields)
} proof_of_execution_t;

/*=============================================================================
 * Device-Side Functions (Non-Secure)
 *=============================================================================*/

/**
 * Verify M_inf signature (sk_v is known to device)
 * 
 * @param m_inf: Received M_inf message
 * @param verifier_pk: Verifier's ECDSA P-256 public key (64 bytes)
 * @return 1 if signature valid, 0 otherwise
 */
int verify_m_inf(const m_inf_t *m_inf, const uint8_t verifier_pk[64]);

/**
 * Generate PoX (Proof of Execution)
 * 
 * @param m_inf: Original M_inf (for nonce echo)
 * @param inference_output: CIFAR-10 prediction (0-9)
 * @param device_sk: Device's ECDSA P-256 private key (32 bytes)
 * @param cert: Provider's certificate (16 bytes)
 * @param pox: Output proof of execution structure
 * @return 0 on success, -1 on failure
 */
int generate_proof_of_execution(
    const m_inf_t *m_inf,
    uint8_t inference_output,
    const uint8_t device_sk[32],
    const uint8_t cert[CERT_SIZE],
    proof_of_execution_t *pox
);

/*=============================================================================
 * Provider-Side Functions (Simulation in Non-Secure)
 *=============================================================================*/

/**
 * Generate M_inf (Verifier creates request)
 * The input image is not transmitted; the device uses its own stored test image.
 *
 * @param model_id: Model identifier (4 bytes)
 * @param verifier_sk: Verifier's ECDSA P-256 private key (32 bytes)
 * @param m_inf: Output message
 * @return 0 on success, -1 on failure
 */
int generate_m_inf(
    const uint8_t model_id[MODEL_ID_SIZE],
    const uint8_t verifier_sk[32],
    m_inf_t *m_inf
);

/**
 * Verify PoX (Verifier validates proof)
 * 
 * @param pox: Received proof of execution
 * @param device_pk: Device's ECDSA P-256 public key (64 bytes)
 * @param provider_pk: Provider's ECDSA P-256 public key (64 bytes)
 * @return 1 if all signatures valid, 0 otherwise
 */
int verify_proof_of_execution(
    const proof_of_execution_t *pox,
    const uint8_t device_pk[64],
    const uint8_t provider_pk[64]
);

#ifdef __cplusplus
}
#endif

#endif // INFERENCE_PROTOCOL_H
