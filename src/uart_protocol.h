/* UART Protocol for Mac ↔ STM32 Communication */

#ifndef UART_PROTOCOL_H
#define UART_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol Commands (Mac → Device) */
#define CMD_COMPUTE_ENCLAVE_INFO    0x01
#define CMD_VALIDATE_AUTHORIZE      0x02
#define CMD_GET_MAX_INFERENCES      0x03
#define CMD_RUN_INFERENCE           0x04
#define CMD_GET_INFERENCE_COUNT     0x05
#define CMD_GET_REMAINING_INFERENCES 0x06
#define CMD_GET_BENCHMARK           0x08
#define CMD_GET_SECURE_BENCHMARK    0x09
#define CMD_GET_INFERENCE_RESULT    0x0A
#define CMD_SET_MAX_INFERENCES      0x0B
#define CMD_GET_DEVICE_PUBKEY       0x0C  /* Return pk_d (65B) for PoX verification */
#define CMD_GET_SAU_STATE           0x0D  /* Return SAU state: state(1)+base(4)+size(4) */
#define CMD_RUN_INFERENCE_NO_SAU    0x0E  /* DANGEROUS TEST: run inference path without SAU open */
#define CMD_READ_PROTECTED_MEM      0x0F  /* DANGEROUS TEST: direct read from protected enclave memory */
#define CMD_GET_ENCLAVE_STATE       0x10  /* Return enclave created state: created(1) */
#define CMD_CREATE_ENCLAVE          0x11  /* Secure lifecycle create; optional payload = decrypt size (u32 LE) */
#define CMD_DESTROY_ENCLAVE         0x12  /* Secure lifecycle destroy */
#define CMD_UPDATE_RATE_LIMIT       0x13  /* Secure lifecycle rate-limit update (u32 LE) */
#define CMD_RUN_INFERENCE_WITH_IMAGE 0x14  /* Upload CIFAR photo + run verified inference */
#define CMD_GET_TCB_BENCHMARK       0x15  /* Return TCB footprint (Secure + trusted NS windows) */
#define CMD_GET_INFERENCE_TRACE     0x1B  /* Return phase0/phase1 counters + last stage */
#define CMD_READ_PROTECTED_ROM      0x18  /* DANGEROUS TEST: direct read from protected model ROM */
/* Debug: return NS-side m_update metrics (uint64 cycles + uint32 count) */
#define CMD_GET_AUTHORIZE_DEBUG     0x1A
/* Response Codes (Device → Mac) */
#define RESP_OK                     0x00
#define RESP_ERROR                  0xFF

/* Protocol Limits */
#define MAX_COMMAND_DATA_SIZE       3201  // Maximum data in one command (label + CIFAR image + encrypted M_inf)
#define MAX_RESPONSE_DATA_SIZE      256  // Maximum data in one response

/* Packet Structure:
 * 
 * Request (Mac → Device):
 *   [CMD:1][LEN:4][DATA:n]
 * 
 * Response (Device → Mac):
 *   [STATUS:1][LEN:4][DATA:n]
 */

/**
 * @brief Initialize UART protocol handler
 * @return 0 on success, negative on error
 */
int uart_protocol_init(void);

/**
 * @brief Process incoming UART commands (call from main loop)
 * 
 * This function checks for incoming commands and processes them.
 * Should be called frequently from the main loop.
 */
void uart_protocol_process(void);

/**
 * @brief Send response back to Mac
 * 
 * @param status Response status (RESP_OK or RESP_ERROR)
 * @param data Response data (can be NULL if len=0)
 * @param len Length of response data
 * @return 0 on success, negative on error
 */
int uart_protocol_send_response(uint8_t status, const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* UART_PROTOCOL_H */
