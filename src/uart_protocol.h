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
#define CMD_VALIDATE_M_UPDATE       0x02
#define CMD_GET_MAX_INFERENCES      0x03
#define CMD_RUN_INFERENCE           0x04
#define CMD_GET_INFERENCE_COUNT     0x05
#define CMD_GET_REMAINING_INFERENCES 0x06

/* Response Codes (Device → Mac) */
#define RESP_OK                     0x00
#define RESP_ERROR                  0xFF

/* Protocol Limits */
#define MAX_COMMAND_DATA_SIZE       256  // Maximum data in one command
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
