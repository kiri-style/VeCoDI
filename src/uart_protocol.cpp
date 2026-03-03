/* UART Protocol Implementation for Mac ↔ STM32 Communication */

#include "uart_protocol.h"
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/gpio.h>
#include <string.h>
#include <psa/crypto.h>

/* Debug mode: Set to 1 to enable diagnostics, 0 for clean protocol */
#define UART_DEBUG_MODE 0

/* UART device */
static const struct device *uart_dev = NULL;

/* RX activity LED (optional) */
static const struct gpio_dt_spec rx_led = GPIO_DT_SPEC_GET_OR(DT_ALIAS(led0), gpios, {0});
static bool rx_led_ready = false;

/* Reception state machine */
enum rx_state {
    RX_CMD,     // Waiting for command byte
    RX_LEN,     // Reading length (4 bytes)
    RX_DATA     // Reading data
};

static enum rx_state rx_state = RX_CMD;
static uint8_t rx_cmd = 0;
static uint32_t rx_len = 0;
static uint32_t rx_received = 0;
static uint8_t rx_buffer[MAX_COMMAND_DATA_SIZE];
static uint8_t len_buffer[4];
static uint32_t rx_data_start_ms = 0;

/* Protocol-only mock state (no inference execution) */
static uint8_t mock_enclave_info[32] = {0};
static uint32_t mock_max_inferences = 0;
static uint32_t mock_inference_count = 0;

/* Shared session key (must match tools/mac_provider.py) */
static const uint8_t session_key[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

static int extract_c_limit_from_m_update(const uint8_t *data, uint32_t len, uint32_t *c_limit)
{
    if (data == NULL || c_limit == NULL || len < 28U) {
        return -1;
    }

    const uint8_t *nonce = data;
    const uint8_t *ciphertext = data + 12;
    uint32_t ciphertext_len = len - 12U - 16U;
    const uint8_t *tag = data + 12U + ciphertext_len;

    uint8_t ciphertext_with_tag[MAX_COMMAND_DATA_SIZE];
    uint8_t plaintext[MAX_COMMAND_DATA_SIZE];
    size_t plaintext_len = 0;

    if ((ciphertext_len + 16U) > sizeof(ciphertext_with_tag)) {
        return -1;
    }

    memcpy(ciphertext_with_tag, ciphertext, ciphertext_len);
    memcpy(ciphertext_with_tag + ciphertext_len, tag, 16U);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return -1;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_key_id_t key_id = 0;
    status = psa_import_key(&attr, session_key, sizeof(session_key), &key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_aead_decrypt(key_id,
                              PSA_ALG_GCM,
                              nonce, 12U,
                              NULL, 0,
                              ciphertext_with_tag, ciphertext_len + 16U,
                              plaintext, sizeof(plaintext),
                              &plaintext_len);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || plaintext_len < sizeof(uint32_t)) {
        return -1;
    }

    *c_limit = (uint32_t)plaintext[0]
             | ((uint32_t)plaintext[1] << 8)
             | ((uint32_t)plaintext[2] << 16)
             | ((uint32_t)plaintext[3] << 24);

    return 0;
}

static bool is_valid_cmd(uint8_t cmd)
{
    return (cmd == CMD_COMPUTE_ENCLAVE_INFO ||
            cmd == CMD_VALIDATE_M_UPDATE ||
            cmd == CMD_GET_MAX_INFERENCES ||
            cmd == CMD_RUN_INFERENCE ||
            cmd == CMD_GET_INFERENCE_COUNT ||
            cmd == CMD_GET_REMAINING_INFERENCES);
}

static bool is_valid_len_for_cmd(uint8_t cmd, uint32_t len)
{
    switch (cmd) {
        case CMD_COMPUTE_ENCLAVE_INFO:
            /* Accept step1 tests (len=0) and provider packet (len=100) */
            return (len == 0U) || (len == 100U);
        case CMD_VALIDATE_M_UPDATE:
            /* nonce(12) + ciphertext(n) + tag(16) */
            return (len >= 28U) && (len <= MAX_COMMAND_DATA_SIZE);
        case CMD_GET_MAX_INFERENCES:
        case CMD_RUN_INFERENCE:
        case CMD_GET_INFERENCE_COUNT:
        case CMD_GET_REMAINING_INFERENCES:
            return len == 0U;
        default:
            return false;
    }
}

/* Forward declarations */
static void process_command(void);
static void handle_compute_enclave_info(const uint8_t *data, uint32_t len);
static void handle_validate_m_update(const uint8_t *data, uint32_t len);
static void handle_get_max_inferences(void);
static void handle_run_inference(void);
static void handle_get_inference_count(void);
static void handle_get_remaining_inferences(void);

int uart_protocol_init(void)
{
    uart_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
    
    if (!device_is_ready(uart_dev)) {
        return -1;
    }

    struct uart_config cfg = {
        .baudrate = 115200,
        .parity = UART_CFG_PARITY_NONE,
        .stop_bits = UART_CFG_STOP_BITS_1,
        .data_bits = UART_CFG_DATA_BITS_8,
        .flow_ctrl = UART_CFG_FLOW_CTRL_NONE,
    };

    (void)uart_configure(uart_dev, &cfg);
    
    // Wait for kernel boot to complete and flush any boot messages
    k_sleep(K_MSEC(500));
    
    // Clear RX buffer to remove any boot-time garbage
    uint8_t dummy;
    int count = 0;
    while (uart_poll_in(uart_dev, &dummy) == 0 && count < 1000) {
        count++;
    }

    // Initialize RX activity LED if available
    if (device_is_ready(rx_led.port)) {
        gpio_pin_configure_dt(&rx_led, GPIO_OUTPUT_INACTIVE);
        rx_led_ready = true;
        // Send startup signal: 3 short blinks
        for (int i = 0; i < 6; i++) {
            gpio_pin_toggle_dt(&rx_led);
            k_sleep(K_MSEC(30));
        }
    }
    
    return 0;
}

int uart_protocol_send_response(uint8_t status, const uint8_t *data, uint32_t len)
{
    if (!uart_dev) {
        return -1;
    }
    
    // Send status byte
    uart_poll_out(uart_dev, status);
    
    // Send length (4 bytes, little-endian)
    uart_poll_out(uart_dev, (len >> 0) & 0xFF);
    uart_poll_out(uart_dev, (len >> 8) & 0xFF);
    uart_poll_out(uart_dev, (len >> 16) & 0xFF);
    uart_poll_out(uart_dev, (len >> 24) & 0xFF);
    
    // Send data
    for (uint32_t i = 0; i < len; i++) {
        uart_poll_out(uart_dev, data[i]);
    }
    
    // Note: printk disabled during protocol to avoid interference
    // printk("[UART] → Response sent: status=0x%02X, len=%u\n", status, len);
    
    return 0;
}

void uart_protocol_process(void)
{
    if (!uart_dev) {
        return;
    }
    
    uint8_t byte;

    if (rx_state == RX_DATA) {
        uint32_t timeout_check = k_uptime_get_32();
        if (timeout_check - rx_data_start_ms > 1000) {
            rx_state = RX_CMD;
            rx_received = 0;
            rx_len = 0;
        }
    }
    
    while (uart_poll_in(uart_dev, &byte) == 0) {
        if (rx_led_ready) {
            gpio_pin_toggle_dt(&rx_led);
        }
        switch (rx_state) {
            case RX_CMD:
                if (!is_valid_cmd(byte)) {
                    if (UART_DEBUG_MODE) {
                        // Blink LED 3 times quickly to signal invalid cmd
                        for (int i = 0; i < 6; i++) {
                            gpio_pin_toggle_dt(&rx_led);
                            k_sleep(K_MSEC(50));
                        }
                    }
                    break;
                }
                rx_cmd = byte;
                rx_received = 0;
                rx_state = RX_LEN;
                if (UART_DEBUG_MODE) {
                    // Blink LED once to signal cmd received
                    gpio_pin_toggle_dt(&rx_led);
                    k_sleep(K_MSEC(100));
                    gpio_pin_toggle_dt(&rx_led);
                }
                break;
            
            case RX_LEN:
                len_buffer[rx_received++] = byte;
                if (rx_received == 4) {
                    rx_len = (uint32_t)len_buffer[0] |
                             ((uint32_t)len_buffer[1] << 8) |
                             ((uint32_t)len_buffer[2] << 16) |
                             ((uint32_t)len_buffer[3] << 24);
                    
                    if (!is_valid_len_for_cmd(rx_cmd, rx_len)) {
                        // Invalid length - send error with LED pattern (2 quick blinks)
                        if (UART_DEBUG_MODE) {
                            for (int i = 0; i < 4; i++) {
                                gpio_pin_toggle_dt(&rx_led);
                                k_sleep(K_MSEC(30));
                            }
                        }
                        uart_protocol_send_response(RESP_ERROR, NULL, 0);
                        rx_state = RX_CMD;
                        rx_received = 0;
                        rx_len = 0;
                    } else if (rx_len == 0) {
                        // No data, process immediately
                        rx_state = RX_CMD;
                        if (UART_DEBUG_MODE) {
                            // Single long blink for process
                            gpio_pin_toggle_dt(&rx_led);
                            k_sleep(K_MSEC(200));
                            gpio_pin_toggle_dt(&rx_led);
                        }
                        process_command();
                    } else if (rx_len > MAX_COMMAND_DATA_SIZE) {
                        // Data too large
                        if (UART_DEBUG_MODE) {
                            for (int i = 0; i < 8; i++) {
                                gpio_pin_toggle_dt(&rx_led);
                                k_sleep(K_MSEC(20));
                            }
                        }
                        uart_protocol_send_response(RESP_ERROR, NULL, 0);
                        rx_state = RX_CMD;
                    } else {
                        rx_received = 0;
                        rx_state = RX_DATA;
                        rx_data_start_ms = k_uptime_get_32();
                    }
                }
                break;
            
            case RX_DATA:
                rx_buffer[rx_received++] = byte;
                if (rx_received == rx_len) {
                    rx_state = RX_CMD;
                    process_command();
                }
                break;
        }
    }
}

static void process_command(void)
{
    switch (rx_cmd) {
        case CMD_COMPUTE_ENCLAVE_INFO:
            handle_compute_enclave_info(rx_buffer, rx_len);
            break;
        
        case CMD_VALIDATE_M_UPDATE:
            handle_validate_m_update(rx_buffer, rx_len);
            break;
        
        case CMD_GET_MAX_INFERENCES:
            handle_get_max_inferences();
            break;
        
        case CMD_RUN_INFERENCE:
            handle_run_inference();
            break;
        
        case CMD_GET_INFERENCE_COUNT:
            handle_get_inference_count();
            break;
        
        case CMD_GET_REMAINING_INFERENCES:
            handle_get_remaining_inferences();
            break;
        
        default:
            uart_protocol_send_response(RESP_ERROR, NULL, 0);
            break;
    }
}

/* ========== COMMAND HANDLERS ========== */

static void handle_compute_enclave_info(const uint8_t *data, uint32_t len)
{
    /* Protocol-only deterministic placeholder for EnclaveInfo (32 bytes) */
    memset(mock_enclave_info, 0, sizeof(mock_enclave_info));

    if (len > 0U && data != NULL) {
        for (uint32_t i = 0; i < len; i++) {
            mock_enclave_info[i % sizeof(mock_enclave_info)] ^= data[i];
        }
    } else {
        for (size_t i = 0; i < sizeof(mock_enclave_info); i++) {
            mock_enclave_info[i] = (uint8_t)(0xA0U + (uint8_t)i);
        }
    }

    uart_protocol_send_response(RESP_OK, mock_enclave_info, sizeof(mock_enclave_info));
}

static void handle_validate_m_update(const uint8_t *data, uint32_t len)
{
    uint32_t new_limit = 0;

    if (extract_c_limit_from_m_update(data, len, &new_limit) != 0 || new_limit == 0U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Anti-replay behavior: require strictly increasing limit. */
    if (new_limit <= mock_max_inferences) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    mock_max_inferences = new_limit;
    mock_inference_count = 0U;

    uart_protocol_send_response(RESP_OK, NULL, 0);
}

static void handle_get_max_inferences(void)
{
    uart_protocol_send_response(RESP_OK, (const uint8_t *)&mock_max_inferences, sizeof(mock_max_inferences));
}

static void handle_run_inference(void)
{
    /* Must have a valid M_update first. */
    if (mock_max_inferences == 0U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    if (mock_inference_count < mock_max_inferences) {
        mock_inference_count++;
        uart_protocol_send_response(RESP_OK, NULL, 0);
    } else {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
    }
}

static void handle_get_inference_count(void)
{
    /* Return the current inference counter (4 bytes, little-endian) */
    uint8_t count_bytes[4];
    count_bytes[0] = (mock_inference_count >> 0) & 0xFF;
    count_bytes[1] = (mock_inference_count >> 8) & 0xFF;
    count_bytes[2] = (mock_inference_count >> 16) & 0xFF;
    count_bytes[3] = (mock_inference_count >> 24) & 0xFF;
    
    uart_protocol_send_response(RESP_OK, count_bytes, 4);
}

static void handle_get_remaining_inferences(void)
{
    /* Calculate remaining inferences: max - count (4 bytes, little-endian) */
    uint32_t remaining = (mock_max_inferences > mock_inference_count) 
                         ? (mock_max_inferences - mock_inference_count) 
                         : 0U;
    
    uint8_t remaining_bytes[4];
    remaining_bytes[0] = (remaining >> 0) & 0xFF;
    remaining_bytes[1] = (remaining >> 8) & 0xFF;
    remaining_bytes[2] = (remaining >> 16) & 0xFF;
    remaining_bytes[3] = (remaining >> 24) & 0xFF;
    
    uart_protocol_send_response(RESP_OK, remaining_bytes, 4);
}
