/* UART Protocol Implementation for Mac ↔ STM32 Communication */

#include "uart_protocol.h"
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/gpio.h>
#include <string.h>
#include <psa/crypto.h>
#include <psa/client.h>
#include "run_enclave.h"

/* Secure partition constants (mirrors dummy_partition.h, not on NS include path) */
#define TFM_DP_SERVICE_SID          0xFFFFF002U
#define DP_CMD_COMPUTE_ENCLAVE_INFO 10U
#include "benchmark.h"
#include "secure_benchmark_ns.h"
#include "split_inference.h"

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
static uint32_t mock_max_inferences = 0;
static uint32_t mock_inference_count = 0;

/* Dynamic session key (derived via ECDH handshake) */
static uint8_t session_key[32] = {0};  /* Initialized to zeros, populated by ECDH */
static bool session_key_established = false;

/* Fallback static key for backward compatibility (testing only) */
static const uint8_t fallback_session_key[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

/* ========== KEY SCHEME: Dev(sk_d,pk_d)  Pvd(sk_p,pk_p)  Vrf(sk_v,pk_v) ========== */

/* Device signing key pair (sk_d / pk_d) — generated once at init, used for PoX */
static psa_key_id_t device_signing_key_id = 0;
static uint8_t      device_pk_d[65] = {0};   /* 0x04 || x(32) || y(32), uncompressed P-256 */
static bool         device_key_ready = false;

/* Verifier public key pk_v — extracted from M_update plaintext after Provider authorization */
static uint8_t stored_pk_v[64] = {0};        /* raw x(32) || y(32), no 0x04 prefix */
static bool    pk_v_valid = false;

/* Model authorization state extracted from M_update plaintext */
static uint32_t stored_model_id  = 0;        /* first 4 bytes of cert (LE uint32) */
static uint8_t  stored_cert[128] = {0};
static uint32_t stored_cert_len  = 0;

/*
 * Process M_update payload: decrypt with session_key and extract authorization fields.
 *
 * M_update plaintext layout (assembled by Provider/Pvd):
 *   c_limit(4) | pk_v(64) | EnclaveInfo(32) | cert_len(4) | cert(n)
 *   where cert[0..3] (LE) = model_id
 *
 * Side-effects (sets module-level state):
 *   stored_pk_v, pk_v_valid, stored_model_id, stored_cert, stored_cert_len
 */
static int process_m_update_payload(const uint8_t *data, uint32_t len, uint32_t *c_limit)
{
    if (data == NULL || c_limit == NULL || len < 28U) {
        return -1;
    }

    const uint8_t *nonce         = data;
    const uint8_t *ciphertext    = data + 12;
    uint32_t       ciphertext_len = len - 12U - 16U;
    const uint8_t *tag           = data + 12U + ciphertext_len;

    uint8_t ciphertext_with_tag[MAX_COMMAND_DATA_SIZE];
    uint8_t plaintext[MAX_COMMAND_DATA_SIZE];
    size_t  plaintext_len = 0;

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

    if (status != PSA_SUCCESS || plaintext_len < 4U) {
        return -1;
    }

    /* Parse plaintext: c_limit(4) | pk_v(64) | EnclaveInfo(32) | cert_len(4) | cert(n) */
    size_t off = 0U;

    /* c_limit (4 bytes LE) */
    *c_limit = (uint32_t)plaintext[off+0]
             | ((uint32_t)plaintext[off+1] << 8)
             | ((uint32_t)plaintext[off+2] << 16)
             | ((uint32_t)plaintext[off+3] << 24);
    off += 4U;

    /* pk_v: 64 bytes raw x||y (Verifier P-256 public key, no 0x04 prefix) */
    if (plaintext_len >= off + 64U) {
        memcpy(stored_pk_v, plaintext + off, 64U);
        pk_v_valid = true;
    }
    off += 64U;

    /* Skip EnclaveInfo (32 bytes) */
    off += 32U;

    /* cert_len (4 bytes LE) + cert bytes; cert[0..3] = model_id (LE) */
    if (plaintext_len >= off + 4U) {
        uint32_t clen = (uint32_t)plaintext[off+0]
                      | ((uint32_t)plaintext[off+1] << 8)
                      | ((uint32_t)plaintext[off+2] << 16)
                      | ((uint32_t)plaintext[off+3] << 24);
        off += 4U;
        if (clen <= sizeof(stored_cert) && plaintext_len >= off + clen) {
            stored_cert_len = clen;
            memcpy(stored_cert, plaintext + off, clen);
            /* model_id = first 4 bytes of cert (LE) */
            if (clen >= 4U) {
                stored_model_id = (uint32_t)stored_cert[0]
                                | ((uint32_t)stored_cert[1] << 8)
                                | ((uint32_t)stored_cert[2] << 16)
                                | ((uint32_t)stored_cert[3] << 24);
            }
        }
    }

    return 0;
}

/*
 * Generate device signing key pair (sk_d, pk_d) using P-256 ECDSA.
 * Called once at uart_protocol_init().  sk_d stays volatile; pk_d is exported
 * to device_pk_d[65] for retrieval via CMD_GET_DEVICE_PUBKEY.
 */
static int init_device_signing_key(void)
{
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return -1;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&attr, &device_signing_key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    size_t pk_len = 0;
    status = psa_export_public_key(device_signing_key_id,
                                   device_pk_d, sizeof(device_pk_d), &pk_len);
    if (status != PSA_SUCCESS || pk_len != 65U) {
        psa_destroy_key(device_signing_key_id);
        device_signing_key_id = 0;
        return -1;
    }

    device_key_ready = true;
    return 0;
}

/*
 * AES-256-GCM encrypt using session_key.
 * Output layout: nonce(12) || ciphertext(pt_len) || tag(16)  [total: pt_len+28]
 */
static int uart_encrypt(const uint8_t *pt, size_t pt_len,
                        uint8_t *out, size_t out_max, size_t *out_len)
{
    if (!session_key_established || pt == NULL || pt_len == 0U) {
        return -1;
    }
    if (out_max < pt_len + 28U) {
        return -1;
    }

    /* Random 12-byte nonce placed at start of output */
    if (psa_generate_random(out, 12U) != PSA_SUCCESS) {
        return -1;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_key_id_t key_id = 0;
    psa_status_t st = psa_import_key(&attr, session_key, 32U, &key_id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        return -1;
    }

    size_t ct_tag_len = 0;
    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          out, 12U,
                          NULL, 0U,
                          pt, pt_len,
                          out + 12U, out_max - 12U, &ct_tag_len);
    psa_destroy_key(key_id);

    if (st != PSA_SUCCESS) {
        return -1;
    }

    *out_len = 12U + ct_tag_len;
    return 0;
}

/*
 * AES-256-GCM decrypt using session_key.
 * Input layout: nonce(12) || ciphertext(n) || tag(16)  (enc_len >= 28)
 */
static int uart_decrypt(const uint8_t *enc, size_t enc_len,
                        uint8_t *out, size_t out_max, size_t *out_len)
{
    if (!session_key_established || enc == NULL || enc_len < 28U) {
        return -1;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_key_id_t key_id = 0;
    psa_status_t st = psa_import_key(&attr, session_key, 32U, &key_id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        return -1;
    }

    st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                          enc, 12U,
                          NULL, 0U,
                          enc + 12U, enc_len - 12U,
                          out, out_max, out_len);
    psa_destroy_key(key_id);
    return (st == PSA_SUCCESS) ? 0 : -1;
}

/*
 * Encrypt plaintext and send as UART response.
 * Falls back to plaintext if session_key is not yet established.
 */
static void uart_send_encrypted_response(uint8_t status,
                                         const uint8_t *pt, size_t pt_len)
{
    if (!session_key_established || pt == NULL || pt_len == 0U) {
        uart_protocol_send_response(status, pt, (uint32_t)pt_len);
        return;
    }

    /* nonce(12) + ciphertext(pt_len) + tag(16) */
    uint8_t enc_buf[MAX_RESPONSE_DATA_SIZE];
    size_t  enc_len = 0;

    if (uart_encrypt(pt, pt_len, enc_buf, sizeof(enc_buf), &enc_len) != 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    uart_protocol_send_response(status, enc_buf, (uint32_t)enc_len);
}

static bool is_valid_cmd(uint8_t cmd)
{
    return (cmd == CMD_COMPUTE_ENCLAVE_INFO ||
            cmd == CMD_VALIDATE_M_UPDATE ||
            cmd == CMD_GET_MAX_INFERENCES ||
            cmd == CMD_RUN_INFERENCE ||
            cmd == CMD_GET_INFERENCE_COUNT ||
            cmd == CMD_GET_REMAINING_INFERENCES ||
            cmd == CMD_ECDH_HANDSHAKE ||
            cmd == CMD_GET_BENCHMARK ||
            cmd == CMD_GET_SECURE_BENCHMARK ||
            cmd == CMD_GET_INFERENCE_RESULT ||
            cmd == CMD_SET_MAX_INFERENCES ||
            cmd == CMD_GET_DEVICE_PUBKEY);
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
        case CMD_GET_INFERENCE_COUNT:
        case CMD_GET_REMAINING_INFERENCES:
        case CMD_GET_BENCHMARK:
        case CMD_GET_SECURE_BENCHMARK:
        case CMD_GET_INFERENCE_RESULT:
        case CMD_GET_DEVICE_PUBKEY:
            return len == 0U;
        case CMD_RUN_INFERENCE:
            /* len=0: legacy (no M_inf);  len=128: new protocol (encrypted M_inf) */
            return (len == 0U) || (len == 128U);
        case CMD_SET_MAX_INFERENCES:
            return len == 4U;  /* Max inferences is uint32_t */
        case CMD_ECDH_HANDSHAKE:
            return len == 65U;  /* Uncompressed P-256 public key: 0x04 || x || y */
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
static void handle_ecdh_handshake(const uint8_t *data, uint32_t len);
static void handle_get_benchmark(void);
static void handle_get_secure_benchmark(void);
static void handle_get_inference_result(void);
static void handle_set_max_inferences(const uint8_t *data, uint32_t len);
static void handle_get_device_pubkey(void);

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

    /* Generate device signing key pair (sk_d, pk_d) for PoX */
    init_device_signing_key();

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
        
        case CMD_ECDH_HANDSHAKE:
            handle_ecdh_handshake(rx_buffer, rx_len);
            break;
        
        case CMD_GET_BENCHMARK:
            handle_get_benchmark();
            break;
        
        case CMD_GET_SECURE_BENCHMARK:
            handle_get_secure_benchmark();
            break;
        
        case CMD_GET_INFERENCE_RESULT:
            handle_get_inference_result();
            break;
        
        case CMD_SET_MAX_INFERENCES:
            handle_set_max_inferences(rx_buffer, rx_len);
            break;

        case CMD_GET_DEVICE_PUBKEY:
            handle_get_device_pubkey();
            break;

        default:
            uart_protocol_send_response(RESP_ERROR, NULL, 0);
            break;
    }
}

/* ========== COMMAND HANDLERS ========== */

static void handle_compute_enclave_info(const uint8_t *data, uint32_t len)
{
    /*
     * Input layout (from host/Pvd):
     *   model_pub(32) || model_secret(32) || code_hash(32) || model_id(4)  = 100 bytes
     *
     * Delegates to Secure partition: SHA-256(model_pub || model_secret || code_hash || model_id)
     */
    if (len < 100U || data == NULL) {
        uart_send_encrypted_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* data[0..95]  = model_pub(32) || model_secret(32) || code_hash(32) */
    /* data[96..99] = model_id (LE uint32) */
    uint32_t model_id_le;
    memcpy(&model_id_le, data + 96, sizeof(model_id_le));

    uint8_t enclave_info[32] = {0};

    /* Call Secure partition for real SHA-256 via PSA IPC */
    psa_handle_t psa_h = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (psa_h <= 0) {
        uart_send_encrypted_response(RESP_ERROR, NULL, 0);
        return;
    }

    uint32_t cmd = DP_CMD_COMPUTE_ENCLAVE_INFO;
    psa_invec  in_vecs[3] = {
        { &cmd,        sizeof(cmd)        },  /* in[0]: command word */
        { data,        96U                },  /* in[1]: model_pub||model_secret||code_hash */
        { &model_id_le, sizeof(model_id_le) } /* in[2]: model_id (4 bytes LE) */
    };
    psa_outvec out_vec = { enclave_info, sizeof(enclave_info) };

    psa_status_t status = psa_call(psa_h, PSA_IPC_CALL, in_vecs, 3, &out_vec, 1);
    psa_close(psa_h);

    if (status != PSA_SUCCESS) {
        uart_send_encrypted_response(RESP_ERROR, NULL, 0);
        return;
    }

    uart_send_encrypted_response(RESP_OK, enclave_info, sizeof(enclave_info));
}

static void handle_validate_m_update(const uint8_t *data, uint32_t len)
{
    uint32_t new_limit = 0;

    if (process_m_update_payload(data, len, &new_limit) != 0 || new_limit == 0U) {
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
    /*
     * PHASE 2 – Inference  (Verifier ↔ Device)
     *
     * New mode (rx_len == 128):  encrypted M_inf
     *   M_inf plaintext = nonce_inf(32) || model_id(4) || Sign(sk_v, SHA256(nonce_inf||model_id))(64)
     *   Device:
     *     1. Decrypt M_inf with session_key
     *     2. Verify model_id matches stored authorization
     *     3. Verify Verifier signature using stored pk_v
     *     4. Run inference
     *     5. PoX = Sign(sk_d, SHA256(model_id||cert||nonce_inf||output))
     *     6. Return encrypted: output_class(1) || pox_sig(64)
     *
     * Legacy mode (rx_len == 0): no M_inf, plain RESP_OK (backward compatible)
     */
    bool verified_mode = (rx_len == 128U);

    uint8_t  nonce_inf[32] = {0};
    uint32_t req_model_id  = 0U;

    if (verified_mode) {
        /* --- Decrypt M_inf --- */
        uint8_t minf_plain[128];
        size_t  minf_plain_len = 0U;

        if (!session_key_established) {
            uart_protocol_send_response(RESP_ERROR, NULL, 0);
            return;
        }
        if (uart_decrypt(rx_buffer, rx_len,
                         minf_plain, sizeof(minf_plain), &minf_plain_len) != 0
            || minf_plain_len < 100U) {
            uart_protocol_send_response(RESP_ERROR, NULL, 0);
            return;
        }

        /* M_inf plaintext: nonce_inf(32) || model_id(4) || sig_v(64) */
        memcpy(nonce_inf, minf_plain, 32U);
        req_model_id = (uint32_t)minf_plain[32]
                     | ((uint32_t)minf_plain[33] << 8)
                     | ((uint32_t)minf_plain[34] << 16)
                     | ((uint32_t)minf_plain[35] << 24);
        const uint8_t *sig_v = minf_plain + 36U;  /* 64-byte raw r||s ECDSA P-256 */

        /* Verify model_id matches stored authorization */
        if (stored_model_id != 0U && req_model_id != stored_model_id) {
            uart_protocol_send_response(RESP_ERROR, NULL, 0);
            return;
        }

        /* --- Verify Verifier signature: Sign(sk_v, SHA256(nonce_inf || model_id)) --- */
        if (pk_v_valid) {
            uint8_t msg[36];
            memcpy(msg, nonce_inf, 32U);
            msg[32] = minf_plain[32];
            msg[33] = minf_plain[33];
            msg[34] = minf_plain[34];
            msg[35] = minf_plain[35];

            uint8_t msg_hash[32];
            size_t  hash_len = 0U;
            if (psa_hash_compute(PSA_ALG_SHA_256, msg, 36U,
                                 msg_hash, sizeof(msg_hash), &hash_len) != PSA_SUCCESS
                || hash_len != 32U) {
                uart_protocol_send_response(RESP_ERROR, NULL, 0);
                return;
            }

            /* Import pk_v: prepend 0x04 uncompressed-point prefix */
            uint8_t pk_v_full[65];
            pk_v_full[0] = 0x04U;
            memcpy(pk_v_full + 1U, stored_pk_v, 64U);

            psa_key_attributes_t vattr = PSA_KEY_ATTRIBUTES_INIT;
            psa_set_key_type(&vattr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
            psa_set_key_bits(&vattr, 256);
            psa_set_key_usage_flags(&vattr, PSA_KEY_USAGE_VERIFY_HASH);
            psa_set_key_algorithm(&vattr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

            psa_key_id_t pk_v_handle = 0;
            psa_status_t vst = psa_import_key(&vattr, pk_v_full, 65U, &pk_v_handle);
            psa_reset_key_attributes(&vattr);
            if (vst != PSA_SUCCESS) {
                uart_protocol_send_response(RESP_ERROR, NULL, 0);
                return;
            }

            vst = psa_verify_hash(pk_v_handle,
                                  PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                  msg_hash, 32U,
                                  sig_v, 64U);
            psa_destroy_key(pk_v_handle);
            if (vst != PSA_SUCCESS) {
                uart_protocol_send_response(RESP_ERROR, NULL, 0);
                return;
            }
        }
    }

    /* Must have a valid M_update first (quota > 0) */
    if (mock_max_inferences == 0U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    if (mock_inference_count >= mock_max_inferences) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Run the enclave (NS+S integrated architecture) */
    run_enclave();
    mock_inference_count++;

    uint8_t output_class = get_last_prediction();

    if (!verified_mode) {
        /* Legacy path: no PoX, plain confirmation */
        uart_protocol_send_response(RESP_OK, NULL, 0);
        return;
    }

    /* ---- Generate PoX = Sign(sk_d, SHA256(model_id(4)||cert(n)||nonce_inf(32)||output(1))) ---- */
    uint8_t  pox_msg[4U + sizeof(stored_cert) + 32U + 1U];
    uint32_t pox_msg_len = 0U;

    pox_msg[0] = (req_model_id >> 0)  & 0xFFU;
    pox_msg[1] = (req_model_id >> 8)  & 0xFFU;
    pox_msg[2] = (req_model_id >> 16) & 0xFFU;
    pox_msg[3] = (req_model_id >> 24) & 0xFFU;
    pox_msg_len = 4U;

    if (stored_cert_len > 0U && stored_cert_len <= sizeof(stored_cert)) {
        memcpy(pox_msg + pox_msg_len, stored_cert, stored_cert_len);
        pox_msg_len += stored_cert_len;
    }
    memcpy(pox_msg + pox_msg_len, nonce_inf, 32U);
    pox_msg_len += 32U;
    pox_msg[pox_msg_len++] = output_class;

    uint8_t pox_sig[64] = {0};
    size_t  pox_sig_len  = 0U;

    if (device_key_ready) {
        uint8_t pox_hash[32];
        size_t  pox_hash_len = 0U;
        if (psa_hash_compute(PSA_ALG_SHA_256, pox_msg, pox_msg_len,
                             pox_hash, sizeof(pox_hash), &pox_hash_len) == PSA_SUCCESS
            && pox_hash_len == 32U) {
            psa_sign_hash(device_signing_key_id,
                          PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                          pox_hash, 32U,
                          pox_sig, sizeof(pox_sig), &pox_sig_len);
        }
    }

    /* Response plaintext: output_class(1) || pox_sig(64) */
    uint8_t response_plain[65];
    response_plain[0] = output_class;
    memcpy(response_plain + 1U, pox_sig, 64U);

    uart_send_encrypted_response(RESP_OK, response_plain, sizeof(response_plain));
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

static void handle_get_benchmark(void)
{
    /* Send complete benchmark metrics structure to Mac */
    extern benchmark_metrics_t g_benchmark_metrics;

    /* Refresh memory-related fields before sending */
    uint32_t heap_total = 0;
    benchmark_get_heap_usage(&g_benchmark_metrics.heap_used_bytes,
                             &g_benchmark_metrics.heap_free_bytes,
                             &heap_total);
    (void)heap_total;
    g_benchmark_metrics.stack_used_bytes = benchmark_get_stack_usage();
    benchmark_get_memory_usage(&g_benchmark_metrics.ram_used_bytes,
                               &g_benchmark_metrics.ram_total_bytes,
                               &g_benchmark_metrics.flash_used_bytes,
                               &g_benchmark_metrics.flash_total_bytes);
    
    /* Cast structure to bytes and send */
    const uint8_t *metrics_bytes = (const uint8_t *)&g_benchmark_metrics;
    uart_protocol_send_response(RESP_OK, metrics_bytes, sizeof(benchmark_metrics_t));
}

static void handle_get_secure_benchmark(void)
{
    /* Get Secure world benchmark metrics via PSA call */
    secure_benchmark_metrics_ns_t secure_metrics;
    
    int ret = get_secure_benchmark_metrics(&secure_metrics);
    if (ret != 0) {
        /* Failed to get Secure metrics, send error */
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Send complete secure metrics structure to Mac */
    const uint8_t *metrics_bytes = (const uint8_t *)&secure_metrics;
    uart_protocol_send_response(RESP_OK, metrics_bytes, sizeof(secure_benchmark_metrics_ns_t));
}

static void handle_ecdh_handshake(const uint8_t *data, uint32_t len)
{
    /*
     * ECDH Key Exchange - Device Side
     * 
     * Input: Mac's public key (65 bytes, uncompressed P-256)
     *        Format: 0x04 || x_coord[32] || y_coord[32]
     * 
     * Output: Device's public key (65 bytes)
     * 
     * Side effect: Derives and stores session_key[32] via ECDH
     */
    
    if (data == NULL || len != 65U || data[0] != 0x04) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Initialize PSA Crypto */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Step 1: Generate ephemeral ECDH key pair */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);  /* P-256 */
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);  /* Auto-destroy */
    
    psa_key_id_t device_keypair = 0;
    status = psa_generate_key(&attr, &device_keypair);
    if (status != PSA_SUCCESS) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Step 2: Export device public key */
    uint8_t device_pubkey[65];  /* 0x04 || x || y */
    size_t pubkey_len = 0;
    status = psa_export_public_key(device_keypair, device_pubkey, sizeof(device_pubkey), &pubkey_len);
    if (status != PSA_SUCCESS || pubkey_len != 65) {
        psa_destroy_key(device_keypair);
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Step 3: Import Mac's public key */
    psa_key_attributes_t mac_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&mac_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&mac_attr, 256);
    psa_set_key_usage_flags(&mac_attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&mac_attr, PSA_ALG_ECDH);
    psa_set_key_lifetime(&mac_attr, PSA_KEY_LIFETIME_VOLATILE);
    
    psa_key_id_t mac_pubkey_handle = 0;
    status = psa_import_key(&mac_attr, data, len, &mac_pubkey_handle);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(device_keypair);
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Step 4: Perform ECDH key agreement using imported Mac's public key */
    uint8_t shared_secret[32];
    size_t secret_len = 0;
    status = psa_raw_key_agreement(PSA_ALG_ECDH, device_keypair, 
                                     data, len,  /* Mac's public key bytes (uncompressed format) */
                                     shared_secret, sizeof(shared_secret), &secret_len);
    if (status != PSA_SUCCESS || secret_len != 32) {
        psa_destroy_key(device_keypair);
        psa_destroy_key(mac_pubkey_handle);
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Step 5: Derive session key from shared secret (HKDF-SHA256) */
    psa_key_derivation_operation_t kdf_op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&kdf_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS) {
        /* Keep HKDF params aligned with host provider tool. */
        const uint8_t salt[] = "uart_protocol_v1_salt";
        const uint8_t info[] = "uart_protocol_v1_session_key";
        
        status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SALT,
                                                  salt, sizeof(salt) - 1);
        if (status == PSA_SUCCESS) {
            status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                                      shared_secret, secret_len);
        }
        if (status == PSA_SUCCESS) {
            status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_INFO,
                                                      info, sizeof(info) - 1);
        }
        if (status == PSA_SUCCESS) {
            status = psa_key_derivation_output_bytes(&kdf_op, session_key, 32);
        }
        psa_key_derivation_abort(&kdf_op);
    }
    
    /* Cleanup ephemeral keys */
    psa_destroy_key(device_keypair);
    psa_destroy_key(mac_pubkey_handle);
    memset(shared_secret, 0, sizeof(shared_secret));  /* Zero shared secret */
    
    if (status != PSA_SUCCESS) {
        memset(session_key, 0, sizeof(session_key));  /* Clear on failure */
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    /* Mark session key as established */
    session_key_established = true;
    
    /* Step 6: Send device's public key back to Mac */
    uart_protocol_send_response(RESP_OK, device_pubkey, 65);
}

static void handle_get_inference_result(void)
{
    /* Get last inference result (prediction and expected label)
     * Format: [prediction:1][expected:1]
     */
    uint8_t result[2];
    result[0] = get_last_prediction();
    result[1] = get_last_expected_label();
    
    uart_protocol_send_response(RESP_OK, result, 2);
}

static void handle_set_max_inferences(const uint8_t *data, uint32_t len)
{
    /* Set maximum inference count
     * Input: [max_inferences:4] (little-endian uint32_t)
     */
    if (data == NULL || len != 4U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    
    uint32_t max_inf = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    
    /* Call into secure world to set max inferences */
    extern int set_max_inferences(uint32_t max_infs);
    int ret = set_max_inferences(max_inf);
    
    if (ret == 0) {
        /* Keep NS shadow state aligned with secure state */
        mock_max_inferences = max_inf;
        mock_inference_count = 0U;
        uart_protocol_send_response(RESP_OK, NULL, 0);
    } else {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
    }
}

static void handle_get_device_pubkey(void)
{
    /*
     * Return the device P-256 public signing key pk_d (65 bytes, uncompressed).
     * Called by the Verifier/Provider to enable off-device PoX verification.
     * Public keys do not require encryption.
     */
    if (!device_key_ready) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    uart_protocol_send_response(RESP_OK, device_pk_d, sizeof(device_pk_d));
}
