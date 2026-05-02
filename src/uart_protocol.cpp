/* UART Protocol Implementation for Mac ↔ STM32 Communication */

#include "uart_protocol.h"
#include <zephyr/kernel.h>
#include <zephyr/irq.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/gpio.h>
#include <string.h>
#include <stdio.h>
#include <psa/crypto.h>
#include <psa/client.h>
#include "run_enclave.h"
#include "create_enclave.h"
#include "../split_inference/late/L_nn_wt_encrypted.h"

/* Secure partition constants (mirrors dummy_partition.h, not on NS include path) */
#define TFM_DP_SERVICE_SID          0xFFFFF002U
#define DP_CMD_COMPUTE_ENCLAVE_INFO 10U
#define DP_CMD_VALIDATE_M_UPDATE    11U
#define DP_CMD_INF_START            25U
#define DP_CMD_INF_COMPLETE         26U
#define DP_CMD_GET_DEVICE_PUBKEY    27U
#define DP_CMD_SIGN_ATTEST_MSG      28U
#define CIFAR_IMAGE_SIZE_BYTES      3072U
#define VERIFIED_MINF_SIZE_BYTES    128U
#define RUN_WITH_IMAGE_DATA_SIZE    (1U + CIFAR_IMAGE_SIZE_BYTES + VERIFIED_MINF_SIZE_BYTES)
#include "benchmark.h"
#include "secure_benchmark_ns.h"
#include "split_inference.h"

extern const uint8_t __model_ro_start[];

int validate_enclave_info_before_inference(void);

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

/* Static session key used for M_update and verified inference encryption. */
static const uint8_t session_key[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};
static const bool session_key_established = true;

/* ========== KEY SCHEME: Dev(sk_d,pk_d)  Pvd(sk_p,pk_p)  Vrf(sk_v,pk_v) ========== */

/* Device public key cache (owned by Secure partition). */
static uint8_t      device_pk_d[65] = {0};
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
 * Fetch secure-owned device public signing key (pk_d) from TF-M partition.
 */
static int fetch_device_pubkey_from_secure(void)
{
    psa_handle_t handle = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (handle <= 0) {
        return -1;
    }

    uint32_t cmd = DP_CMD_GET_DEVICE_PUBKEY;
    psa_invec in_vec = { &cmd, sizeof(cmd) };
    psa_outvec out_vec = { device_pk_d, sizeof(device_pk_d) };
    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
    psa_close(handle);

    if (status != PSA_SUCCESS || out_vec.len != sizeof(device_pk_d)) {
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
            cmd == CMD_GET_BENCHMARK ||
            cmd == CMD_GET_SECURE_BENCHMARK ||
            cmd == CMD_GET_INFERENCE_RESULT ||
            cmd == CMD_SET_MAX_INFERENCES ||
            cmd == CMD_RUN_INFERENCE_WITH_IMAGE ||
            cmd == CMD_GET_DEVICE_PUBKEY ||
            cmd == CMD_GET_SAU_STATE ||
            cmd == CMD_GET_ENCLAVE_STATE ||
            cmd == CMD_CREATE_ENCLAVE ||
            cmd == CMD_DESTROY_ENCLAVE ||
            cmd == CMD_UPDATE_RATE_LIMIT ||
            cmd == CMD_RUN_INFERENCE_NO_SAU ||
            cmd == CMD_GET_TCB_BENCHMARK ||
            cmd == CMD_READ_PROTECTED_MEM ||
            cmd == CMD_READ_PROTECTED_ROM ||
            cmd == CMD_GET_M_UPDATE_DEBUG);
}

static bool is_valid_len_for_cmd(uint8_t cmd, uint32_t len)
{
    switch (cmd) {
        case CMD_COMPUTE_ENCLAVE_INFO:
            /* len=32: attested mode (nonce from host)
             * len=0 : secure-internal compute only */
            return (len == 0U) || (len == 32U);
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
        case CMD_GET_SAU_STATE:
        case CMD_GET_ENCLAVE_STATE:
        case CMD_GET_TCB_BENCHMARK:
        case CMD_CREATE_ENCLAVE:
            return (len == 0U) || (len == 4U);
        case CMD_DESTROY_ENCLAVE:
        case CMD_RUN_INFERENCE_NO_SAU:
        case CMD_READ_PROTECTED_MEM:
        case CMD_READ_PROTECTED_ROM:
            return len == 0U;
        case CMD_GET_M_UPDATE_DEBUG:
            return len == 0U;
        case CMD_RUN_INFERENCE:
            /* Verified-only protocol: encrypted M_inf packet nonce(12)+ciphertext(100)+tag(16). */
            return (len == 128U);
        case CMD_RUN_INFERENCE_WITH_IMAGE:
            /* Photo upload + verified inference: label(1) + image(3072) + encrypted M_inf(128). */
            return len == RUN_WITH_IMAGE_DATA_SIZE;
        case CMD_SET_MAX_INFERENCES:
        case CMD_UPDATE_RATE_LIMIT:
            return len == 4U;  /* Max inferences is uint32_t */
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
static void handle_run_inference_with_image(const uint8_t *data, uint32_t len);
static void handle_get_inference_count(void);
static void handle_get_remaining_inferences(void);
static void handle_get_benchmark(void);
static void handle_get_secure_benchmark(void);
static void handle_get_inference_result(void);
static void handle_set_max_inferences(const uint8_t *data, uint32_t len);
static void handle_get_device_pubkey(void);
static void handle_get_sau_state(void);
static void handle_get_enclave_state(void);
static void handle_get_tcb_benchmark(void);
static void handle_run_inference_no_sau(void);
static void handle_read_protected_mem(void);
static void handle_read_protected_rom(void);
static void handle_create_enclave(const uint8_t *data, uint32_t len);
static void handle_destroy_enclave(void);
static void handle_update_rate_limit(const uint8_t *data, uint32_t len);
static void handle_get_m_update_debug(void);

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

    /* Cache secure-owned device public signing key (sk_d never leaves Secure). */
    (void)fetch_device_pubkey_from_secure();

    /* Boot-time Secure EnclaveInfo materialization (all components). */
    if (initialize_secure_enclave_info_boot() != 0) {
        printk("[UART] WARNING: secure boot EnclaveInfo init failed\n");
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

        case CMD_RUN_INFERENCE_WITH_IMAGE:
            handle_run_inference_with_image(rx_buffer, rx_len);
            break;
        
        case CMD_GET_INFERENCE_COUNT:
            handle_get_inference_count();
            break;
        
        case CMD_GET_REMAINING_INFERENCES:
            handle_get_remaining_inferences();
            break;
        
        case CMD_GET_BENCHMARK:
            handle_get_benchmark();
            break;

        case CMD_GET_SECURE_BENCHMARK:
            handle_get_secure_benchmark();
            break;

        case CMD_GET_M_UPDATE_DEBUG:
            handle_get_m_update_debug();
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

        case CMD_GET_SAU_STATE:
            handle_get_sau_state();
            break;

        case CMD_GET_ENCLAVE_STATE:
            handle_get_enclave_state();
            break;

        case CMD_GET_TCB_BENCHMARK:
            handle_get_tcb_benchmark();
            break;

        case CMD_CREATE_ENCLAVE:
            handle_create_enclave(rx_buffer, rx_len);
            break;

        case CMD_DESTROY_ENCLAVE:
            handle_destroy_enclave();
            break;

        case CMD_UPDATE_RATE_LIMIT:
            handle_update_rate_limit(rx_buffer, rx_len);
            break;

        case CMD_RUN_INFERENCE_NO_SAU:
            handle_run_inference_no_sau();
            break;

        case CMD_READ_PROTECTED_MEM:
            handle_read_protected_mem();
            break;

        case CMD_READ_PROTECTED_ROM:
            handle_read_protected_rom();
            break;

        default:
            uart_protocol_send_response(RESP_ERROR, NULL, 0);
            break;
    }
}

/* ========== COMMAND HANDLERS ========== */

static void handle_compute_enclave_info(const uint8_t *data, uint32_t len)
{
    /* Modes:
     *   len=32  => attested mode: host provides nonce, device returns enclave_info||sig_d
     *   len=0   => secure-internal compute, returns enclave_info
    * EnclaveInfo is derived from secure cached model metadata and does not
    * require runtime enclave creation or an open SAU execution window.
     */
    if ((len != 0U && len != 32U) || (len > 0U && data == NULL)) {
        uart_send_encrypted_response(RESP_ERROR, NULL, 0);
        return;
    }

    uint8_t enclave_info[32] = {0};

    if (initialize_secure_enclave_info_boot() != 0) {
        uart_send_encrypted_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Call Secure partition for real SHA-256 via PSA IPC */
    psa_handle_t psa_h = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (psa_h <= 0) {
        uart_send_encrypted_response(RESP_ERROR, NULL, 0);
        return;
    }

    uint32_t cmd = DP_CMD_COMPUTE_ENCLAVE_INFO;
    psa_outvec out_vec = { enclave_info, sizeof(enclave_info) };

    psa_invec in_vec = { &cmd, sizeof(cmd) };
    psa_status_t status = psa_call(psa_h, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
    psa_close(psa_h);

    if (status != PSA_SUCCESS) {
        uart_send_encrypted_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Attested mode: sign SHA256(nonce(32) || enclave_info(32)) in Secure. */
    if (len == 32U) {
        uint8_t msg[64];
        memcpy(msg, data, 32U);
        memcpy(msg + 32U, enclave_info, 32U);

        uint8_t sig_d[64] = {0};
        psa_handle_t sign_h = psa_connect(TFM_DP_SERVICE_SID, 1);
        if (sign_h <= 0) {
            uart_send_encrypted_response(RESP_ERROR, NULL, 0);
            return;
        }

        uint32_t sign_cmd = DP_CMD_SIGN_ATTEST_MSG;
        psa_invec in_sign[2] = {
            { &sign_cmd, sizeof(sign_cmd) },
            { msg, sizeof(msg) }
        };
        psa_outvec out_sign = { sig_d, sizeof(sig_d) };
        psa_status_t sign_st = psa_call(sign_h, PSA_IPC_CALL, in_sign, 2, &out_sign, 1);
        psa_close(sign_h);
        if (sign_st != PSA_SUCCESS || out_sign.len != sizeof(sig_d)) {
            uart_send_encrypted_response(RESP_ERROR, NULL, 0);
            return;
        }

        uint8_t attested_resp[96];
        memcpy(attested_resp, enclave_info, 32U);
        memcpy(attested_resp + 32U, sig_d, 64U);
        uart_send_encrypted_response(RESP_OK, attested_resp, sizeof(attested_resp));
        return;
    }

    uart_send_encrypted_response(RESP_OK, enclave_info, sizeof(enclave_info));
}

static void handle_validate_m_update(const uint8_t *data, uint32_t len)
{
    bool m_update_success = false;

    struct ns_m_update_benchmark_scope {
        uint32_t start_cycles;
        bool *success;

        explicit ns_m_update_benchmark_scope(bool *success_flag)
            : start_cycles(benchmark_get_cycles()), success(success_flag)
        {
        }

        ~ns_m_update_benchmark_scope()
        {
            if (success != NULL && *success) {
                uint32_t elapsed_cycles = benchmark_get_cycles() - start_cycles;
                g_benchmark_metrics.m_update_cycles += (uint64_t)elapsed_cycles;
            }
        }
    } m_update_scope(NULL);
    m_update_scope.success = &m_update_success;

    /*
     * NS receives encrypted M_update from host and forwards the raw bytes
     * to the Secure partition for AES-256-GCM decryption + EnclaveInfo
     * validation + counter update.  Secure returns auth fields so NS can
     * store them for later M_inf verification.
     *
     * Secure in[0] = cmd (4B)
     * Secure in[1] = full packet: nonce(12) || ciphertext || tag(16)
     * Secure out[0] = c_limit(4) + pk_v(64) + model_id(4) + cert_len(4) + cert(n)
     */
    if (data == NULL || len < 28U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    if (initialize_secure_enclave_info_boot() != 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Build auth-state response buffer (max 204B) */
    uint8_t auth_resp[204];
    memset(auth_resp, 0, sizeof(auth_resp));

    psa_handle_t psa_h = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (psa_h <= 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    uint32_t cmd = DP_CMD_VALIDATE_M_UPDATE;
    psa_invec  in_v[2] = {
        { &cmd, sizeof(cmd) },   /* in[0]: command word */
        { data, len         }    /* in[1]: full raw packet */
    };
    psa_outvec out_v = { auth_resp, sizeof(auth_resp) };

    psa_status_t psa_st = psa_call(psa_h, PSA_IPC_CALL, in_v, 2, &out_v, 1);
    psa_close(psa_h);

    if (psa_st != PSA_SUCCESS) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Parse auth response: c_limit(4) + pk_v(64) + model_id(4) + cert_len(4) + cert(n) */
    size_t resp_len = out_v.len;
    if (resp_len < (4U + 64U + 4U + 4U)) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    size_t   roff    = 0;
    uint32_t c_limit = 0;
    memcpy(&c_limit, auth_resp + roff, 4); roff += 4;

    /* Anti-replay shadow check on NS side */
    if (c_limit <= mock_max_inferences) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }
    mock_max_inferences  = c_limit;
    mock_inference_count = 0U;

    /* pk_v (64B raw x||y) */
    memcpy(stored_pk_v, auth_resp + roff, 64U);
    pk_v_valid = true;
    roff += 64U;

    /* model_id (4B LE) */
    memcpy(&stored_model_id, auth_resp + roff, 4U);
    roff += 4U;

    /* cert_len + cert */
    uint32_t clen = 0;
    memcpy(&clen, auth_resp + roff, 4U);
    roff += 4U;
    if (clen <= sizeof(stored_cert) && roff + clen <= resp_len) {
        stored_cert_len = clen;
        memcpy(stored_cert, auth_resp + roff, clen);
    }

    m_update_success = true;
    /* Ensure the NS-side m_update count is visible immediately to host
     * (some hosts read device counters immediately after the response).
     * Increment here rather than relying solely on the RAII destructor so
     * the count is durable before uart_protocol_send_response returns.
     */
    g_benchmark_metrics.m_update_count++;
    uart_protocol_send_response(RESP_OK, NULL, 0);
}

static void handle_get_max_inferences(void)
{
    uart_protocol_send_response(RESP_OK, (const uint8_t *)&mock_max_inferences, sizeof(mock_max_inferences));
}

static void handle_run_inference_common(const uint8_t *minf_data, uint32_t minf_len)
{
    /*
     * PHASE 2 – Inference  (Verifier ↔ Device)
     *
     * Verified-only mode: encrypted M_inf packet.
     *   Device:
     *     1. Forward encrypted payload to Secure START
     *     2. Secure decrypts + verifies M_inf signature
     *     3. NS executes inference atomically
     *     4. Return to Secure COMPLETE for PoX signing + commit
     *     5. Return encrypted response: output_class(1) || pox_sig(64)
     */
    struct full_execute_benchmark_scope {
        uint32_t start_cycles;

        full_execute_benchmark_scope()
            : start_cycles(benchmark_get_cycles())
        {
        }

        ~full_execute_benchmark_scope()
        {
            uint32_t elapsed_cycles = benchmark_get_cycles() - start_cycles;
            g_benchmark_metrics.full_execute_cycles = elapsed_cycles;
            BENCHMARK_ACCUMULATE(elapsed_cycles,
                                 g_benchmark_metrics.full_execute_sum_cycles,
                                 g_benchmark_metrics.full_execute_min_cycles,
                                 g_benchmark_metrics.full_execute_max_cycles,
                                 g_benchmark_metrics.full_execute_count);
        }
    } full_execute_scope;

    g_benchmark_metrics.inference_requests_total++;
    uint32_t tx_id = 0U;

    /* Error payload for host diagnostics: stage(4B LE), detail(4B LE signed). */
    auto send_inf_error = [](uint32_t stage, int32_t detail) {
        uint8_t err[8];
        memcpy(err, &stage, sizeof(stage));
        memcpy(err + 4U, &detail, sizeof(detail));
        uart_protocol_send_response(RESP_ERROR, err, sizeof(err));
    };

    if (!session_key_established || minf_len != VERIFIED_MINF_SIZE_BYTES) {
        send_inf_error(1U, -1);
        return;
    }

    /* Must have a valid M_update first (quota > 0) */
    if (mock_max_inferences == 0U) {
        send_inf_error(1U, -2);
        return;
    }
    if (mock_inference_count >= mock_max_inferences) {
        send_inf_error(1U, -3);
        return;
    }

    /* Pre-check secure EnclaveInfo before entering the atomic run window. */
    if (validate_enclave_info_before_inference() != 0) {
        g_benchmark_metrics.enclave_info_validation_failures++;
        printk("[UART] WARNING: EnclaveInfo runtime validation failed, continuing inference path\n");
    }

    /*
     * ATOMIC INFERENCE SECTION:
     * Keep IRQ masked from Secure START (opens enclave RAM to NS) until
     * Secure COMPLETE (closes enclave RAM + signs PoX).
     */
    uint32_t irq_atomic_start = benchmark_get_cycles();
    unsigned int irq_key_atomic = irq_lock();

    /* START in Secure: decrypt + verify M_inf and open transaction window. */
    psa_handle_t handle_start = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (handle_start <= 0) {
        uint32_t irq_atomic_elapsed = benchmark_get_cycles() - irq_atomic_start;
        BENCHMARK_ACCUMULATE(irq_atomic_elapsed,
                             g_benchmark_metrics.irq_atomic_sum_cycles,
                             g_benchmark_metrics.irq_atomic_min_cycles,
                             g_benchmark_metrics.irq_atomic_max_cycles,
                             g_benchmark_metrics.irq_atomic_count);
        irq_unlock(irq_key_atomic);
        send_inf_error(3U, (int32_t)handle_start);
        return;
    }

    uint32_t cmd = DP_CMD_INF_START;
    psa_invec in_vec[2] = {
        { &cmd, sizeof(cmd) },
        { minf_data, minf_len }
    };
    psa_outvec out_vec = { &tx_id, sizeof(tx_id) };
    psa_status_t st = psa_call(handle_start, PSA_IPC_CALL, in_vec, 2, &out_vec, 1);
    psa_close(handle_start);
    if (st != PSA_SUCCESS || out_vec.len != sizeof(tx_id) || tx_id == 0U) {
        uint32_t irq_atomic_elapsed = benchmark_get_cycles() - irq_atomic_start;
        BENCHMARK_ACCUMULATE(irq_atomic_elapsed,
                             g_benchmark_metrics.irq_atomic_sum_cycles,
                             g_benchmark_metrics.irq_atomic_min_cycles,
                             g_benchmark_metrics.irq_atomic_max_cycles,
                             g_benchmark_metrics.irq_atomic_count);
        irq_unlock(irq_key_atomic);
        send_inf_error(4U, (int32_t)st);
        return;
    }

    /* Inference executes in NS during the active secure transaction window. */
    set_atomic_inference_window_open(true);
    run_split_inference();
    set_atomic_inference_window_open(false);
    g_benchmark_metrics.inference_count++;

    uint8_t output_class = get_last_prediction();
    uint8_t expected_class = get_last_expected_label();
    if (output_class == 255U || expected_class == 255U) {
        uint32_t irq_atomic_elapsed = benchmark_get_cycles() - irq_atomic_start;
        BENCHMARK_ACCUMULATE(irq_atomic_elapsed,
                             g_benchmark_metrics.irq_atomic_sum_cycles,
                             g_benchmark_metrics.irq_atomic_min_cycles,
                             g_benchmark_metrics.irq_atomic_max_cycles,
                             g_benchmark_metrics.irq_atomic_count);
        irq_unlock(irq_key_atomic);
        send_inf_error(5U, -1);
        return;
    }

    /* COMPLETE in Secure: increments secure counter, closes SAU, returns PoX signature. */
    uint8_t pox_sig[64] = {0};
    uint8_t complete_req[5];
    complete_req[0] = (uint8_t)(tx_id & 0xFFU);
    complete_req[1] = (uint8_t)((tx_id >> 8) & 0xFFU);
    complete_req[2] = (uint8_t)((tx_id >> 16) & 0xFFU);
    complete_req[3] = (uint8_t)((tx_id >> 24) & 0xFFU);
    complete_req[4] = output_class;

    psa_handle_t handle_complete = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (handle_complete <= 0) {
        uint32_t irq_atomic_elapsed = benchmark_get_cycles() - irq_atomic_start;
        BENCHMARK_ACCUMULATE(irq_atomic_elapsed,
                             g_benchmark_metrics.irq_atomic_sum_cycles,
                             g_benchmark_metrics.irq_atomic_min_cycles,
                             g_benchmark_metrics.irq_atomic_max_cycles,
                             g_benchmark_metrics.irq_atomic_count);
        irq_unlock(irq_key_atomic);
        send_inf_error(6U, (int32_t)handle_complete);
        return;
    }

    uint32_t cmd_complete = DP_CMD_INF_COMPLETE;
    psa_invec in_vec_complete[2] = {
        { &cmd_complete, sizeof(cmd_complete) },
        { complete_req, sizeof(complete_req) }
    };
    psa_outvec out_vec_complete = { pox_sig, sizeof(pox_sig) };
    psa_status_t st_complete = psa_call(handle_complete, PSA_IPC_CALL, in_vec_complete, 2, &out_vec_complete, 1);
    psa_close(handle_complete);
    if (st_complete != PSA_SUCCESS || out_vec_complete.len != sizeof(pox_sig)) {
        uint32_t irq_atomic_elapsed = benchmark_get_cycles() - irq_atomic_start;
        BENCHMARK_ACCUMULATE(irq_atomic_elapsed,
                             g_benchmark_metrics.irq_atomic_sum_cycles,
                             g_benchmark_metrics.irq_atomic_min_cycles,
                             g_benchmark_metrics.irq_atomic_max_cycles,
                             g_benchmark_metrics.irq_atomic_count);
        irq_unlock(irq_key_atomic);
        send_inf_error(7U, (int32_t)st_complete);
        return;
    }

    mock_inference_count++;

    /* Response plaintext: output_class(1) || pox_sig(64) */
    uint8_t response_plain[65];
    response_plain[0] = output_class;
    memcpy(response_plain + 1U, pox_sig, 64U);

    uart_send_encrypted_response(RESP_OK, response_plain, sizeof(response_plain));
    uint32_t irq_atomic_elapsed = benchmark_get_cycles() - irq_atomic_start;
    BENCHMARK_ACCUMULATE(irq_atomic_elapsed,
                         g_benchmark_metrics.irq_atomic_sum_cycles,
                         g_benchmark_metrics.irq_atomic_min_cycles,
                         g_benchmark_metrics.irq_atomic_max_cycles,
                         g_benchmark_metrics.irq_atomic_count);
    irq_unlock(irq_key_atomic);
}

static void handle_run_inference(void)
{
    handle_run_inference_common(rx_buffer, rx_len);
}

static void handle_run_inference_with_image(const uint8_t *data, uint32_t len)
{
    if (data == NULL || len != RUN_WITH_IMAGE_DATA_SIZE) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    uint8_t label = data[0];
    const uint8_t *image = data + 1U;
    const uint8_t *minf_data = data + 1U + CIFAR_IMAGE_SIZE_BYTES;

    if (set_custom_test_image(image, label) != 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    g_benchmark_metrics.run_inference_with_image_count++;

    handle_run_inference_common(minf_data, VERIFIED_MINF_SIZE_BYTES);
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

static void handle_get_m_update_debug(void)
{
    /* Return little-endian: uint64_t m_update_cycles, uint32_t m_update_count */
    uint8_t resp[12];
    uint64_t cycles = g_benchmark_metrics.m_update_cycles;
    uint32_t count = g_benchmark_metrics.m_update_count;
    for (int i = 0; i < 8; i++) {
        resp[i] = (uint8_t)((cycles >> (8 * i)) & 0xFFULL);
    }
    for (int i = 0; i < 4; i++) {
        resp[8 + i] = (uint8_t)((count >> (8 * i)) & 0xFFU);
    }
    uart_protocol_send_response(RESP_OK, resp, sizeof(resp));
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

static void handle_run_inference_no_sau(void)
{
    /*
     * DANGEROUS TEST PATH:
     * Intentionally attempts inference without calling enclave_sau_open().
     * Used only to validate that protected late-weights are not accessible
     * when SAU is closed.
     *
     * Expected behavior on protected systems: BusFault/HardFault or error.
     */
    printk("[UART TEST] CMD_RUN_INFERENCE_NO_SAU received\n");
    g_benchmark_metrics.dangerous_inference_no_sau_count++;

    if (!is_enclave_created()) {
        printk("[UART TEST] enclave not created -> reject (create explicitly first)\n");
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Keep policy semantics aligned with normal path. */
    if (mock_max_inferences == 0U || mock_inference_count >= mock_max_inferences) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Prepare split-inference context (but DO NOT open SAU). */
    set_late_weights_buffer(get_enclave_region(), get_enclave_region_size());
    if (precompute_late_weights_hash() != 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    printk("[UART TEST] Running split inference WITHOUT SAU OPEN (expected to fault if closed)\n");
    run_split_inference();
    mock_inference_count++;

    uint8_t pred = get_last_prediction();
    uart_protocol_send_response(RESP_OK, &pred, 1);
}

static void handle_read_protected_mem(void)
{
    /*
     * DANGEROUS TEST PATH:
     * Force a direct NS read from enclave memory while SAU should be CLOSED.
     * Expected behavior on protected system: BusFault/HardFault/reset/no response.
     */
    printk("[UART TEST] CMD_READ_PROTECTED_MEM received\n");
    g_benchmark_metrics.dangerous_read_ram_count++;

    if (!is_enclave_created()) {
        printk("[UART TEST] enclave not created -> reject (create explicitly first)\n");
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    volatile uint8_t *p = (volatile uint8_t *)get_enclave_region();
    printk("[UART TEST] Direct read from protected ptr=%p (expect fault if protected)\n", (void *)p);

    /* If protection is effective, this can fault/reset and no response is sent. */
    uint8_t v = p[0];

    /* Reaching here means read did not fault (unexpected in strict isolation). */
    uart_protocol_send_response(RESP_OK, &v, 1);
}

static void handle_read_protected_rom(void)
{
    /*
     * DANGEROUS TEST PATH:
     * Force a direct NS read from protected model RO memory while SAU should be CLOSED.
     * Expected behavior on protected system: BusFault/HardFault/reset/no response.
     */
    printk("[UART TEST] CMD_READ_PROTECTED_ROM received\n");
    g_benchmark_metrics.dangerous_read_rom_count++;

    if (!is_enclave_created()) {
        printk("[UART TEST] enclave not created -> reject (create explicitly first)\n");
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    volatile uint8_t *p = (volatile uint8_t *)__model_ro_start;
    printk("[UART TEST] Direct read from protected model_ro ptr=%p (expect fault if protected)\n", (void *)p);

    /* If protection is effective, this can fault/reset and no response is sent. */
    uint8_t v = p[0];

    /* Reaching here means read did not fault (unexpected in strict isolation). */
    uart_protocol_send_response(RESP_OK, &v, 1);
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

static void handle_get_inference_result(void)
{
    /* Get last inference result (prediction and expected label)
     * Format: [prediction:1][expected:1]
     */
    uint8_t result[2];
    result[0] = get_last_prediction();
    result[1] = get_last_expected_label();

    if (result[0] == 255U || result[1] == 255U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

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
    if (!device_key_ready && fetch_device_pubkey_from_secure() != 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    /* Refresh cache in case secure side rotated on reboot. */
    (void)fetch_device_pubkey_from_secure();
    uart_protocol_send_response(RESP_OK, device_pk_d, sizeof(device_pk_d));
}

static void handle_get_sau_state(void)
{
    /* Response format returned to host:
     *   byte 0   = state code: 0=unregistered, 1=open, 2=closed
     *   bytes 1-4 = base (LE uint32)
     *   bytes 5-8 = size (LE uint32)
     */
    psa_handle_t handle = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (handle <= 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    uint32_t cmd = 16U; /* DP_CMD_GET_SAU_STATE */
    uint8_t resp[9] = {0};
    psa_invec in_vec = { &cmd, sizeof(cmd) };
    psa_outvec out_vec = { resp, sizeof(resp) };

    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    uart_protocol_send_response(RESP_OK, resp, sizeof(resp));
}

static void handle_get_enclave_state(void)
{
    uint8_t created = is_enclave_created() ? 1U : 0U;
    uart_protocol_send_response(RESP_OK, &created, sizeof(created));
}

static void handle_get_tcb_benchmark(void)
{
    typedef struct {
        uint32_t secure_flash_used_bytes;
        uint32_t secure_ram_used_bytes;
        uint32_t model_ro_bytes;
        uint32_t inference_ro_bytes;
        uint32_t tcb_flash_bytes;
        uint32_t tcb_total_bytes;
    } tcb_benchmark_ns_t;

    secure_benchmark_metrics_ns_t secure_metrics;
    if (get_secure_benchmark_metrics(&secure_metrics) != 0) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    tcb_benchmark_ns_t tcb = {0};
    tcb.secure_flash_used_bytes = secure_metrics.flash_used_bytes;
    tcb.secure_ram_used_bytes = secure_metrics.ram_used_bytes;
    tcb.model_ro_bytes = (uint32_t)get_model_ro_size();
    tcb.inference_ro_bytes = (uint32_t)get_inference_code_size();
    tcb.tcb_flash_bytes = tcb.secure_flash_used_bytes + tcb.model_ro_bytes + tcb.inference_ro_bytes;
    tcb.tcb_total_bytes = tcb.tcb_flash_bytes + tcb.secure_ram_used_bytes;

    uart_protocol_send_response(RESP_OK, (const uint8_t *)&tcb, sizeof(tcb));
}

static void handle_create_enclave(const uint8_t *data, uint32_t len)
{
    bool create_success = false;

    struct ns_create_benchmark_scope {
        uint32_t start_cycles;
        bool *success;

        explicit ns_create_benchmark_scope(bool *success_flag)
            : start_cycles(benchmark_get_cycles()), success(success_flag)
        {
        }

        ~ns_create_benchmark_scope()
        {
            if (success != NULL && *success) {
                uint32_t elapsed_cycles = benchmark_get_cycles() - start_cycles;
                g_benchmark_metrics.enclave_create_cycles = elapsed_cycles;
                BENCHMARK_ACCUMULATE(elapsed_cycles,
                                     g_benchmark_metrics.enclave_create_sum_cycles,
                                     g_benchmark_metrics.enclave_create_min_cycles,
                                     g_benchmark_metrics.enclave_create_max_cycles,
                                     g_benchmark_metrics.enclave_create_count);
            }
        }
    } create_scope(&create_success);

    if (is_enclave_created()) {
        uart_protocol_send_response(RESP_OK, NULL, 0);
        return;
    }

    if (len != 0U && len != 4U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    size_t decrypt_size_bytes = 0U;
    if (len == 4U && data != NULL) {
        decrypt_size_bytes = (size_t)data[0]
                           | ((size_t)data[1] << 8)
                           | ((size_t)data[2] << 16)
                           | ((size_t)data[3] << 24);
    }

    uint32_t atomic_start = benchmark_get_cycles();
    unsigned int irq_key_atomic = irq_lock();
    int create_ret = create_enclave_with_size(decrypt_size_bytes);
    irq_unlock(irq_key_atomic);
    uint32_t atomic_elapsed = benchmark_get_cycles() - atomic_start;
    BENCHMARK_ACCUMULATE(atomic_elapsed,
                         g_benchmark_metrics.create_atomic_sum_cycles,
                         g_benchmark_metrics.create_atomic_min_cycles,
                         g_benchmark_metrics.create_atomic_max_cycles,
                         g_benchmark_metrics.create_atomic_count);

    if (create_ret == 0) {
        create_success = true;
        uart_protocol_send_response(RESP_OK, NULL, 0);
    } else {
        int32_t detail = get_last_create_secure_status();
        uart_protocol_send_response(RESP_ERROR, (const uint8_t *)&detail, sizeof(detail));
    }
}

static void handle_destroy_enclave(void)
{
    bool destroy_success = false;

    struct ns_destroy_benchmark_scope {
        uint32_t start_cycles;
        bool *success;

        explicit ns_destroy_benchmark_scope(bool *success_flag)
            : start_cycles(benchmark_get_cycles()), success(success_flag)
        {
        }

        ~ns_destroy_benchmark_scope()
        {
            if (success != NULL && *success) {
                uint32_t elapsed_cycles = benchmark_get_cycles() - start_cycles;
                g_benchmark_metrics.enclave_destroy_cycles = elapsed_cycles;
                BENCHMARK_ACCUMULATE(elapsed_cycles,
                                     g_benchmark_metrics.enclave_destroy_sum_cycles,
                                     g_benchmark_metrics.enclave_destroy_min_cycles,
                                     g_benchmark_metrics.enclave_destroy_max_cycles,
                                     g_benchmark_metrics.enclave_destroy_count);
            }
        }
    } destroy_scope(&destroy_success);

    if (!is_enclave_created()) {
        uart_protocol_send_response(RESP_OK, NULL, 0);
        return;
    }

    uint32_t atomic_start = benchmark_get_cycles();
    unsigned int irq_key_atomic = irq_lock();
    int destroy_ret = destroy_enclave();
    irq_unlock(irq_key_atomic);
    uint32_t atomic_elapsed = benchmark_get_cycles() - atomic_start;
    BENCHMARK_ACCUMULATE(atomic_elapsed,
                         g_benchmark_metrics.destroy_atomic_sum_cycles,
                         g_benchmark_metrics.destroy_atomic_min_cycles,
                         g_benchmark_metrics.destroy_atomic_max_cycles,
                         g_benchmark_metrics.destroy_atomic_count);

    if (destroy_ret == 0) {
        destroy_success = true;
        mock_inference_count = 0U;
        mock_max_inferences = 0U;
        uart_protocol_send_response(RESP_OK, NULL, 0);
    } else {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
    }
}

static void handle_update_rate_limit(const uint8_t *data, uint32_t len)
{
    if (data == NULL || len != 4U) {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
        return;
    }

    uint32_t new_limit = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);

    if (update_rate_limit(new_limit) == 0) {
        mock_max_inferences = new_limit;
        mock_inference_count = 0U;
        uart_protocol_send_response(RESP_OK, NULL, 0);
    } else {
        uart_protocol_send_response(RESP_ERROR, NULL, 0);
    }
}
