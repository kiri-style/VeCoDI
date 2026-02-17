#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <cstring>
#include <psa/client.h>

#include "create_enclave.h"
#include "run_enclave.h"
#include "model_data.h"  // Pour accéder au modèle ROM

/* ============================================================
 *                 CONFIGURATION
 * ============================================================ */

#define ENCLAVE_MEMORY_SIZE   (1 * 1024)  // Symbolique - on ne copie pas le modèle

#define ENCLAVE_STACK_SIZE    (12 * 1024)
#define ENCLAVE_THREAD_PRIORITY 5

/* PSA definitions (must match Secure manifest) */
#define ENCLAVE_SID  0xFFFFF002
#define ENCLAVE_VER  1

#define DP_CMD_SECRET_DIGEST   0
#define DP_CMD_SEAL_ENCLAVE    1
#define DP_CMD_DECRYPT_MODEL   2

/* ============================================================
 *                 GLOBALS
 * ============================================================ */

static bool enclave_created = false;

/* Enclave isolated memory (model plaintext lives here) */
alignas(32) static uint8_t enclave_memory[ENCLAVE_MEMORY_SIZE];

K_THREAD_STACK_DEFINE(enclave_stack, ENCLAVE_STACK_SIZE);
static struct k_thread enclave_thread;

/* Encrypted model (stored in flash) */
extern const unsigned char cifar_resnet_int8_tflite_encrypted[];
extern const unsigned int cifar_resnet_int8_tflite_encrypted_len;

/* ============================================================
 *                 SECURE CALLS
 * ============================================================ */

static int seal_enclave(void)
{
    printk("[NS] Requesting enclave seal (Secure call)...\n");

    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed\n");
        return -1;
    }

    uint32_t cmd = DP_CMD_SEAL_ENCLAVE;

    psa_invec in_vec = {
        .base = &cmd,
        .len  = sizeof(cmd)
    };

    psa_status_t status = psa_call(handle,
                                   PSA_IPC_CALL,
                                   &in_vec, 1,
                                   NULL, 0);

    psa_close(handle);

    if (status == PSA_SUCCESS) {
        printk("[NS] Enclave sealed successfully\n");
        return 0;
    }

    printk("[NS] Enclave seal failed\n");
    return -1;
}

/* ============================================================
 *          PSA DECRYPT → WRITE DIRECTLY INTO ENCLAVE
 * ============================================================ */

int decrypt_model_into_enclave(uint8_t* output_buffer)
{
    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (decrypt)\n");
        return -1;
    }

    uint32_t cmd = DP_CMD_DECRYPT_MODEL;

    psa_invec in_vec[2] = {
        { &cmd, sizeof(cmd) },
        { cifar_resnet_int8_tflite_encrypted,
          cifar_resnet_int8_tflite_encrypted_len }
    };

    psa_outvec out_vec = {
        output_buffer,
        cifar_resnet_int8_tflite_encrypted_len
    };

    psa_status_t status = psa_call(handle,
                                   PSA_IPC_CALL,
                                   in_vec, 2,
                                   &out_vec, 1);

    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Secure decrypt failed\n");
        return -1;
    }

    printk("[NS] Model decrypted into enclave memory\n");
    return 0;
}

/* ============================================================
 *                 ENCLAVE CREATION
 * ============================================================ */

int create_enclave(void)
{
    if (enclave_created) {
        printk("[NS] Enclave already created\n");
        return -1;
    }

    printk("\n--- CREATE ENCLAVE ---\n");
    printk("[NS] Configuration:\n");
    printk("      Enclave memory size: %d bytes\n", ENCLAVE_MEMORY_SIZE);
    printk("      Enclave memory addr: %p\n", (void*)enclave_memory);
    printk("      Stack size: %d bytes\n", ENCLAVE_STACK_SIZE);
    
    printk("[NS] Initializing enclave memory...\n");
    memset(enclave_memory, 0, ENCLAVE_MEMORY_SIZE);
    printk("[NS] \u2713 Memory cleared\n");

    /* Model stays in ROM - we just mark it as "enclave model" */
    extern const unsigned char cifar_resnet_int8_tflite[];
    extern const unsigned int cifar_resnet_int8_tflite_len;
    
    printk("[NS] ROM Model info:\n");
    printk("      Address: %p\n", (void*)cifar_resnet_int8_tflite);
    printk("      Size: %u bytes (%.1f KB)\n", 
           cifar_resnet_int8_tflite_len, 
           cifar_resnet_int8_tflite_len / 1024.0f);
    printk("[NS] Model will be accessed from ROM (zero-copy)\n");

    /* Seal enclave */
    printk("[NS] Calling secure partition to seal enclave...\n");
    if (seal_enclave() != 0) {
        printk("[NS] \u2717 Seal failed\n");
        return -1;
    }
    printk("[NS] \u2713 Enclave sealed\n");

    enclave_created = true;

    printk("[NS] \u2713 Enclave creation complete\n");
    printk("--- END CREATE ENCLAVE ---\n\n");
    return 0;
}

/* ============================================================
 *                 THREAD ENTRY (INFERENCE)
 * ============================================================ */

static void enclave_thread_entry(void *, void *, void *)
{
    printk("[NS] Enclave running on dedicated stack\n");

    run_enclave();

    printk("[NS] Enclave computation done\n");
}

/* ============================================================
 *                 ENTER ENCLAVE
 * ============================================================ */

int enter_enclave(void)
{
    if (!enclave_created) {
        printk("[NS] Enclave not created\n");
        return -1;
    }

    printk("[NS] Starting enclave thread...\n");

    k_tid_t tid = k_thread_create(&enclave_thread,
                                  enclave_stack,
                                  ENCLAVE_STACK_SIZE,
                                  enclave_thread_entry,
                                  NULL, NULL, NULL,
                                  ENCLAVE_THREAD_PRIORITY,
                                  0,
                                  K_NO_WAIT);

    printk("Thread pointer: %p\n", tid);

    k_thread_join(tid, K_FOREVER);

    printk("[NS] Enclave thread finished\n");

    return 0;
}

/* ============================================================
 *                 DESTROY ENCLAVE
 * ============================================================ */

int destroy_enclave(void)
{
    if (!enclave_created) {
        printk("[NS] No enclave to destroy\n");
        return -1;
    }

    printk("[NS] Destroying enclave...\n");

    /* Zeroize sensitive model memory */
    memset(enclave_memory, 0, ENCLAVE_MEMORY_SIZE);

    enclave_created = false;

    printk("[NS] Enclave destroyed\n");
    return 0;
}

/* ============================================================
 *            ACCESSORS FOR INFERENCE MODULE
 * ============================================================ */

uint8_t* get_enclave_model_ptr(void)
{
    return enclave_memory;
}

size_t get_enclave_model_size(void)
{
    return cifar_resnet_int8_tflite_encrypted_len;
}