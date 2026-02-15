#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <cstring>
#include <psa/client.h>

#include "create_enclave.h"
#include "run_enclave.h"

/* ============================================================
 *                 CONFIGURATION
 * ============================================================ */

#define ENCLAVE_MEMORY_SIZE   (150 * 1024)

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

    printk("[NS] Allocating enclave memory...\n");
    memset(enclave_memory, 0, ENCLAVE_MEMORY_SIZE);

    /* Decrypt model directly into enclave memory */
    if (decrypt_model_into_enclave(enclave_memory) != 0) {
        printk("[NS] Model decrypt failed\n");
        return -1;
    }

    printk("[NS] Enclave memory prepared with model data\n");

    /* Optional: model attestation */
    /*if (attest_model() != 0) {
        printk("[NS] Model integrity failed!\n");
        return -1;
    }*/

    /* Seal enclave */
    if (seal_enclave() != 0) {
        return -1;
    }

    enclave_created = true;

    printk("[NS] Enclave successfully created\n");
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