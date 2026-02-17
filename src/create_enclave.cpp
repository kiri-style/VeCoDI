#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <cstring>
#include <psa/client.h>

#include "create_enclave.h"
#include "run_enclave.h"
#include "cifar_resnet_lite_int8_encrypted.h"  // Encrypted lightweight model

/* ============================================================
 *                 CONFIGURATION
 * ============================================================ */

#define ENCLAVE_MEMORY_SIZE   (40 * 1024)  // Model RAM copy (39.5 KB model)

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
extern const unsigned char cifar_resnet_lite_int8_encrypted[];
extern const unsigned int cifar_resnet_lite_int8_encrypted_len;

/* ============================================================
 *                 SECURE CALLS
 * ============================================================ */

static int seal_enclave(void)
{
    printk("[NS] Requesting enclave seal + decrypt (Secure call)...\n");
    printk("[NS] → Connecting to Secure partition (SID=0x%08x, VER=%u)...\n",
           ENCLAVE_SID, ENCLAVE_VER);

    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] ✗ psa_connect failed (seal), handle=%d\n", (int)handle);
        return -1;
    }
    printk("[NS] ✓ PSA connected (handle=%d)\n", (int)handle);

    uint32_t cmd = DP_CMD_SEAL_ENCLAVE;

    psa_invec in_vec[2] = {
        { &cmd, sizeof(cmd) },
        { cifar_resnet_lite_int8_encrypted, cifar_resnet_lite_int8_encrypted_len }
    };
    
    psa_outvec out_vec = {
        enclave_memory,  // Secure World will write decrypted model here
        ENCLAVE_MEMORY_SIZE
    };

    printk("[NS] → PSA invec[0]: cmd=%u, size=%zu\n", cmd, sizeof(cmd));
    printk("[NS] → PSA invec[1]: encrypted_model ptr=%p, size=%u\n",
           (void*)cifar_resnet_lite_int8_encrypted,
           cifar_resnet_lite_int8_encrypted_len);
    printk("[NS] → PSA outvec[0]: enclave ptr=%p, size=%d\n",
           (void*)enclave_memory, ENCLAVE_MEMORY_SIZE);
    printk("[NS] Calling Secure partition...\n");

    psa_status_t status = psa_call(handle,
                                   PSA_IPC_CALL,
                                   in_vec, 2,
                                   &out_vec, 1);

    if (status != PSA_SUCCESS) {
        printk("[NS] ✗ psa_call failed (seal), status=%d\n", (int)status);
        psa_close(handle);
        return -1;
    }
    printk("[NS] ✓ psa_call success (seal), status=%d\n", (int)status);

    psa_close(handle);
    printk("[NS] ✓ PSA connection closed\n");
    printk("[NS] ✓ Enclave sealed + model decrypted\n");
    return 0;

    printk("[NS] Enclave seal failed\n");
    return -1;
}

/* ============================================================
 *          PSA DECRYPT → WRITE DIRECTLY INTO ENCLAVE
 * ============================================================ */

int decrypt_model_into_enclave(uint8_t* output_buffer)
{
    printk("[NS] Requesting model decryption from Secure World...\n");
    printk("[NS] → Input: encrypted model ptr=%p, len=%u\n",
           (void*)cifar_resnet_lite_int8_encrypted,
           cifar_resnet_lite_int8_encrypted_len);
    printk("[NS] → Output: buffer ptr=%p\n", (void*)output_buffer);
    
    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (decrypt), handle=%d\n", (int)handle);
        return -1;
    }
    printk("[NS] ✓ PSA connected (handle=%d)\n", (int)handle);

    uint32_t cmd = DP_CMD_DECRYPT_MODEL;

    psa_invec in_vec[2] = {
        { &cmd, sizeof(cmd) },
        { cifar_resnet_lite_int8_encrypted,
          cifar_resnet_lite_int8_encrypted_len }
    };

    psa_outvec out_vec = {
        output_buffer,
        cifar_resnet_lite_int8_encrypted_len
    };

    psa_status_t status = psa_call(handle,
                                   PSA_IPC_CALL,
                                   in_vec, 2,
                                   &out_vec, 1);

    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Secure decrypt failed (status=%d)\n", status);
        return -1;
    }

    printk("[NS] ✓ Model decrypted into enclave memory\n");
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

    /* Copy model from ROM to RAM enclave */
    printk("[NS] Encrypted Model source:\n");
    printk("      Address: %p\n", (void*)cifar_resnet_lite_int8_encrypted);
    printk("      Size: %u bytes (%.1f KB)\n", 
           cifar_resnet_lite_int8_encrypted_len, 
           cifar_resnet_lite_int8_encrypted_len / 1024.0f);
    
    if (cifar_resnet_lite_int8_encrypted_len > ENCLAVE_MEMORY_SIZE) {
        printk("[NS] ✗ Model too large for enclave (%u > %d bytes)\n",
               cifar_resnet_lite_int8_encrypted_len, ENCLAVE_MEMORY_SIZE);
        return -1;
    }
    
    printk("[NS] Model fits in enclave (%.1f%% usage)\n",
           (cifar_resnet_lite_int8_encrypted_len * 100.0f) / ENCLAVE_MEMORY_SIZE);

    /* Seal enclave - Secure World will decrypt model into enclave */
    printk("[NS] Calling secure partition to seal enclave + decrypt model...\n");
    printk("[NS] → Encrypted model ptr: %p, len: %u\n",
           (void*)cifar_resnet_lite_int8_encrypted, cifar_resnet_lite_int8_encrypted_len);
    printk("[NS] → Enclave buffer ptr: %p, size: %d\n",
           (void*)enclave_memory, ENCLAVE_MEMORY_SIZE);
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

uint8_t* get_enclave_memory(void)
{
    return enclave_memory;
}

uint8_t* get_enclave_model_ptr(void)
{
    return enclave_memory;
}

size_t get_enclave_model_size(void)
{
    return cifar_resnet_lite_int8_encrypted_len;
}