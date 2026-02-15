#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <psa/client.h>
#include <stdint.h>
#include "create_enclave.h"

/* Must match Secure manifest SID */
#define ENCLAVE_SID  0xFFFFF002
#define ENCLAVE_VERSION 1

#define DP_CMD_SECRET_DIGEST   0

int main(void)
{
    printk("\n=== NS START ===\n");

    /* Create + seal enclave */
    if (create_enclave() != 0) {
        printk("Enclave creation failed\n");
        return 0;
    }
    /* 👇 AJOUTE ÇA ICI */
    if (enter_enclave() != 0) {
        printk("Enter enclave failed\n");
    }

    psa_handle_t handle;
    psa_status_t status;

    uint32_t cmd = DP_CMD_SECRET_DIGEST;
    uint32_t secret_index = 0;
    uint8_t digest[32];

    psa_invec in_vec[2] = {
        { .base = &cmd,          .len = sizeof(cmd) },
        { .base = &secret_index, .len = sizeof(secret_index) }
    };

    psa_outvec out_vec = {
        .base = digest,
        .len  = sizeof(digest)
    };

    /* Connect to SAME Secure service */
    handle = psa_connect(ENCLAVE_SID, ENCLAVE_VERSION);

    if (handle <= 0) {
        printk("psa_connect failed\n");
        return 0;
    }

    /* Call secure partition */
    status = psa_call(handle,
                      PSA_IPC_CALL,
                      in_vec, 2,
                      &out_vec, 1);

    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("psa_call failed: %d\n", status);
        return 0;
    }

    printk("Digest received:\n");

    for (int i = 0; i < 32; i++) {
        printk("%02X ", digest[i]);
    }

    printk("\n");

    while (1) {
        k_sleep(K_FOREVER);
    }
}