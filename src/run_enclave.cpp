#include <zephyr/sys/printk.h>
#include <psa/client.h>
#include "run_enclave.h"

#include "split_inference.h"
#include "create_enclave.h"
#include "benchmark.h"
#include "secure_benchmark_ns.h"

/* PSA definitions */
#define ENCLAVE_SID  0xFFFFF002
#define ENCLAVE_VER  1

__attribute__((section(".inference_ro"), used))
void run_enclave(void)
{
    BENCHMARK_START(run_enc);
    bool should_execute_inference = true;
    bool secure_denied = false;
    
    printk("[ENCLAVE] ===== ENTER =====\n");
    
    /* Check if enclave exists, if not create it */
    if (!is_enclave_created()) {
        printk("[ENCLAVE] Enclave not created, creating new enclave...\n");
        if (create_enclave() != 0) {
            printk("[ENCLAVE] ✗ Failed to create enclave\n");
            should_execute_inference = false;
        }
        if (should_execute_inference) {
            printk("[ENCLAVE] ✓ New enclave created\n");
            
            /* Configure split inference with decrypted late weights */
            printk("[ENCLAVE] Configuring split inference...\n");
            uint8_t* late_wt_buf = get_enclave_region();
            size_t late_wt_size = get_enclave_region_size();
            set_late_weights_buffer(late_wt_buf, late_wt_size);
            printk("[ENCLAVE] ✓ Late weights buffer configured: %p (%zu bytes)\n", 
                   (void*)late_wt_buf, late_wt_size);
            
            /* Pre-compute hash of code pointers + late weights */
            if (precompute_late_weights_hash() != 0) {
                printk("[ENCLAVE] ✗ Failed to pre-compute late weights hash\n");
                should_execute_inference = false;
            }
            if (should_execute_inference) {
                printk("[ENCLAVE] ✓ Late weights hash pre-computed\n");
            }
        }
    }

    if (should_execute_inference) {
        /* Ask Secure partition to verify and increment counter atomically */
        printk("[ENCLAVE] Calling Secure: DP_CMD_RUN_INFERENCE (check + increment)...\n");

        psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
        if (handle <= 0) {
            printk("[ENCLAVE] ⚠ psa_connect failed (handle=%d), continuing in NS benchmark mode\n", (int)handle);
            secure_denied = true;
        } else {
            uint32_t cmd = 9; /* DP_CMD_RUN_INFERENCE */
            psa_invec in_vec = { &cmd, sizeof(cmd) };
            uint32_t allowed = 0;
            psa_outvec out_vec = { &allowed, sizeof(allowed) };

            psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
            psa_close(handle);

            if (status != PSA_SUCCESS) {
                printk("[ENCLAVE] ⚠ DP_CMD_RUN_INFERENCE failed (status=%d), continuing in NS benchmark mode\n", status);
                secure_denied = true;
            } else {
                printk("[ENCLAVE] Secure response: allowed=%u\n", allowed);
                if (allowed == 0) {
                    printk("[ENCLAVE] ⚠ Secure denied inference, continuing in NS benchmark mode\n");
                    secure_denied = true;
                }
            }
        }
    }

    /* Execute inference (counter already incremented by Secure) */
    if (should_execute_inference) {
        if (secure_denied) {
            printk("[ENCLAVE] NS fallback mode active for benchmarking\n");
        }
        /* Open the SAU enclave window: late weights must be NS-accessible. */
        printk("[ENCLAVE] Opening SAU enclave window for inference...\n");
        enclave_sau_open();

        printk("[ENCLAVE] Executing split inference...\n");
        run_split_inference();
        g_benchmark_metrics.inference_count++;

        /* Close the SAU enclave window: weights are Secure again. */
        enclave_sau_close();
        printk("[ENCLAVE] SAU enclave window closed (weights Secure).\n");
    }
    
    /* Update metrics */
    BENCHMARK_END(run_enc, g_benchmark_metrics.run_enclave_cycles);

    printk("[ENCLAVE] ===== EXIT (total: %u cycles, %u ms) =====\n",
           g_benchmark_metrics.run_enclave_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.run_enclave_cycles));
}

int set_max_inferences(uint32_t max_infs)
{
    int ret = set_max_inferences_secure(max_infs);
    if (ret == 0) {
        printk("[ENCLAVE] Max inferences set in Secure partition: %u\n", max_infs);
    }
    return ret;
}