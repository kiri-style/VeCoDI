#include <zephyr/sys/printk.h>
#include <psa/client.h>
#include "run_enclave.h"

#include "split_inference.h"
#include "create_enclave.h"
#include "benchmark.h"

/* PSA definitions */
#define ENCLAVE_SID  0xFFFFF002
#define ENCLAVE_VER  1

void run_enclave(void)
{
    BENCHMARK_START(run_enc);
    
    printk("[ENCLAVE] ===== ENTER =====\n");
    
    /* Check if enclave exists, if not create it */
    if (!is_enclave_created()) {
        printk("[ENCLAVE] Enclave not created, creating new enclave...\n");
        if (create_enclave() != 0) {
            printk("[ENCLAVE] ✗ Failed to create enclave\n");
            printk("[ENCLAVE] ===== EXIT (error) =====\n");
            return;
        }
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
            printk("[ENCLAVE] ===== EXIT (error) =====\n");
            return;
        }
        printk("[ENCLAVE] ✓ Late weights hash pre-computed\n");
    }
    
    /* Ask Secure partition to verify and increment counter atomically */
    printk("[ENCLAVE] Calling Secure: DP_CMD_RUN_INFERENCE (check + increment)...\n");
    
    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[ENCLAVE] ✗ psa_connect failed, handle=%d\n", (int)handle);
        printk("[ENCLAVE] ===== EXIT (error) =====\n");
        return;
    }

    uint32_t cmd = 9; /* DP_CMD_RUN_INFERENCE */
    psa_invec in_vec = { &cmd, sizeof(cmd) };
    uint32_t allowed = 0;
    psa_outvec out_vec = { &allowed, sizeof(allowed) };

    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[ENCLAVE] ✗ Failed to call DP_CMD_RUN_INFERENCE, status=%d\n", status);
        printk("[ENCLAVE] ===== EXIT (error) =====\n");
        return;
    }

    printk("[ENCLAVE] Secure response: allowed=%u\n", allowed);
    
    /* If limit reached, BLOCK inference (no auto-recreation) */
    if (allowed == 0) {
        printk("[ENCLAVE] ✗ BLOCKED: Inference limit reached (max 3 per enclave)\n");
        printk("[ENCLAVE] ===== EXIT (blocked) =====\n");
        return;
    }

    /* Execute inference (counter already incremented by Secure) */
    printk("[ENCLAVE] Executing split inference...\n");
    run_split_inference();
    
    /* Update metrics */
    g_benchmark_metrics.inference_count++;
    BENCHMARK_END(run_enc, g_benchmark_metrics.run_enclave_cycles);

    printk("[ENCLAVE] ===== EXIT (total: %u cycles, %u ms) =====\n",
           benchmark_get_cycles() - run_enc_start,
           benchmark_cycles_to_ms(benchmark_get_cycles() - run_enc_start));
}