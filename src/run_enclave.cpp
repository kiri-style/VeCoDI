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
    uint32_t tx_id = 0U;  /* Store tx_id from Phase 0 for Phase 1 */
    
    printk("[ENCLAVE] ===== ENTER =====\n");
    
    if (should_execute_inference) {
        /* Secure precheck only: no counter increment here. */
        printk("[ENCLAVE] Calling Secure: DP_CMD_RUN_INFERENCE precheck...\n");

        /* NS-side API call: DP_CMD_RUN_INFERENCE, phase=0 (precheck). */
        psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
        if (handle <= 0) {
            printk("[ENCLAVE] ✗ psa_connect failed (handle=%d)\n", (int)handle);
            should_execute_inference = false;
        } else {
            uint32_t cmd = 9; /* DP_CMD_RUN_INFERENCE */
            uint8_t phase = 0U; /* precheck */
            psa_invec in_vec[2] = {
                { &cmd, sizeof(cmd) },
                { &phase, sizeof(phase) }
            };
            psa_outvec out_vec = { &tx_id, sizeof(tx_id) };

            psa_status_t status = psa_call(handle, PSA_IPC_CALL, in_vec, 2, &out_vec, 1);
            psa_close(handle);

            if (status != PSA_SUCCESS) {
                printk("[ENCLAVE] ✗ Precheck failed (status=%d)\n", status);
                should_execute_inference = false;
            } else {
                printk("[ENCLAVE] Secure response: tx_id=%u\n", tx_id);
                if (tx_id == 0) {
                    printk("[ENCLAVE] ✗ Secure denied inference\n");
                    should_execute_inference = false;
                }
            }
        }
    }

    /* Execute inference */
    if (should_execute_inference) {
        set_atomic_inference_window_open(true);
        printk("[ENCLAVE] Executing inference via entry()...\n");
        
        /* Étape 5: Call entry() directly to execute F */
        uint8_t output_class = entry(NULL);
        printk("[ENCLAVE] entry() returned output=%u\n", output_class);
        
        g_benchmark_metrics.inference_count++;

        /* Secure commit: increment only after successful execution. */
        /* NS-side API call: DP_CMD_RUN_INFERENCE, phase=1 (commit). */
        psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
        if (handle <= 0) {
            printk("[ENCLAVE] ✗ Commit connect failed (handle=%d)\n", (int)handle);
            should_execute_inference = false;
        } else {
            uint32_t cmd = 9; /* DP_CMD_RUN_INFERENCE */
            uint8_t phase = 1U; /* commit */
            uint8_t req[5];
            req[0] = (uint8_t)(tx_id & 0xFFU);
            req[1] = (uint8_t)((tx_id >> 8) & 0xFFU);
            req[2] = (uint8_t)((tx_id >> 16) & 0xFFU);
            req[3] = (uint8_t)((tx_id >> 24) & 0xFFU);
            req[4] = output_class;
            
            psa_invec in_vec[3] = {
                { &cmd, sizeof(cmd) },
                { &phase, sizeof(phase) },
                { &req, sizeof(req) }
            };
            uint32_t allowed = 0;
            psa_outvec out_vec = { &allowed, sizeof(allowed) };
            psa_status_t status = psa_call(handle, PSA_IPC_CALL, in_vec, 3, &out_vec, 1);
            psa_close(handle);
            if (status != PSA_SUCCESS || allowed == 0U) {
                printk("[ENCLAVE] ✗ Commit failed (status=%d, allowed=%u)\n", status, allowed);
                should_execute_inference = false;
            }
        }

        set_atomic_inference_window_open(false);
    }
    else {
        set_atomic_inference_window_open(false);
    }
    
    /* Update metrics */
    BENCHMARK_END(run_enc, g_benchmark_metrics.run_enclave_cycles);
    BENCHMARK_ACCUMULATE(g_benchmark_metrics.run_enclave_cycles,
                         g_benchmark_metrics.run_enclave_sum_cycles,
                         g_benchmark_metrics.run_enclave_min_cycles,
                         g_benchmark_metrics.run_enclave_max_cycles,
                         g_benchmark_metrics.run_enclave_count);

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