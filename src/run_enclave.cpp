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
    printk("[ENCLAVE] Running split inference in NS context\n");

    if (!is_enclave_created()) {
        printk("[ENCLAVE] Refusing to run: enclave is not created\n");
        BENCHMARK_END(run_enc, g_benchmark_metrics.run_enclave_cycles);
        return;
    }

    printk("[ENCLAVE] >>> ENTRY: about to call run_split_inference()\n");
    set_atomic_inference_window_open(true);
    run_split_inference();
    /* Read and log the prediction produced by the split inference
     * before closing the atomic window so the log proves the work
     * happened while the window was open.
     */
    uint8_t _pred = get_last_prediction();
    printk("[ENCLAVE] run_split_inference produced prediction=%u\n", _pred);
    printk("[ENCLAVE] <<< EXIT: finished run_split_inference()\n");
    set_atomic_inference_window_open(false);
    
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

int execute_verified_inference(uint32_t tx_id, uint8_t *output_class)
{
    if (output_class == NULL) {
        return -1;
    }

    if (tx_id == 0U) {
        return -1;
    }

    /* Simplified: call the public `run_enclave()` helper which already
     * opens the atomic window and runs the split inference flow. This
     * keeps the NS call simple and uses the existing header API.
     */
    printk("[ENCLAVE] execute_verified_inference: invoking run_enclave()\n");
    run_enclave();
    /* run_enclave populates benchmark counters and the split inference
     * code stores the last prediction accessible via `get_last_prediction()`.
     */
    *output_class = get_last_prediction();
    if (*output_class == 255U) {
        printk("[ENCLAVE] Invalid inference result (255)\n");
        return -1;
    }
    printk("[ENCLAVE] run_enclave returned output=%u\n", *output_class);

    return 0;
}

int set_max_inferences(uint32_t max_infs)
{
    int ret = set_max_inferences_secure(max_infs);
    if (ret == 0) {
        printk("[ENCLAVE] Max inferences set in Secure partition: %u\n", max_infs);
    }
    return ret;
}