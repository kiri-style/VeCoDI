/*
 * Secure Benchmark NS Implementation
 */

#include "secure_benchmark_ns.h"
#include <psa/client.h>
#include <zephyr/sys/printk.h>
#include <string.h>

/* TF-M Dummy Partition SID and version (must match create_enclave.cpp) */
#define ENCLAVE_SID  0xFFFFF002
#define ENCLAVE_VER  1

/* CPU frequency: 110 MHz (STM32L552) */
#define CPU_FREQ_MHZ    110

static uint32_t cycles_to_ms(uint64_t cycles)
{
    return (uint32_t)(cycles / (CPU_FREQ_MHZ * 1000));
}

static uint32_t cycles_to_us(uint64_t cycles)
{
    return (uint32_t)(cycles / CPU_FREQ_MHZ);
}

int get_secure_benchmark_metrics(secure_benchmark_metrics_ns_t *metrics)
{
    if (!metrics) {
        return -1;
    }

    psa_handle_t handle;
    psa_status_t status;
    uint32_t cmd = 8; /* DP_CMD_GET_BENCHMARK */

    /* Connect to Secure partition */
    handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        printk("[NS] Failed to connect to Secure partition for benchmark\n");
        return -1;
    }

    /* Prepare invocation */
    psa_invec in_vec[] = {
        { &cmd, sizeof(cmd) }
    };
    psa_outvec out_vec[] = {
        { metrics, sizeof(*metrics) }
    };

    /* Call Secure partition */
    status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, out_vec, 1);
    
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Failed to get Secure benchmark: %d\n", status);
        return -1;
    }

    return 0;
}

void print_secure_benchmark_report(const secure_benchmark_metrics_ns_t *metrics)
{
    if (!metrics) {
        return;
    }

    printk("\n");
    printk("╔══════════════════════════════════════════════════════════════╗\n");
    printk("║          SECURE PARTITION BENCHMARK REPORT                  ║\n");
    printk("╠══════════════════════════════════════════════════════════════╣\n");
    printk("║ CRYPTOGRAPHIC OPERATIONS                                     ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    
    /* AES Decrypt */
    if (metrics->aes_decrypt_count > 0) {
        uint32_t avg_cycles = (uint32_t)(metrics->aes_decrypt_cycles / metrics->aes_decrypt_count);
        printk("║ AES Decrypt: %10llu cycles  (%6u ms)  [%u ops]         ║\n",
               (unsigned long long)metrics->aes_decrypt_cycles,
               cycles_to_ms(metrics->aes_decrypt_cycles),
               metrics->aes_decrypt_count);
        printk("║   Avg/op:    %10u cycles  (%6u ms)                   ║\n",
               avg_cycles,
               cycles_to_ms(avg_cycles));
    } else {
        printk("║ AES Decrypt:          0 cycles  (     0 ms)  [0 ops]        ║\n");
    }
    
    /* Late Hash */
    if (metrics->late_hash_count > 0) {
        uint32_t avg_cycles = (uint32_t)(metrics->late_hash_cycles / metrics->late_hash_count);
        printk("║ Late Hash:   %10llu cycles  (%6u ms)  [%u ops]         ║\n",
               (unsigned long long)metrics->late_hash_cycles,
               cycles_to_ms(metrics->late_hash_cycles),
               metrics->late_hash_count);
        printk("║   Avg/op:    %10u cycles  (%6u ms)                   ║\n",
               avg_cycles,
               cycles_to_ms(avg_cycles));
    } else {
        printk("║ Late Hash:            0 cycles  (     0 ms)  [0 ops]        ║\n");
    }
    
    /* Digest Compute */
    if (metrics->digest_count > 0) {
        uint32_t avg_cycles = (uint32_t)(metrics->digest_compute_cycles / metrics->digest_count);
        printk("║ Digest:      %10llu cycles  (%6u ms)  [%u ops]         ║\n",
               (unsigned long long)metrics->digest_compute_cycles,
               cycles_to_ms(metrics->digest_compute_cycles),
               metrics->digest_count);
        printk("║   Avg/op:    %10u cycles  (%6u ms)                   ║\n",
               avg_cycles,
               cycles_to_ms(avg_cycles));
    } else {
        printk("║ Digest:               0 cycles  (     0 ms)  [0 ops]        ║\n");
    }
    
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    printk("║ COUNTER MANAGEMENT                                           ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    
    /* Counter operations */
    printk("║ Get Max:     %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)metrics->get_max_cycles,
           cycles_to_ms(metrics->get_max_cycles));
    printk("║ Check Allow: %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)metrics->check_allowed_cycles,
           cycles_to_ms(metrics->check_allowed_cycles));
    printk("║ Increment:   %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)metrics->increment_cycles,
           cycles_to_ms(metrics->increment_cycles));
    printk("║ Reset:       %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)metrics->reset_cycles,
           cycles_to_ms(metrics->reset_cycles));
    printk("║ Total Ops:   %10u                                       ║\n",
           metrics->counter_operations);
    
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    printk("║ MEMORY USAGE (SECURE)                                        ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    
    /* Memory usage */
    if (metrics->ram_total_bytes > 0) {
        uint32_t ram_percent = (metrics->ram_used_bytes * 100) / metrics->ram_total_bytes;
        uint32_t ram_used_kb = metrics->ram_used_bytes / 1024;
        uint32_t ram_total_kb = metrics->ram_total_bytes / 1024;
        printk("║ RAM Used:    %10u / %u bytes  (%3u%%)            ║\n",
               metrics->ram_used_bytes,
               metrics->ram_total_bytes,
               ram_percent);
        printk("║                    %3u /    %3u KB                        ║\n",
               ram_used_kb, ram_total_kb);
    }
    
    if (metrics->flash_total_bytes > 0) {
        uint32_t flash_percent = (metrics->flash_used_bytes * 100) / metrics->flash_total_bytes;
        uint32_t flash_used_kb = metrics->flash_used_bytes / 1024;
        uint32_t flash_total_kb = metrics->flash_total_bytes / 1024;
        printk("║ Flash Used:  %10u / %u bytes  (%3u%%)            ║\n",
               metrics->flash_used_bytes,
               metrics->flash_total_bytes,
               flash_percent);
        printk("║                    %3u /    %3u KB                        ║\n",
               flash_used_kb, flash_total_kb);
    }
    
    printk("╚══════════════════════════════════════════════════════════════╝\n");
    printk("\n");
}
