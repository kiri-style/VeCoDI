/*
 * Secure Benchmark Implementation
 */

#include "secure_benchmark.h"
#include <stdio.h>
#include <string.h>

/* ARM Cortex-M DWT (Data Watchpoint and Trace) registers */
#define DWT_CTRL        (*(volatile uint32_t *)0xE0001000)
#define DWT_CYCCNT      (*(volatile uint32_t *)0xE0001004)
#define DEMCR           (*(volatile uint32_t *)0xE000EDFC)

/* DWT Control bits */
#define TRCENA          (1UL << 24)     // Trace enable (DEMCR)
#define CYCCNTENA       (1UL << 0)      // Cycle counter enable (DWT_CTRL)

/* CPU frequency: 110 MHz (STM32L552) */
#define CPU_FREQ_MHZ    110

/* Global Secure metrics */
secure_benchmark_metrics_t g_secure_metrics = {0};

void secure_benchmark_init(void)
{
    /* Reset metrics */
    memset(&g_secure_metrics, 0, sizeof(g_secure_metrics));
    
    /* Enable DWT cycle counter */
    DEMCR |= TRCENA;                    // Enable trace
    DWT_CYCCNT = 0;                     // Reset counter
    DWT_CTRL |= CYCCNTENA;              // Start counting
    
    printf("[SECURE BENCH] Initialized (110 MHz)\n");
}

uint32_t secure_benchmark_get_cycles(void)
{
    return DWT_CYCCNT;
}

uint32_t secure_benchmark_cycles_to_ms(uint64_t cycles)
{
    return (uint32_t)(cycles / (CPU_FREQ_MHZ * 1000));
}

uint32_t secure_benchmark_cycles_to_us(uint64_t cycles)
{
    return (uint32_t)(cycles / CPU_FREQ_MHZ);
}

void secure_benchmark_get_memory_usage(uint32_t *ram_used, uint32_t *ram_total,
                                       uint32_t *flash_used, uint32_t *flash_total)
{
    /* TF-M Secure partition linker symbols use different naming */
    /* Use build output values from: Memory region Used Size (build log) */
    /* Secure Flash: 119,532 B (~117 KB), Secure RAM: 52,732 B (~51 KB) */
    
    if (ram_used) {
        /* From build output: ~52,732 bytes (actual measurement) */
        *ram_used = 52732;
    }
    
    if (ram_total) {
        /* STM32L552 Secure RAM: 64 KB (TrustZone split) */
        *ram_total = 64 * 1024;
    }
    
    if (flash_used) {
        /* From build output: ~119,532 bytes (actual measurement) */
        *flash_used = 119532;
    }
    
    if (flash_total) {
        /* STM32L552 Secure Flash: 131 KB (from build output) */
        *flash_total = 131 * 1024;
    }
}

void secure_benchmark_print_report(void)
{
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          SECURE PARTITION BENCHMARK REPORT                  ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ CRYPTOGRAPHIC OPERATIONS                                     ║\n");
    printf("╟──────────────────────────────────────────────────────────────╢\n");
    
    /* AES Decrypt */
    if (g_secure_metrics.aes_decrypt_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.aes_decrypt_cycles / g_secure_metrics.aes_decrypt_count);
        printf("║ AES Decrypt: %10llu cycles  (%6u ms)  [%u ops]         ║\n",
               (unsigned long long)g_secure_metrics.aes_decrypt_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.aes_decrypt_cycles),
               g_secure_metrics.aes_decrypt_count);
        printf("║   Avg/op:    %10u cycles  (%6u ms)                   ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ AES Decrypt:          0 cycles  (     0 ms)  [0 ops]        ║\n");
    }
    
    /* Late Hash */
    if (g_secure_metrics.late_hash_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.late_hash_cycles / g_secure_metrics.late_hash_count);
        printf("║ Late Hash:   %10llu cycles  (%6u ms)  [%u ops]         ║\n",
               (unsigned long long)g_secure_metrics.late_hash_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.late_hash_cycles),
               g_secure_metrics.late_hash_count);
        printf("║   Avg/op:    %10u cycles  (%6u ms)                   ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ Late Hash:            0 cycles  (     0 ms)  [0 ops]        ║\n");
    }
    
    /* Digest Compute */
    if (g_secure_metrics.digest_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.digest_compute_cycles / g_secure_metrics.digest_count);
        printf("║ Digest:      %10llu cycles  (%6u ms)  [%u ops]         ║\n",
               (unsigned long long)g_secure_metrics.digest_compute_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.digest_compute_cycles),
               g_secure_metrics.digest_count);
        printf("║   Avg/op:    %10u cycles  (%6u ms)                   ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ Digest:               0 cycles  (     0 ms)  [0 ops]        ║\n");
    }

    /* M_update validation */
    if (g_secure_metrics.m_update_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.m_update_cycles / g_secure_metrics.m_update_count);
        printf("║ M_update:     %10llu cycles  (%6u ms)  [%u ops]         ║\n",
               (unsigned long long)g_secure_metrics.m_update_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.m_update_cycles),
               g_secure_metrics.m_update_count);
        printf("║   Avg/op:    %10u cycles  (%6u ms)                   ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ M_update:             0 cycles  (     0 ms)  [0 ops]        ║\n");
    }

    printf("╟──────────────────────────────────────────────────────────────╢\n");
    printf("║ SECURE LIFECYCLE / POX                                       ║\n");
    printf("╟──────────────────────────────────────────────────────────────╢\n");

    if (g_secure_metrics.create_enclave_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.create_enclave_cycles / g_secure_metrics.create_enclave_count);
        printf("║ Create Enclave: %10llu cycles  (%6u ms)  [%u ops]      ║\n",
               (unsigned long long)g_secure_metrics.create_enclave_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.create_enclave_cycles),
               g_secure_metrics.create_enclave_count);
        printf("║   Avg/op:      %10u cycles  (%6u ms)                  ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ Create Enclave:        0 cycles  (     0 ms)  [0 ops]      ║\n");
    }

    if (g_secure_metrics.finalize_create_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.finalize_create_cycles / g_secure_metrics.finalize_create_count);
        printf("║ Finalize Create:%10llu cycles  (%6u ms)  [%u ops]      ║\n",
               (unsigned long long)g_secure_metrics.finalize_create_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.finalize_create_cycles),
               g_secure_metrics.finalize_create_count);
        printf("║   Avg/op:      %10u cycles  (%6u ms)                  ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ Finalize Create:       0 cycles  (     0 ms)  [0 ops]      ║\n");
    }

    if (g_secure_metrics.inf_start_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.inf_start_cycles / g_secure_metrics.inf_start_count);
        printf("║ Inf START:      %10llu cycles  (%6u ms)  [%u ops]      ║\n",
               (unsigned long long)g_secure_metrics.inf_start_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.inf_start_cycles),
               g_secure_metrics.inf_start_count);
        printf("║   Avg/op:      %10u cycles  (%6u ms)                  ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ Inf START:            0 cycles  (     0 ms)  [0 ops]      ║\n");
    }

    if (g_secure_metrics.inf_complete_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.inf_complete_cycles / g_secure_metrics.inf_complete_count);
        printf("║ PoX / COMPLETE:%10llu cycles  (%6u ms)  [%u ops]      ║\n",
               (unsigned long long)g_secure_metrics.inf_complete_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.inf_complete_cycles),
               g_secure_metrics.inf_complete_count);
        printf("║   Avg/op:      %10u cycles  (%6u ms)                  ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ PoX / COMPLETE:       0 cycles  (     0 ms)  [0 ops]      ║\n");
    }

    if (g_secure_metrics.destroy_enclave_count > 0) {
        uint32_t avg_cycles = (uint32_t)(g_secure_metrics.destroy_enclave_cycles / g_secure_metrics.destroy_enclave_count);
        printf("║ Destroy Enclave:%10llu cycles  (%6u ms)  [%u ops]      ║\n",
               (unsigned long long)g_secure_metrics.destroy_enclave_cycles,
               secure_benchmark_cycles_to_ms(g_secure_metrics.destroy_enclave_cycles),
               g_secure_metrics.destroy_enclave_count);
        printf("║   Avg/op:      %10u cycles  (%6u ms)                  ║\n",
               avg_cycles,
               secure_benchmark_cycles_to_ms(avg_cycles));
    } else {
        printf("║ Destroy Enclave:      0 cycles  (     0 ms)  [0 ops]      ║\n");
    }

    printf("║ TX Ops total:  %10u                                       ║\n",
           g_secure_metrics.create_enclave_count +
           g_secure_metrics.finalize_create_count +
           g_secure_metrics.destroy_enclave_count +
           g_secure_metrics.inf_start_count +
           g_secure_metrics.inf_complete_count);
    
    printf("╟──────────────────────────────────────────────────────────────╢\n");
    printf("║ COUNTER MANAGEMENT                                           ║\n");
    printf("╟──────────────────────────────────────────────────────────────╢\n");
    
    /* Counter operations */
    printf("║ Get Max:     %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)g_secure_metrics.get_max_cycles,
           secure_benchmark_cycles_to_ms(g_secure_metrics.get_max_cycles));
    printf("║ Check Allow: %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)g_secure_metrics.check_allowed_cycles,
           secure_benchmark_cycles_to_ms(g_secure_metrics.check_allowed_cycles));
    printf("║ Increment:   %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)g_secure_metrics.increment_cycles,
           secure_benchmark_cycles_to_ms(g_secure_metrics.increment_cycles));
    printf("║ Reset:       %10llu cycles  (%6u ms)                   ║\n",
           (unsigned long long)g_secure_metrics.reset_cycles,
           secure_benchmark_cycles_to_ms(g_secure_metrics.reset_cycles));
    printf("║ Total Ops:   %10u                                       ║\n",
           g_secure_metrics.counter_operations);
    
    printf("╟──────────────────────────────────────────────────────────────╢\n");
    printf("║ MEMORY USAGE (SECURE)                                        ║\n");
    printf("╟──────────────────────────────────────────────────────────────╢\n");
    
    /* Memory usage */
    if (g_secure_metrics.ram_total_bytes > 0) {
        uint32_t ram_percent = (g_secure_metrics.ram_used_bytes * 100) / g_secure_metrics.ram_total_bytes;
        uint32_t ram_used_kb = g_secure_metrics.ram_used_bytes / 1024;
        uint32_t ram_total_kb = g_secure_metrics.ram_total_bytes / 1024;
        printf("║ RAM Used:    %10u / %u bytes  (%3u%%)            ║\n",
               g_secure_metrics.ram_used_bytes,
               g_secure_metrics.ram_total_bytes,
               ram_percent);
        printf("║                    %3u /    %3u KB                        ║\n",
               ram_used_kb, ram_total_kb);
    }
    
    if (g_secure_metrics.flash_total_bytes > 0) {
        uint32_t flash_percent = (g_secure_metrics.flash_used_bytes * 100) / g_secure_metrics.flash_total_bytes;
        uint32_t flash_used_kb = g_secure_metrics.flash_used_bytes / 1024;
        uint32_t flash_total_kb = g_secure_metrics.flash_total_bytes / 1024;
        printf("║ Flash Used:  %10u / %u bytes  (%3u%%)            ║\n",
               g_secure_metrics.flash_used_bytes,
               g_secure_metrics.flash_total_bytes,
               flash_percent);
        printf("║                    %3u /    %3u KB                        ║\n",
               flash_used_kb, flash_total_kb);
    }
    
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}
