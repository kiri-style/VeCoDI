#include "benchmark.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <string.h>

// ============================================================================
// Cycle Counter - Using Zephyr's sys_clock_elapsed() instead of DWT
// (DWT is not accessible from Non-Secure world in TrustZone-M)
// ============================================================================

// System clock (STM32L552 default)
#ifndef CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC
#define CPU_FREQ_HZ 110000000  // 110 MHz default for STM32L552
#else
#define CPU_FREQ_HZ CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC
#endif

// Global metrics storage
benchmark_metrics_t g_benchmark_metrics;

// Reference point for cycle counting
static uint32_t benchmark_start_cycles = 0;

static uint32_t safe_avg_u64(uint64_t sum, uint32_t count)
{
    if (count == 0U) {
        return 0U;
    }
    return (uint32_t)(sum / count);
}

// ============================================================================
// Initialization
// ============================================================================

void benchmark_init(void)
{
    // Initialize with current kernel cycle count
    benchmark_start_cycles = k_cycle_get_32();
    
    // Reset metrics
    benchmark_reset_metrics();
    
    printk("[BENCHMARK] Initialized - CPU freq: %u MHz\n", CPU_FREQ_HZ / 1000000);
}

// ============================================================================
// Cycle Counter Implementation
// Using Zephyr's k_cycle_get_32() for TrustZone-M safe access
// ============================================================================

uint32_t benchmark_get_cycles(void)
{
    // Get current cycle count and calculate elapsed
    uint32_t current_cycles = k_cycle_get_32();
    uint32_t elapsed_cycles = current_cycles - benchmark_start_cycles;
    
    return elapsed_cycles;
}

uint32_t benchmark_cycles_to_us(uint32_t cycles)
{
    // Convert cycles to microseconds
    // us = cycles / (freq_hz / 1000000)
    return (uint32_t)((uint64_t)cycles * 1000000ULL / CPU_FREQ_HZ);
}

uint32_t benchmark_cycles_to_ms(uint32_t cycles)
{
    // Convert cycles to milliseconds
    return (uint32_t)((uint64_t)cycles * 1000ULL / CPU_FREQ_HZ);
}

// ============================================================================
// Memory Usage Implementation
// ============================================================================

void benchmark_get_heap_usage(uint32_t *used_bytes, uint32_t *free_bytes, uint32_t *total_bytes)
{
    // Simplified implementation - heap runtime stats not always available
    // Return zeros as placeholder (can be enhanced later)
    if (used_bytes) {
        *used_bytes = 0;
    }
    if (free_bytes) {
        *free_bytes = 0;
    }
    if (total_bytes) {
        *total_bytes = 0;
    }
}

uint32_t benchmark_get_stack_usage(void)
{
    // Return approximate stack usage
    // This is a simplified implementation
    return CONFIG_MAIN_STACK_SIZE / 2; // Placeholder estimate
}

void benchmark_get_memory_usage(uint32_t *ram_used, uint32_t *ram_total,
                                uint32_t *flash_used, uint32_t *flash_total)
{
    // Linker symbols for RAM sections
    extern char __data_start[], __data_end[];
    extern char __bss_start[], __bss_end[];
    
    // Linker symbols for Flash sections  
    extern char __rom_region_start[];
    extern char __rom_region_end[];
    
    // Calculate RAM usage (DATA + BSS only - stacks/heap managed separately)
    uint32_t data_size = (uint32_t)((uintptr_t)__data_end - (uintptr_t)__data_start);
    uint32_t bss_size = (uint32_t)((uintptr_t)__bss_end - (uintptr_t)__bss_start);
    
    if (ram_used) {
        // DATA + BSS sections only (from linker map)
        *ram_used = data_size + bss_size;
    }
    
    if (ram_total) {
        // STM32L552 NS RAM: 128 KB
        *ram_total = 128 * 1024;
    }
    
    if (flash_used) {
        // Flash used from linker (text + rodata + data init)
        uint32_t rom_size = (uint32_t)((uintptr_t)__rom_region_end - (uintptr_t)__rom_region_start);
        *flash_used = rom_size;
    }
    
    if (flash_total) {
        // STM32L552 NS Flash: 256 KB
        *flash_total = 256 * 1024;
    }
}

// ============================================================================
// Reporting Implementation
// ============================================================================

void benchmark_print_report(const benchmark_metrics_t *metrics)
{
    printk("\n");
    printk("╔══════════════════════════════════════════════════════════════╗\n");
    printk("║           PERFORMANCE BENCHMARK REPORT                      ║\n");
    printk("╠══════════════════════════════════════════════════════════════╣\n");
    
    // Enclave Lifecycle
    printk("║ ENCLAVE LIFECYCLE                                            ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    printk("║ Create:    %10u cycles  (%6u ms)                   ║\n",
           metrics->enclave_create_cycles,
           benchmark_cycles_to_ms(metrics->enclave_create_cycles));
    printk("║ Destroy:   %10u cycles  (%6u ms)                   ║\n",
           metrics->enclave_destroy_cycles,
           benchmark_cycles_to_ms(metrics->enclave_destroy_cycles));
    printk("║ Recreations: %8u times                                 ║\n",
           metrics->enclave_recreations);
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    
    // Cryptographic Operations
    printk("║ CRYPTOGRAPHIC OPERATIONS                                     ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    printk("║ AES Decrypt: %8u cycles  (%6u ms)                   ║\n",
           metrics->aes_decrypt_cycles,
           benchmark_cycles_to_ms(metrics->aes_decrypt_cycles));
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    
    // Inference Performance
    printk("║ INFERENCE PERFORMANCE                                        ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    printk("║ Early Layers:  %8u cycles  (%6u ms)                 ║\n",
           metrics->early_layers_cycles,
           benchmark_cycles_to_ms(metrics->early_layers_cycles));
    printk("║ Late Layers:   %8u cycles  (%6u ms)                 ║\n",
           metrics->late_layers_cycles,
           benchmark_cycles_to_ms(metrics->late_layers_cycles));
    printk("║ Total Inf:     %8u cycles  (%6u ms)                 ║\n",
           metrics->total_inference_cycles,
           benchmark_cycles_to_ms(metrics->total_inference_cycles));
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    
        // End-to-End
    printk("║ END-TO-END METRICS                                           ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
        printk("║ run_enclave(last): %8u cycles  (%6u ms)            ║\n",
           metrics->run_enclave_cycles,
           benchmark_cycles_to_ms(metrics->run_enclave_cycles));
    printk("║ Inferences:    %8u total                               ║\n",
           metrics->inference_count);

        if (metrics->full_execute_count > 0U) {
         uint32_t full_execute_avg = safe_avg_u64(metrics->full_execute_sum_cycles,
                                metrics->full_execute_count);
         printk("║ full_execute(last): %8u cycles  (%6u ms)          ║\n",
             metrics->full_execute_cycles,
             benchmark_cycles_to_ms(metrics->full_execute_cycles));
         printk("║ full_execute(avg):  %8u cycles  (%6u ms)          ║\n",
             full_execute_avg,
             benchmark_cycles_to_ms(full_execute_avg));
         printk("║ full_execute(min/max): %5u / %5u ms             ║\n",
             benchmark_cycles_to_ms(metrics->full_execute_min_cycles),
             benchmark_cycles_to_ms(metrics->full_execute_max_cycles));
        }

        if (metrics->run_enclave_count > 0U) {
            uint32_t avg_cycles = safe_avg_u64(metrics->run_enclave_sum_cycles,
                                               metrics->run_enclave_count);
            printk("║ run_enclave(avg):  %8u cycles  (%6u ms)          ║\n",
                   avg_cycles,
                   benchmark_cycles_to_ms(avg_cycles));
            printk("║ run_enclave(min/max): %6u / %6u ms               ║\n",
                   benchmark_cycles_to_ms(metrics->run_enclave_min_cycles),
                   benchmark_cycles_to_ms(metrics->run_enclave_max_cycles));
            uint32_t avg_ms = benchmark_cycles_to_ms(avg_cycles);
            if (avg_ms > 0U) {
                printk("║ Approx throughput:  %8u inf/s                     ║\n", 1000U / avg_ms);
            }
        }

        if (metrics->irq_atomic_count > 0U) {
            uint32_t irq_avg = safe_avg_u64(metrics->irq_atomic_sum_cycles,
                                            metrics->irq_atomic_count);
            printk("║ IRQ-masked(avg):   %8u cycles  (%6u us)          ║\n",
                   irq_avg,
                   benchmark_cycles_to_us(irq_avg));
            printk("║ IRQ-masked(min/max): %6u / %6u us               ║\n",
                   benchmark_cycles_to_us(metrics->irq_atomic_min_cycles),
                   benchmark_cycles_to_us(metrics->irq_atomic_max_cycles));
        }

         if (metrics->create_atomic_count > 0U) {
             uint32_t create_atomic_avg = safe_avg_u64(metrics->create_atomic_sum_cycles,
                                     metrics->create_atomic_count);
             printk("║ CREATE atomic(avg): %8u cycles  (%6u us)         ║\n",
                 create_atomic_avg,
                 benchmark_cycles_to_us(create_atomic_avg));
             printk("║ CREATE atomic(min/max): %5u / %5u us            ║\n",
                 benchmark_cycles_to_us(metrics->create_atomic_min_cycles),
                 benchmark_cycles_to_us(metrics->create_atomic_max_cycles));
         }

         if (metrics->destroy_atomic_count > 0U) {
             uint32_t destroy_atomic_avg = safe_avg_u64(metrics->destroy_atomic_sum_cycles,
                                      metrics->destroy_atomic_count);
             printk("║ DESTROY atomic(avg): %7u cycles  (%6u us)        ║\n",
                 destroy_atomic_avg,
                 benchmark_cycles_to_us(destroy_atomic_avg));
             printk("║ DESTROY atomic(min/max): %4u / %5u us           ║\n",
                 benchmark_cycles_to_us(metrics->destroy_atomic_min_cycles),
                 benchmark_cycles_to_us(metrics->destroy_atomic_max_cycles));
         }

        printk("║ Requests total: %8u | EnclaveInfo fail: %6u        ║\n",
               metrics->inference_requests_total,
               metrics->enclave_info_validation_failures);

        printk("╟──────────────────────────────────────────────────────────────╢\n");

        // Memory Usage
    printk("║ MEMORY USAGE                                                 ║\n");
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    
    // RAM
    if (metrics->ram_total_bytes > 0) {
        uint32_t ram_pct = (metrics->ram_used_bytes * 100) / metrics->ram_total_bytes;
        printk("║ RAM Used:   %10u / %6u bytes  (%3u%%)            ║\n",
               metrics->ram_used_bytes, metrics->ram_total_bytes, ram_pct);
        printk("║             %10u / %6u KB                        ║\n",
               metrics->ram_used_bytes / 1024, metrics->ram_total_bytes / 1024);
    }
    
    // Flash
    if (metrics->flash_total_bytes > 0) {
        uint32_t flash_pct = (metrics->flash_used_bytes * 100) / metrics->flash_total_bytes;
        printk("║ Flash Used: %10u / %6u bytes  (%3u%%)            ║\n",
               metrics->flash_used_bytes, metrics->flash_total_bytes, flash_pct);
        printk("║             %10u / %6u KB                        ║\n",
               metrics->flash_used_bytes / 1024, metrics->flash_total_bytes / 1024);
    }
    
    printk("╟──────────────────────────────────────────────────────────────╢\n");
    printk("║ Heap Used:  %10u bytes  (%6u KB)                  ║\n",
           metrics->heap_used_bytes, metrics->heap_used_bytes / 1024);
    printk("║ Heap Free:  %10u bytes  (%6u KB)                  ║\n",
           metrics->heap_free_bytes, metrics->heap_free_bytes / 1024);
    printk("║ Stack Used: %10u bytes  (%6u KB)                  ║\n",
           metrics->stack_used_bytes, metrics->stack_used_bytes / 1024);
    printk("╚══════════════════════════════════════════════════════════════╝\n");
    printk("\n");

        printk("[BENCHMARK][CSV] stage,count,sum_cycles,avg_cycles,min_cycles,max_cycles\n");
        printk("[BENCHMARK][CSV] enclave_create,%u,%llu,%u,%u,%u\n",
            metrics->enclave_create_count,
            (unsigned long long)metrics->enclave_create_sum_cycles,
            safe_avg_u64(metrics->enclave_create_sum_cycles, metrics->enclave_create_count),
            metrics->enclave_create_min_cycles,
            metrics->enclave_create_max_cycles);
        printk("[BENCHMARK][CSV] enclave_destroy,%u,%llu,%u,%u,%u\n",
            metrics->enclave_destroy_count,
            (unsigned long long)metrics->enclave_destroy_sum_cycles,
            safe_avg_u64(metrics->enclave_destroy_sum_cycles, metrics->enclave_destroy_count),
            metrics->enclave_destroy_min_cycles,
            metrics->enclave_destroy_max_cycles);
        printk("[BENCHMARK][CSV] aes_decrypt,%u,%llu,%u,%u,%u\n",
            metrics->aes_decrypt_count,
            (unsigned long long)metrics->aes_decrypt_sum_cycles,
            safe_avg_u64(metrics->aes_decrypt_sum_cycles, metrics->aes_decrypt_count),
            metrics->aes_decrypt_min_cycles,
            metrics->aes_decrypt_max_cycles);
        printk("[BENCHMARK][CSV] early_layers,%u,%llu,%u,%u,%u\n",
            metrics->early_layers_count,
            (unsigned long long)metrics->early_layers_sum_cycles,
            safe_avg_u64(metrics->early_layers_sum_cycles, metrics->early_layers_count),
            metrics->early_layers_min_cycles,
            metrics->early_layers_max_cycles);
        printk("[BENCHMARK][CSV] late_layers,%u,%llu,%u,%u,%u\n",
            metrics->late_layers_count,
            (unsigned long long)metrics->late_layers_sum_cycles,
            safe_avg_u64(metrics->late_layers_sum_cycles, metrics->late_layers_count),
            metrics->late_layers_min_cycles,
            metrics->late_layers_max_cycles);
        printk("[BENCHMARK][CSV] total_inference,%u,%llu,%u,%u,%u\n",
            metrics->total_inference_count,
            (unsigned long long)metrics->total_inference_sum_cycles,
            safe_avg_u64(metrics->total_inference_sum_cycles, metrics->total_inference_count),
            metrics->total_inference_min_cycles,
            metrics->total_inference_max_cycles);
        printk("[BENCHMARK][CSV] run_enclave,%u,%llu,%u,%u,%u\n",
            metrics->run_enclave_count,
            (unsigned long long)metrics->run_enclave_sum_cycles,
            safe_avg_u64(metrics->run_enclave_sum_cycles, metrics->run_enclave_count),
            metrics->run_enclave_min_cycles,
            metrics->run_enclave_max_cycles);
        printk("[BENCHMARK][CSV] irq_atomic,%u,%llu,%u,%u,%u\n",
            metrics->irq_atomic_count,
            (unsigned long long)metrics->irq_atomic_sum_cycles,
            safe_avg_u64(metrics->irq_atomic_sum_cycles, metrics->irq_atomic_count),
            metrics->irq_atomic_min_cycles,
            metrics->irq_atomic_max_cycles);
        printk("[BENCHMARK][CSV] create_atomic,%u,%llu,%u,%u,%u\n",
            metrics->create_atomic_count,
            (unsigned long long)metrics->create_atomic_sum_cycles,
            safe_avg_u64(metrics->create_atomic_sum_cycles, metrics->create_atomic_count),
            metrics->create_atomic_min_cycles,
            metrics->create_atomic_max_cycles);
        printk("[BENCHMARK][CSV] destroy_atomic,%u,%llu,%u,%u,%u\n",
            metrics->destroy_atomic_count,
            (unsigned long long)metrics->destroy_atomic_sum_cycles,
            safe_avg_u64(metrics->destroy_atomic_sum_cycles, metrics->destroy_atomic_count),
            metrics->destroy_atomic_min_cycles,
            metrics->destroy_atomic_max_cycles);
}

void benchmark_print_memory_summary(void)
{
    uint32_t used, free, total;
    benchmark_get_heap_usage(&used, &free, &total);
    uint32_t stack = benchmark_get_stack_usage();
    
    printk("[BENCHMARK] Memory: Heap=%u/%u KB (%.1f%%), Stack=%u KB\n",
           used / 1024, total / 1024,
            (total > 0) ? (100.0 * (double)used / (double)total) : 0.0,
           stack / 1024);
}

void benchmark_reset_metrics(void)
{
    memset(&g_benchmark_metrics, 0, sizeof(g_benchmark_metrics));
}
