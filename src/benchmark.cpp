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
    printk("║ Late Hash:   %8u cycles  (%6u ms)                   ║\n",
           metrics->late_hash_cycles,
           benchmark_cycles_to_ms(metrics->late_hash_cycles));
    printk("║ Inf Hash:    %8u cycles  (%6u ms)                   ║\n",
           metrics->inference_hash_cycles,
           benchmark_cycles_to_ms(metrics->inference_hash_cycles));
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
    printk("║ run_enclave(): %8u cycles  (%6u ms)                 ║\n",
           metrics->run_enclave_cycles,
           benchmark_cycles_to_ms(metrics->run_enclave_cycles));
    printk("║ Inferences:    %8u total                               ║\n",
           metrics->inference_count);
    
    // Calculate average if we have inferences
    if (metrics->inference_count > 0) {
        uint32_t avg_cycles = metrics->run_enclave_cycles / metrics->inference_count;
        printk("║ Avg per inf:   %8u cycles  (%6u ms)                 ║\n",
               avg_cycles, benchmark_cycles_to_ms(avg_cycles));
    }
    
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
}

void benchmark_print_memory_summary(void)
{
    uint32_t used, free, total;
    benchmark_get_heap_usage(&used, &free, &total);
    uint32_t stack = benchmark_get_stack_usage();
    
    printk("[BENCHMARK] Memory: Heap=%u/%u KB (%.1f%%), Stack=%u KB\n",
           used / 1024, total / 1024,
           (total > 0) ? (100.0f * used / total) : 0.0f,
           stack / 1024);
}

void benchmark_reset_metrics(void)
{
    memset(&g_benchmark_metrics, 0, sizeof(g_benchmark_metrics));
}
