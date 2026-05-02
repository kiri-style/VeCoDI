#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Performance Counters Initialization
// ============================================================================

/**
 * @brief Initialize DWT cycle counter for precise timing measurements
 * @note Must be called once at startup before any benchmark calls
 */
void benchmark_init(void);

// ============================================================================
// Cycle Counter API
// ============================================================================

/**
 * @brief Get current CPU cycle count
 * @return Current cycle count (32-bit, wraps around)
 */
uint32_t benchmark_get_cycles(void);

/**
 * @brief Convert cycles to microseconds
 * @param cycles Number of CPU cycles
 * @return Time in microseconds
 */
uint32_t benchmark_cycles_to_us(uint32_t cycles);

/**
 * @brief Convert cycles to milliseconds
 * @param cycles Number of CPU cycles
 * @return Time in milliseconds
 */
uint32_t benchmark_cycles_to_ms(uint32_t cycles);

// ============================================================================
// Memory Usage API
// ============================================================================

/**
 * @brief Get current heap usage statistics
 * @param used_bytes Output: bytes currently allocated
 * @param free_bytes Output: bytes available
 * @param total_bytes Output: total heap size
 */
void benchmark_get_heap_usage(uint32_t *used_bytes, uint32_t *free_bytes, uint32_t *total_bytes);

/**
 * @brief Get stack usage for current thread
 * @return Stack usage in bytes (approximate)
 */
uint32_t benchmark_get_stack_usage(void);

/**
 * @brief Get RAM and Flash usage from linker symbols
 * @param ram_used Output: RAM used in bytes
 * @param ram_total Output: Total RAM available in bytes
 * @param flash_used Output: Flash used in bytes
 * @param flash_total Output: Total Flash available in bytes
 */
void benchmark_get_memory_usage(uint32_t *ram_used, uint32_t *ram_total,
                                uint32_t *flash_used, uint32_t *flash_total);

// ============================================================================
// Performance Metrics Storage
// ============================================================================

typedef struct {
    // Enclave lifecycle
    uint32_t enclave_create_cycles;
    uint32_t enclave_destroy_cycles;
    
    // Decryption (Secure world)
    uint32_t aes_decrypt_cycles;
    
    // Inference
    uint32_t early_layers_cycles;
    uint32_t late_layers_cycles;
    uint32_t total_inference_cycles;
    
    // End-to-end
    uint32_t run_enclave_cycles;

    // Full verified inference flow (handle_run_inference_common)
    uint32_t full_execute_cycles;
    
    // Memory
    uint32_t heap_used_bytes;
    uint32_t heap_free_bytes;
    uint32_t stack_used_bytes;
    
    // RAM/Flash usage (from linker symbols)
    uint32_t ram_used_bytes;
    uint32_t ram_total_bytes;
    uint32_t flash_used_bytes;
    uint32_t flash_total_bytes;
    
    // Counter metrics
    uint32_t inference_count;
    uint32_t enclave_recreations;

    // Request / security counters
    uint32_t inference_requests_total;
    uint32_t enclave_info_validation_failures;

    // Aggregate cycle stats (for paper reporting)
    uint64_t enclave_create_sum_cycles;
    uint64_t enclave_destroy_sum_cycles;
    uint64_t aes_decrypt_sum_cycles;
    uint64_t early_layers_sum_cycles;
    uint64_t late_layers_sum_cycles;
    uint64_t total_inference_sum_cycles;
    uint64_t run_enclave_sum_cycles;
    uint64_t irq_atomic_sum_cycles;

    uint32_t enclave_create_min_cycles;
    uint32_t enclave_create_max_cycles;
    uint32_t enclave_destroy_min_cycles;
    uint32_t enclave_destroy_max_cycles;
    uint32_t aes_decrypt_min_cycles;
    uint32_t aes_decrypt_max_cycles;
    uint32_t early_layers_min_cycles;
    uint32_t early_layers_max_cycles;
    uint32_t late_layers_min_cycles;
    uint32_t late_layers_max_cycles;
    uint32_t total_inference_min_cycles;
    uint32_t total_inference_max_cycles;
    uint32_t run_enclave_min_cycles;
    uint32_t run_enclave_max_cycles;
    uint32_t irq_atomic_min_cycles;
    uint32_t irq_atomic_max_cycles;

    uint32_t enclave_create_count;
    uint32_t enclave_destroy_count;
    uint32_t aes_decrypt_count;
    uint32_t early_layers_count;
    uint32_t late_layers_count;
    uint32_t total_inference_count;
    uint32_t run_enclave_count;
    uint32_t irq_atomic_count;

    uint32_t full_execute_count;

    uint64_t full_execute_sum_cycles;
    uint32_t full_execute_min_cycles;
    uint32_t full_execute_max_cycles;

    // Dedicated atomic operation stats (UART lifecycle critical sections)
    uint64_t create_atomic_sum_cycles;
    uint64_t destroy_atomic_sum_cycles;
    uint32_t create_atomic_min_cycles;
    uint32_t create_atomic_max_cycles;
    uint32_t destroy_atomic_min_cycles;
    uint32_t destroy_atomic_max_cycles;
    uint32_t create_atomic_count;
    uint32_t destroy_atomic_count;

    // UART flow counters for critical feature coverage
    uint32_t run_inference_with_image_count;
    uint32_t dangerous_inference_no_sau_count;
    uint32_t dangerous_read_ram_count;
    uint32_t dangerous_read_rom_count;

    // NS M_update timing (handle_validate_m_update)
    uint64_t m_update_cycles;
    uint32_t m_update_count;
} benchmark_metrics_t;

extern benchmark_metrics_t g_benchmark_metrics;

// ============================================================================
// Reporting API
// ============================================================================

/**
 * @brief Print comprehensive performance report
 * @param metrics Pointer to metrics structure
 */
void benchmark_print_report(const benchmark_metrics_t *metrics);

/**
 * @brief Print memory usage summary
 */
void benchmark_print_memory_summary(void);

/**
 * @brief Reset all metrics to zero
 */
void benchmark_reset_metrics(void);

// ============================================================================
// Convenience Macros
// ============================================================================

#define BENCHMARK_START(var_name) \
    uint32_t var_name##_start = benchmark_get_cycles()

#define BENCHMARK_END(var_name, target_field) \
    do { \
        uint32_t var_name##_end = benchmark_get_cycles(); \
        uint32_t var_name##_elapsed = var_name##_end - var_name##_start; \
        target_field = var_name##_elapsed; \
    } while(0)

#define BENCHMARK_MEASURE(operation, target_field) \
    do { \
        BENCHMARK_START(bench); \
        operation; \
        BENCHMARK_END(bench, target_field); \
    } while(0)

#define BENCHMARK_ACCUMULATE(sample_cycles, sum_field, min_field, max_field, count_field) \
    do { \
        uint32_t __bench_sample = (sample_cycles); \
        (sum_field) += (uint64_t)__bench_sample; \
        if ((count_field) == 0U || __bench_sample < (min_field)) { \
            (min_field) = __bench_sample; \
        } \
        if ((count_field) == 0U || __bench_sample > (max_field)) { \
            (max_field) = __bench_sample; \
        } \
        (count_field)++; \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif // BENCHMARK_H
