/*
 * Secure Benchmark System for TF-M Dummy Partition
 * 
 * Provides cycle-accurate performance measurement for Secure-side operations
 * using ARM Cortex-M33 DWT (Data Watchpoint and Trace) hardware.
 */

#ifndef SECURE_BENCHMARK_H
#define SECURE_BENCHMARK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Secure-side performance metrics */
typedef struct {
    /* Cryptographic operations */
    uint64_t aes_decrypt_cycles;
    uint64_t late_hash_cycles;
    uint64_t digest_compute_cycles;
    uint64_t authorize_cycles;
    uint64_t global_crypto_init_cycles;

    /* Fine-grained Authorize/Create metrics */
    uint64_t create_validate_cycles;
    uint64_t authorize_parse_cycles;
    uint64_t authorize_verify_cycles;
    uint64_t authorize_update_cycles;
    uint64_t authorize_crypto_init_cycles;
    uint64_t authorize_read_cycles;
    uint64_t authorize_import_key_cycles;
    uint64_t authorize_hash_msg_cycles;
    uint64_t authorize_verify_sig_cycles;
    uint64_t authorize_destroy_key_cycles;
    uint64_t authorize_verify_message_cycles;
    uint64_t authorize_verify_old_cycles;
    uint64_t create_recompute_cycles;
    
    /* Counter management */
    uint64_t get_max_cycles;
    uint64_t check_allowed_cycles;
    uint64_t increment_cycles;
    uint64_t reset_cycles;

    /* Secure lifecycle / transaction operations */
    uint64_t create_enclave_cycles;
    uint64_t finalize_create_cycles;
    uint64_t destroy_enclave_cycles;
    uint64_t inf_start_cycles;
    uint64_t inf_complete_cycles;

    /* SAU management operations */
    uint64_t sau_sync_open_cycles;
    uint64_t sau_sync_close_cycles;
    uint64_t sau_flash_close_cycles;
    uint64_t sau_flash_open_cycles;
    uint64_t sau_flash_pulse_cycles;
    
    /* Operation counts */
    uint32_t aes_decrypt_count;
    uint32_t late_hash_count;
    uint32_t digest_count;
    uint32_t authorize_count;
    uint32_t authorize_crypto_init_count;
    uint32_t authorize_import_key_count;
    uint32_t authorize_verify_sig_count;
    uint32_t authorize_verify_message_count;
    uint32_t create_recompute_count;
    uint32_t counter_operations;

    /* Operation counts for lifecycle / SAU */
    uint32_t create_enclave_count;
    uint32_t finalize_create_count;
    uint32_t destroy_enclave_count;
    uint32_t inf_start_count;
    uint32_t inf_complete_count;
    uint32_t sau_sync_open_count;
    uint32_t sau_sync_close_count;
    uint32_t sau_flash_close_count;
    uint32_t sau_flash_open_count;
    uint32_t sau_flash_pulse_count;
    
    /* Memory usage (Secure partition) */
    uint32_t ram_used_bytes;
    uint32_t ram_total_bytes;
    uint32_t flash_used_bytes;
    uint32_t flash_total_bytes;
    
} secure_benchmark_metrics_t;

/* Global metrics (Secure-side) */
extern secure_benchmark_metrics_t g_secure_metrics;

/**
 * Initialize Secure benchmark system (DWT cycle counter)
 */
void secure_benchmark_init(void);

/**
 * Get current DWT cycle count
 */
uint32_t secure_benchmark_get_cycles(void);

/**
 * Convert cycles to milliseconds (110 MHz CPU)
 */
uint32_t secure_benchmark_cycles_to_ms(uint64_t cycles);

/**
 * Convert cycles to microseconds (110 MHz CPU)
 */
uint32_t secure_benchmark_cycles_to_us(uint64_t cycles);

/**
 * Get Secure partition memory usage (RAM and Flash)
 */
void secure_benchmark_get_memory_usage(uint32_t *ram_used, uint32_t *ram_total,
                                       uint32_t *flash_used, uint32_t *flash_total);

/**
 * Print Secure-side benchmark report
 */
void secure_benchmark_print_report(void);

/* Benchmark macros for easy instrumentation */
#define SECURE_BENCHMARK_START(var) \
    uint32_t var = secure_benchmark_get_cycles()

#define SECURE_BENCHMARK_END(var, field) \
    do { \
        uint32_t end_cycles = secure_benchmark_get_cycles(); \
        g_secure_metrics.field += (end_cycles - var); \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* SECURE_BENCHMARK_H */
