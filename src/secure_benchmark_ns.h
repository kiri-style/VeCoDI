/*
 * Secure Gate NS Interface for Benchmark
 * Provides NS-side definitions and PSA call wrappers to retrieve Secure benchmark metrics
 */

#ifndef SECURE_BENCHMARK_NS_H
#define SECURE_BENCHMARK_NS_H

#include <stdint.h>
#include <psa/client.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Must match secure_benchmark_metrics_t in dummy_partition/secure_benchmark.h */
typedef struct {
    /* Cryptographic operations */
    uint64_t aes_decrypt_cycles;
    uint64_t late_hash_cycles;
    uint64_t digest_compute_cycles;
    
    /* Counter management */
    uint64_t get_max_cycles;
    uint64_t check_allowed_cycles;
    uint64_t increment_cycles;
    uint64_t reset_cycles;
    
    /* Operation counts */
    uint32_t aes_decrypt_count;
    uint32_t late_hash_count;
    uint32_t digest_count;
    uint32_t counter_operations;
    
    /* Memory usage (Secure partition) */
    uint32_t ram_used_bytes;
    uint32_t ram_total_bytes;
    uint32_t flash_used_bytes;
    uint32_t flash_total_bytes;
    
} secure_benchmark_metrics_ns_t;

/**
 * Retrieve Secure partition benchmark metrics via PSA call
 * @param metrics Pointer to structure to fill with Secure metrics
 * @return 0 on success, negative on error
 */
int get_secure_benchmark_metrics(secure_benchmark_metrics_ns_t *metrics);

/**
 * Print Secure partition benchmark report (called from NS)
 * @param metrics Pointer to Secure metrics structure
 */
void print_secure_benchmark_report(const secure_benchmark_metrics_ns_t *metrics);

/**
 * Set maximum inferences in Secure partition
 * @param max_infs Maximum inference count
 * @return 0 on success, negative on error
 */
int set_max_inferences_secure(uint32_t max_infs);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_BENCHMARK_NS_H */
