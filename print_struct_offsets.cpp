#include <iostream>
#include <cstddef>
#include "src/benchmark.h"

int main() {
    std::cout << "Size of benchmark_metrics_t: " << sizeof(benchmark_metrics_t) << " bytes\n\n";
    
    // Print offsets of key fields
    benchmark_metrics_t m;
    
    std::cout << "Offset of enclave_create_cycles: " << offsetof(benchmark_metrics_t, enclave_create_cycles) << "\n";
    std::cout << "Offset of full_execute_cycles: " << offsetof(benchmark_metrics_t, full_execute_cycles) << "\n";
    std::cout << "Offset of heap_used_bytes: " << offsetof(benchmark_metrics_t, heap_used_bytes) << "\n";
    std::cout << "Offset of enclave_create_sum_cycles: " << offsetof(benchmark_metrics_t, enclave_create_sum_cycles) << "\n";
    std::cout << "Offset of full_execute_count: " << offsetof(benchmark_metrics_t, full_execute_count) << "\n";
    std::cout << "Offset of full_execute_sum_cycles: " << offsetof(benchmark_metrics_t, full_execute_sum_cycles) << "\n";
    std::cout << "Offset of create_atomic_sum_cycles: " << offsetof(benchmark_metrics_t, create_atomic_sum_cycles) << "\n";
    std::cout << "Offset of run_inference_with_image_count: " << offsetof(benchmark_metrics_t, run_inference_with_image_count) << "\n";
    
    return 0;
}
