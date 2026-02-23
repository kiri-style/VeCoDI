#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
// #include "inference.h"  // Legacy full-model path (not used)
#include "run_enclave.h"
#include "create_enclave.h"
#include "split_inference.h"
#include "benchmark.h"
#include "secure_benchmark_ns.h"

/* Linker symbols pour calculs mémoire */
extern char __bss_start[];
extern char __bss_end[];
extern char __data_start[];
extern char __data_end[];

static void print_memory_stats(void)
{
    size_t bss_size = (size_t)(__bss_end - __bss_start);
    size_t data_size = (size_t)(__data_end - __data_start);
    
    printk("\n======= NS MEMORY STATS =======\n");
    printk("  BSS size:   %zu bytes\n", bss_size);
    printk("  DATA size:  %zu bytes\n", data_size);
    printk("  Stack ptr:  %p\n", (void*)&bss_size);
    printk("===============================\n\n");
}

int main(void)
{
    printk("\n\n");
    printk("========================================\n");
    printk("=== CIFAR-10 Enclave + ROM Model ===\n");
    printk("========================================\n\n");
    
    /* Initialize benchmark system */
    benchmark_init();
    
    print_memory_stats();

    /* Les étapes 1 et 1.5 sont maintenant gérées automatiquement par run_enclave() */
    /* L'enclave est créée au premier appel et recréée après destruction */

    /* Étape 2: Exécution inference - 4 appels (1 inférence par appel) */
    /* Limite: 3 inférences autorisées par enclave */
    for (int i = 0; i < 4; i++) {
        printk("[STEP 2] Running inference in enclave (call %d/4)...\n", i+1);
        run_enclave();
        printk("[STEP 2] ✓ Call %d/4 complete\n\n", i+1);
    }

    print_memory_stats();
    
    /* Update final memory metrics */
    benchmark_get_heap_usage(&g_benchmark_metrics.heap_used_bytes,
                            &g_benchmark_metrics.heap_free_bytes,
                            NULL);
    g_benchmark_metrics.stack_used_bytes = benchmark_get_stack_usage();
    
    /* Get RAM and Flash usage */
    benchmark_get_memory_usage(&g_benchmark_metrics.ram_used_bytes,
                              &g_benchmark_metrics.ram_total_bytes,
                              &g_benchmark_metrics.flash_used_bytes,
                              &g_benchmark_metrics.flash_total_bytes);

    printk("\n========================================\n");
    printk("=== All operations completed ===\n");
    printk("========================================\n\n");
    
    /* Print comprehensive benchmark report */
    benchmark_print_report(&g_benchmark_metrics);
    
    /* Retrieve and print Secure partition benchmark */
    secure_benchmark_metrics_ns_t secure_metrics;
    if (get_secure_benchmark_metrics(&secure_metrics) == 0) {
        print_secure_benchmark_report(&secure_metrics);
    } else {
        printk("[NS] Warning: Failed to retrieve Secure benchmark metrics\n");
    }

    while (1) {
        k_sleep(K_FOREVER);
    }
}