#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include "inference.h"
#include "run_enclave.h"
#include "create_enclave.h"

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
    
    print_memory_stats();

    /* Étape 1: Création enclave */
    printk("[STEP 1] Creating enclave environment...\n");
    if (create_enclave() != 0) {
        printk("[ERROR] Enclave creation failed\n");
        return -1;
    }
    printk("[STEP 1] ✓ Complete\n\n");

    print_memory_stats();

    /* Étape 2: Exécution inference */
    printk("[STEP 2] Running inference in enclave...\n");
    run_enclave();
    printk("[STEP 2] ✓ Complete\n\n");

    print_memory_stats();

    printk("\n========================================\n");
    printk("=== All operations completed ===\n");
    printk("========================================\n\n");

    while (1) {
        k_sleep(K_FOREVER);
    }
}