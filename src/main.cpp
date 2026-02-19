#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
// #include "inference.h"  // Legacy full-model path (not used)
#include "run_enclave.h"
#include "create_enclave.h"
#include "split_inference.h"

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

    /* Étape 1.5: Configuration split inference avec late weights déchiffrés */
    printk("[STEP 1.5] Configuring split inference with decrypted weights...\n");
    uint8_t* late_wt_buf = get_enclave_region();
    size_t late_wt_size = get_enclave_region_size();
    set_late_weights_buffer(late_wt_buf, late_wt_size);
    printk("[STEP 1.5] ✓ Late weights buffer configured: %p (%zu bytes)\n\n", 
           (void*)late_wt_buf, late_wt_size);

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