#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
// #include "inference.h"  // Legacy full-model path (not used)
#include "run_enclave.h"
#include "create_enclave.h"
#include "split_inference.h"
#include "benchmark.h"
#include "secure_benchmark_ns.h"
#include "uart_protocol.h"

/* Configuration: Set to 1 for simple UART test, 0 for normal flow */
#define SIMPLE_UART_MODE 0

/* Configuration: Set to 1 for Mac interactive mode, 0 for auto test */
#define MAC_INTERACTIVE_MODE 1

/* Forward declarations for test functions */
extern "C" int test_enclave_authorization_protocol(void);
extern "C" int test_inference_protocol(void);

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
#if SIMPLE_UART_MODE
    const struct device *uart = DEVICE_DT_GET(DT_NODELABEL(lpuart1));
    if (!device_is_ready(uart)) {
        while (1) {
            k_sleep(K_FOREVER);
        }
    }

    // Simple test: Mac sends 0x01, device responds 0x02
    while (1) {
        uint8_t byte;
        if (uart_poll_in(uart, &byte) == 0) {
            if (byte == 0x01) {
                uart_poll_out(uart, 0x02);
            }
        }
        k_sleep(K_MSEC(1));
    }
#endif

    // All console output disabled to avoid interfering with binary UART protocol
    // (CONFIG_PRINTK=n in prj.conf disables printk at compile time)

    /* Initialize benchmark system */
    benchmark_init();

    // print_memory_stats();

#if MAC_INTERACTIVE_MODE
    /* MAC INTERACTIVE MODE: Device waits for commands from Mac */
    /* All console output disabled to avoid interfering with binary protocol */

    /* Initialize UART protocol */
    while (uart_protocol_init() != 0) {
        k_sleep(K_MSEC(100));
    }

    /* Main loop: process incoming commands - no console output to avoid protocol interference */
    while (1) {
        uart_protocol_process();
        k_yield();
    }

#else
    /* AUTO TEST MODE: Run automated tests */
    printk("\n[MAIN] AUTO TEST MODE\n");
    printk("[MAIN] Starting Enclave Authorization Protocol Test...\n\n");

    int auth_result = test_enclave_authorization_protocol();

    if (auth_result != 0) {
        printk("\n[MAIN] ERROR: Authorization protocol test failed\n");
        printk("========================================\n\n");
        while (1) {
            k_sleep(K_FOREVER);
        }
    }

    /* Phase 2: Test Inference Protocol (M_inf / PoX) */
    printk("\n[MAIN] Starting Inference Protocol Test...\n\n");
    int inference_protocol_result = test_inference_protocol();

    if (inference_protocol_result != 0) {
        printk("\n[MAIN] ERROR: Inference protocol test failed\n");
        printk("========================================\n\n");
        while (1) {
            k_sleep(K_FOREVER);
        }
    }

    /* Phase 3: Single inference in enclave */
    printk("\n[MAIN] Running single inference in enclave...\n");
    run_enclave();
    printk("[MAIN] ✓ Inference complete\n\n");

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
#endif

    return 0;
}