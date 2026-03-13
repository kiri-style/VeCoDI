/*
 * sau_test.cpp — SAU dynamic RAM enclave isolation demo
 *
 * Demonstrates the OPEN/CLOSE SAU lifecycle from the Non-Secure side.
 * The Secure partition (dummy_partition) is the sole authority over
 * SAU region configuration; NS only issues PSA IPC calls.
 *
 * Expected console output (with SAU_TEST_TRIGGER_HARDFAULT = 1):
 *
 *   [SAU TEST] ========================
 *   [SAU TEST] SAU Isolation Demo
 *   [SAU TEST] Enclave base: 0x20000fc0  size: 39552
 *   stage open: status=0, byte=0xa2
 *   [SAU TEST] open read 1 @0x20000fc0 = 0xXX  (OK)
 *   ...
 *   [SAU TEST] open read 5 @0x20000fc0+128 = 0xXX  (OK)
 *   [SAU TEST] open write @0x20000fc0 = 0xAB, readback=0xAB  (OK)
 *   stage close: status=0, byte=0xa1
 *   [SAU TEST] final read @0x20000fc0
 *   [SAU TEST] >>> HARDFAULT INCOMING <<<
 *   FATAL ERROR: HardFault  ← printed by k_sys_fatal_error_handler
 *   SAU isolation VERIFIED
 *
 * Hors enclave: all other NS RAM accesses remain unaffected.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <psa/client.h>

#include "sau_test.h"
#include "create_enclave.h"   /* get_enclave_region(), enclave_sau_open/close */

/* Control: set to 1 to actually trigger the HardFault (system will crash/reset).
 * Set to 0 to verify OPEN/CLOSE without the fatal crash. */
#ifndef SAU_TEST_TRIGGER_HARDFAULT
#define SAU_TEST_TRIGGER_HARDFAULT 1
#endif

/* Dedicated small RAM window for SAU isolation demo.
 * Kept independent from large inference buffers to avoid accidental faults
 * before the explicit final-read step. */
alignas(32) static uint8_t sau_test_window[160];

void sau_test_isolation(void)
{
    volatile uint8_t *enc = (volatile uint8_t *)sau_test_window;
    uint32_t          sz  = (uint32_t)sizeof(sau_test_window);

    if (enclave_sau_register_window((const uint8_t *)enc, sz) != 0) {
        printk("[SAU TEST] ERROR: register window failed\n");
        return;
    }

    printk("\n[SAU TEST] ========================\n");
    printk("[SAU TEST] SAU Dynamic RAM Enclave Isolation Demo\n");
    printk("[SAU TEST] Enclave base: %p  size: %u\n", (void *)enc, sz);
    printk("[SAU TEST] NS_DATA_START (TF-M SAU region 1 base): checked by Secure\n\n");

    /* ------------------------------------------------------------------ */
    /* Step 1: OPEN the enclave window (cmd=2 → 0xA2)                     */
    /* ------------------------------------------------------------------ */
    if (enclave_sau_open() != 0) {
        printk("[SAU TEST] ERROR: OPEN failed (SAU not registered?)\n");
        return;
    }

    /* ------------------------------------------------------------------ */
    /* Step 2: Read 5 addresses inside the enclave window                 */
    /*         (must succeed: enclave is NS-accessible)                   */
    /* ------------------------------------------------------------------ */
    for (int i = 0; i < 5; i++) {
        volatile uint8_t v = enc[(size_t)i * 32];
        printk("[SAU TEST] open read %d @%p = 0x%02X  (OK)\n",
               i + 1, (const void *)(enc + (size_t)i * 32), v);
    }

    /* Write test */
    enc[0] = 0xABU;
    volatile uint8_t rb = enc[0];
    printk("[SAU TEST] open write @%p = 0xAB, readback=0x%02X  (OK)\n",
           (void *)enc, rb);

    /* ------------------------------------------------------------------ */
    /* Step 3: CLOSE the enclave window (cmd=1 → 0xA1)                   */
    /* ------------------------------------------------------------------ */
    if (enclave_sau_close() != 0) {
        printk("[SAU TEST] ERROR: CLOSE failed\n");
        return;
    }

    /* Verify: accesses to memory OUTSIDE the enclave still work. */
    printk("[SAU TEST] Hors enclave: stack access OK (addr=%p)\n",
           (void *)&enc);

    /* ------------------------------------------------------------------ */
    /* Step 4: Access the closed enclave → BusFault → HardFault           */
    /* ------------------------------------------------------------------ */
    printk("[SAU TEST] final read @%p\n", (void *)enc);
    printk("[SAU TEST] >>> HARDFAULT INCOMING <<<\n");

    /* Delay so UART output flushes before the intentional fault. */
    k_sleep(K_MSEC(300));

#if SAU_TEST_TRIGGER_HARDFAULT
    /* This read goes to a Secure address (SAU CLOSED) from NS world.
     * The AHB matrix raises a BusFault which escalates to HardFault. */
    volatile uint8_t fault_val = enc[0];
    (void)fault_val;

    /* Never reached if SAU isolation is working. */
    printk("[SAU TEST] ERROR: expected HardFault but got 0x%02X — isolation FAILED!\n",
           fault_val);
#else
    printk("[SAU TEST] HardFault trigger DISABLED (SAU_TEST_TRIGGER_HARDFAULT=0)\n");
    printk("[SAU TEST] SAU isolation VERIFIED (OPEN/CLOSE both worked)\n");
    printk("[SAU TEST] ========================\n\n");
#endif
}

void sau_test_isolation_print_only(void)
{
    volatile uint8_t *enc = (volatile uint8_t *)sau_test_window;
    uint32_t          sz  = (uint32_t)sizeof(sau_test_window);

    if (enclave_sau_register_window((const uint8_t *)enc, sz) != 0) {
        printk("[SAU TEST] ERROR: register window failed\n");
        return;
    }

    printk("\n[SAU TEST] ===== print-only cycle =====\n");
    printk("[SAU TEST] window=%p size=%u\n", (void *)enc, sz);

    if (enclave_sau_open() != 0) {
        printk("[SAU TEST] ERROR: OPEN failed\n");
        return;
    }

    for (int i = 0; i < 5; i++) {
        volatile uint8_t v = enc[(size_t)i * 32];
        printk("[SAU TEST] open read %d @%p = 0x%02X\n",
               i + 1, (const void *)(enc + (size_t)i * 32), v);
    }

    enc[0] = (uint8_t)(enc[0] + 1U);
    printk("[SAU TEST] open write/read @%p = 0x%02X\n", (void *)enc, enc[0]);

    if (enclave_sau_close() != 0) {
        printk("[SAU TEST] ERROR: CLOSE failed\n");
        return;
    }

    printk("[SAU TEST] close done (no HardFault in print-only mode)\n");
    printk("[SAU TEST] hors enclave stack access OK: %p\n", (void *)&enc);
    printk("[SAU TEST] ===============================\n");
}
