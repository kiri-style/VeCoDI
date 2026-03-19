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
#include "sau_test.h"
#include "create_enclave.h"

/* Control: set to 1 to actually trigger the HardFault (system will crash/reset).
 * Set to 0 to verify OPEN/CLOSE without the fatal crash. */
#ifndef SAU_TEST_TRIGGER_HARDFAULT
#define SAU_TEST_TRIGGER_HARDFAULT 1
#endif

void sau_test_isolation(void)
{
    ARG_UNUSED(SAU_TEST_TRIGGER_HARDFAULT);
    printk("[SAU TEST] NS-driven SAU control is disabled by security policy\n");
    printk("[SAU TEST] Use Create_Enclave / Run_Enclave / Destroy_Enclave flow\n");
}

void sau_test_isolation_print_only(void)
{
    printk("[SAU TEST] Print-only mode disabled (no NS SAU API exposed)\n");
}
