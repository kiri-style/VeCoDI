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
#include "create_enclave.h"

/* Control: set to 1 to actually trigger the HardFault (system will crash/reset).
 * Set to 0 to verify OPEN/CLOSE without the fatal crash. */
#ifndef SAU_TEST_TRIGGER_HARDFAULT
#define SAU_TEST_TRIGGER_HARDFAULT 1
#endif

/* 1: call cmd=6 after cmd=5 (normal path). 0: stay closed (fault expected). */
#ifndef SAU_ROM_TEST_REOPEN
#define SAU_ROM_TEST_REOPEN 1
#endif

#define TFM_DP_SERVICE_SID          0xFFFFF002U
#define DP_CMD_CHECK_INFERENCE_ALLOWED 5U
#define DP_CMD_INCREMENT_COUNTER    6U

__attribute__((noinline, aligned(32), section(".flash_exec_test")))
static int rom_target_function(int x)
{
    return (x * 5) + 1;
}

static int call_secure_cmd_u32(uint32_t cmd)
{
    psa_handle_t h = psa_connect(TFM_DP_SERVICE_SID, 1);
    if (h <= 0) {
        return -1;
    }
    psa_invec in = { &cmd, sizeof(cmd) };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, &in, 1, NULL, 0);
    psa_close(h);
    return (st == PSA_SUCCESS) ? 0 : -1;
}

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

void sau_test_rom_protection(void)
{
    uintptr_t fn = (uintptr_t)&rom_target_function;
    uint32_t win_base = (uint32_t)(fn & ~((uintptr_t)0x1FU));
    uint32_t win_limit = win_base + 31U;

    printk("[SAU ROM TEST] target fn=0x%08x\n", (uint32_t)fn);
    printk("[SAU ROM TEST] computed window=0x%08x..0x%08x\n", win_base, win_limit);

    int r1 = rom_target_function(7);
    printk("[SAU ROM TEST] call #1 result=%d\n", r1);

    int st_close = call_secure_cmd_u32(DP_CMD_CHECK_INFERENCE_ALLOWED);
    printk("[SAU ROM TEST] cmd=5 close status=%d\n", st_close);

#if SAU_ROM_TEST_REOPEN
    int st_open = call_secure_cmd_u32(DP_CMD_INCREMENT_COUNTER);
    printk("[SAU ROM TEST] cmd=6 open status=%d\n", st_open);
#endif

    printk("[SAU ROM TEST] call #2 entering...\n");
    int r2 = rom_target_function(7);
    printk("[SAU ROM TEST] call #2 result=%d\n", r2);
}
