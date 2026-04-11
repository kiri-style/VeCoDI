/*
 * sau_test.h — SAU dynamic RAM enclave isolation demo
 *
 * Validates the OPEN/CLOSE SAU lifecycle:
 *   1. OPEN  → NS can read/write the enclave window
 *   2. CLOSE → NS access triggers BusFault → HardFault
 *
 * Call sau_test_isolation() AFTER create_enclave() so the enclave
 * window is already registered with the Secure partition.
 *
 * NOTE: sau_test_isolation() intentionally triggers a HardFault at the
 * end of the test when SAU_TEST_TRIGGER_HARDFAULT == 1.  The Zephyr
 * fatal-error handler (overridden in main.cpp) prints a diagnostic
 * message before halting.  Set the flag to 0 to run without crashing.
 */

#ifndef SAU_TEST_H
#define SAU_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Run the full SAU isolation test sequence:
 *   stage open  → 5 reads/writes → stage close → [HardFault if enabled]
 */
void sau_test_isolation(void);

/* Non-destructive variant: prints OPEN/CLOSE checks without triggering HardFault. */
void sau_test_isolation_print_only(void);

/* ROM/flash SAU toggle test driven by secure cmd=5/cmd=6. */
void sau_test_rom_protection(void);

#ifdef __cplusplus
}
#endif

#endif /* SAU_TEST_H */
