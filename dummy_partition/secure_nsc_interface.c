#include <arm_cmse.h>
#include <stdint.h>
#include <stdio.h>
#include "cmsis.h"
#include "flash_layout.h"

/*
 * Secure → Non-Secure bridge.
 *
 * This helper validates a Non-Secure entry address and safely transitions
 * to it using CMSE sanitization. Intended for debug/bring-up scenarios.
 */

/* =========================================================
 * Adresse réelle issue du zephyr.map + 1 (Thumb bit)
 * ========================================================= */
#define NS_ENCLAVE_ADDR   (0x0C042599U)


/* Prototype fonction Non-Secure. */
typedef void (*ns_enclave_func_t)(void)
    __attribute__((cmse_nonsecure_call));

/* =========================================================
 * Secure → Non-Secure Bridge
 * ========================================================= */
__attribute__((cmse_nonsecure_entry))
void secure_call_ns_enclave(void)
{
    printf("\n==============================\n");
    printf("[SECURE] secure_call_ns_enclave()\n");

    printf("[SECURE] FLASH_BASE_ADDRESS = 0x%08X\n",
           (uint32_t)FLASH_BASE_ADDRESS);

    printf("[SECURE] Target NS addr = 0x%08X\n",
           (uint32_t)NS_ENCLAVE_ADDR);

    printf("[SECURE] SAU->CTRL = 0x%08X\n",
           (uint32_t)SAU->CTRL);

    printf("[SECURE] SCB->AIRCR = 0x%08X\n",
           (uint32_t)SCB->AIRCR);

    /* ----------------------------------------------------- */
    if (!cmse_is_nsfptr((void *)NS_ENCLAVE_ADDR)) {
        printf("[SECURE] ❌ ERROR: Address NOT NonSecure!\n");
        return;
    }

    printf("[SECURE] ✔ Address is NonSecure\n");

    ns_enclave_func_t ns_func =
        (ns_enclave_func_t)cmse_nsfptr_create(
            (void *)NS_ENCLAVE_ADDR);

    if (ns_func == NULL) {
        printf("[SECURE] ❌ ERROR: cmse_nsfptr_create NULL\n");
        return;
    }

    printf("[SECURE] ✔ NS function pointer sanitized\n");

    __DSB();
    __ISB();

    printf("[SECURE] 🚀 Jumping to NonSecure world...\n");

    ns_func();

    printf("[SECURE] 🔙 Returned from NonSecure world\n");
    printf("==============================\n\n");
}