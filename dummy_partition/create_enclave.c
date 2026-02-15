#include <arm_cmse.h>
#include <stdint.h>
#include "stm32l5xx.h"

/* =========================================================
 * CONFIGURATION
 * ========================================================= */

#define ENCLAVE_SAU_REGION   6
#define ENCLAVE_START        0x20008000
#define ENCLAVE_SIZE         0x00004000
#define ENCLAVE_END          (ENCLAVE_START + ENCLAVE_SIZE - 1)  // <-- inclusif

#define NS_ENCLAVE_IRQn      EXTI15_IRQn

static volatile uint8_t enclave_open = 0;
static volatile uint8_t enclave_done = 0;

/* =========================================================
 * SAU HELPERS
 * ========================================================= */

static inline void sau_disable(void)
{
    SAU->CTRL &= ~SAU_CTRL_ENABLE_Msk;
    __DSB();
    __ISB();
}

static inline void sau_enable(void)
{
    SAU->CTRL |= SAU_CTRL_ENABLE_Msk;
    __DSB();
    __ISB();
}

static void sau_config_nonsecure(uint32_t start, uint32_t end)
{
    SAU->RNR  = ENCLAVE_SAU_REGION;
    SAU->RBAR = start & SAU_RBAR_BADDR_Msk;
    SAU->RLAR = (end  & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk;
}

static void sau_config_secure(uint32_t start, uint32_t end)
{
    SAU->RNR  = ENCLAVE_SAU_REGION;
    SAU->RBAR = start & SAU_RBAR_BADDR_Msk;
    SAU->RLAR = (end  & SAU_RLAR_LADDR_Msk);  // ENABLE bit cleared
}

/* =========================================================
 * CREATE ENCLAVE
 * ========================================================= */

void secure_create_enclave(void)
{
    if (enclave_open)
        return;

    enclave_done = 0;

    /* Disable IRQ globally */
    __disable_irq();

    /* Open memory window to NonSecure */
    sau_disable();
    sau_config_nonsecure(ENCLAVE_START, ENCLAVE_END);
    sau_enable();

    __DSB();
    __ISB();

    enclave_open = 1;
}

/* =========================================================
 * DESTROY ENCLAVE
 * ========================================================= */

void secure_destroy_enclave(void)
{
    if (!enclave_open)
        return;

    /* Close memory window */
    sau_disable();
    sau_config_secure(ENCLAVE_START, ENCLAVE_END);
    sau_enable();

    __DSB();
    __ISB();

    enclave_open = 0;

    /* Restore interrupts */
    __enable_irq();
}

/* =========================================================
 * RUN ENCLAVE
 * ========================================================= */

void secure_run_enclave(void)
{
    if (enclave_open)
        return;

    secure_create_enclave();

    /* Route IRQ to NonSecure */
    NVIC_SetTargetState(NS_ENCLAVE_IRQn);

    /* Trigger NonSecure handler */
    NVIC_SetPendingIRQ(NS_ENCLAVE_IRQn);

    /* Wait until NS signals completion */
    while (!enclave_done)
    {
        __NOP();
    }

    secure_destroy_enclave();
}

/* =========================================================
 * NS CALLBACK (called from NonSecure side)
 * ========================================================= */

__attribute__((cmse_nonsecure_entry))
void SECURE_enclave_done(void)
{
    enclave_done = 1;
}