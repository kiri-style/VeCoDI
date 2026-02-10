#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdint.h>

extern "C" {

/* =========================================================
 * Linker symbols
 * ========================================================= */
extern uint32_t __model_ro_start;
extern uint32_t __model_ro_end;

/* =========================================================
 * Internal state
 * ========================================================= */
static uintptr_t model_ro_start_addr;
static size_t    model_ro_size;

/* =========================================================
 * Init
 * ========================================================= */
void mpu_model_init(void)
{
    model_ro_start_addr = (uintptr_t)&__model_ro_start;
    uintptr_t end       = (uintptr_t)&__model_ro_end;

    if (end <= model_ro_start_addr) {
        printk("[MPU][ERROR] invalid model_ro range\n");
        return;
    }

    model_ro_size = end - model_ro_start_addr;

    printk("[MPU] model_ro start : 0x%08lx\n", (unsigned long)model_ro_start_addr);
    printk("[MPU] model_ro end   : 0x%08lx\n", (unsigned long)end);
    printk("[MPU] model_ro size  : %u bytes\n", (unsigned int)model_ro_size);
}

uintptr_t mpu_model_get_start(void)
{
    return model_ro_start_addr;
}

size_t mpu_model_get_size(void)
{
    return model_ro_size;
}

} // extern "C"