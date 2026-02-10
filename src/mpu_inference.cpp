#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdint.h>
#include "mpu_inference.h"

extern "C" {

/* ================= TENSOR ARENA ================= */
#define TENSOR_ARENA_SIZE (70 * 1024)
alignas(32) uint8_t tensor_arena[TENSOR_ARENA_SIZE];
uint8_t* tensor_arena_end = tensor_arena + TENSOR_ARENA_SIZE;

/* =========================================================
 * Internal state
 * ========================================================= */
static uintptr_t tensor_arena_start_addr;
static size_t    tensor_arena_size;

/* =========================================================
 * Init
 * ========================================================= */
void mpu_inference_init(void)
{
    tensor_arena_start_addr = (uintptr_t)tensor_arena;
    uintptr_t end           = (uintptr_t)tensor_arena_end;

    if (end <= tensor_arena_start_addr) {
        printk("[MPU][ERROR] invalid tensor_arena range\n");
        return;
    }

    tensor_arena_size = end - tensor_arena_start_addr;

    printk("[MPU] Tensor arena start : 0x%08lx\n", (unsigned long)tensor_arena_start_addr);
    printk("[MPU] Tensor arena end   : 0x%08lx\n", (unsigned long)end);
    printk("[MPU] Tensor arena size  : %u bytes\n", (unsigned int)tensor_arena_size);
}

uintptr_t mpu_inference_get_start(void)
{
    return tensor_arena_start_addr;
}

size_t mpu_inference_get_size(void)
{
    return tensor_arena_size;
}

} // extern "C"