#include <zephyr/sys/printk.h>
#include "run_enclave.h"
#include "split_inference.h"

void run_enclave(void)
{
    printk("[ENCLAVE] ===== ENTER =====\n");

    run_split_inference();

    printk("[ENCLAVE] ===== EXIT =====\n");
}