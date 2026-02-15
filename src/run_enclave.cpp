#include <zephyr/sys/printk.h>
#include "run_enclave.h"

extern "C" void run_cifar_inference(void);

void run_enclave(void)
{
    printk("[ENCLAVE] ===== ENTER =====\n");

    run_cifar_inference();

    printk("[ENCLAVE] ===== EXIT =====\n");
}