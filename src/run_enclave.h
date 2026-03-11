#ifndef RUN_ENCLAVE_H
#define RUN_ENCLAVE_H

#include <stdint.h>
#include <stddef.h>

void run_enclave(void);
int set_max_inferences(uint32_t max_infs);

#endif