#ifndef RUN_ENCLAVE_H
#define RUN_ENCLAVE_H

#include <stdint.h>
#include <stddef.h>

void run_enclave(void);
int set_max_inferences(uint32_t max_infs);
int execute_verified_inference(uint32_t tx_id, uint8_t *output_class, uint8_t pox_sig[64]);

#endif