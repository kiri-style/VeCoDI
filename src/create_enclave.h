#ifndef CREATE_ENCLAVE_H
#define CREATE_ENCLAVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int create_enclave(void);
int enter_enclave(void);
int destroy_enclave(void);

/* Get enclave memory region (for late weights) */
uint8_t* get_enclave_region(void);
size_t get_enclave_region_size(void);

#ifdef __cplusplus
}
#endif

#endif /* CREATE_ENCLAVE_H */