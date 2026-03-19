#ifndef CREATE_ENCLAVE_H
#define CREATE_ENCLAVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int create_enclave(void);
int update_rate_limit(uint32_t new_limit);
int destroy_enclave(void);
int32_t get_last_create_secure_status(void);

/* Internal NS runtime helpers (not Secure IPC APIs) */
uint8_t* get_enclave_region(void);
size_t get_enclave_region_size(void);
uint32_t get_max_inferences_per_enclave(void);
bool is_enclave_created(void);

/* Internal boot/auth helpers used by UART/auth flow */
int ensure_model_ro_registered(void);
int ensure_inference_code_registered(void);
int initialize_secure_enclave_info_boot(void);
int validate_enclave_info_before_inference(void);

#ifdef __cplusplus
}
#endif

#endif /* CREATE_ENCLAVE_H */