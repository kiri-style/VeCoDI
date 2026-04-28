#ifndef CREATE_ENCLAVE_H
#define CREATE_ENCLAVE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int create_enclave(void);
int create_enclave_with_size(size_t decrypt_size_bytes);
int enter_enclave(void);
int destroy_enclave(void);
int update_rate_limit(uint32_t new_limit);
int32_t get_last_create_secure_status(void);

/* Get enclave memory region (for late weights) */
uint8_t* get_enclave_region(void);
size_t get_enclave_region_size(void);
uint32_t get_max_inferences_per_enclave(void);
bool is_enclave_created(void);
size_t get_model_ro_size(void);
size_t get_inference_code_size(void);

/* SAU enclave RAM isolation: open/close the window from NS side */
int enclave_sau_register_window(const uint8_t *base, uint32_t size);
int enclave_sau_open(void);
int enclave_sau_close(void);
int enclave_sau_model_ro_open(void);
int enclave_sau_model_ro_close(void);

/* Boot-time secure EnclaveInfo bootstrap helpers */
int ensure_model_ro_registered(void);
int ensure_inference_code_registered(void);
int initialize_secure_enclave_info_boot(void);
int validate_enclave_info_before_inference(void);

#ifdef __cplusplus
}
#endif

#endif /* CREATE_ENCLAVE_H */