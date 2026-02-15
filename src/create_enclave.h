#ifndef CREATE_ENCLAVE_H
#define CREATE_ENCLAVE_H

#ifdef __cplusplus
extern "C" {
#endif

int create_enclave(void);
int enter_enclave(void);
int destroy_enclave(void);
uint8_t* get_enclave_model_ptr(void);
size_t get_enclave_model_size(void);
int decrypt_model_into_tensor_arena(uint8_t* output_buffer);
#ifdef __cplusplus
}
#endif

#endif /* CREATE_ENCLAVE_H */