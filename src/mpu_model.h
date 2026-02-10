#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void      mpu_model_init(void);
uintptr_t mpu_model_get_start(void);
size_t    mpu_model_get_size(void);

#ifdef __cplusplus
}
#endif