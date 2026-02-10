#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void SECURE_run_model(const int8_t *input);
int  SECURE_get_prediction(void);

#ifdef __cplusplus
}
#endif