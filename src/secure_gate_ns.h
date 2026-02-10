#pragma once
#include <stdint.h>
#include "arm_cmse.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t (*secure_infer_fn_t)(void)
    __attribute__((cmse_nonsecure_call));

#ifdef __cplusplus
}
#endif