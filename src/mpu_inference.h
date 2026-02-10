#ifndef MPU_INFERENCE_H
#define MPU_INFERENCE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Initialise la protection MPU pour le tensor arena */
void mpu_inference_init(void);

/** Retourne l'adresse de début du tensor arena */
uintptr_t mpu_inference_get_start(void);

/** Retourne la taille du tensor arena */
size_t mpu_inference_get_size(void);

#ifdef __cplusplus
}
#endif

#endif // MPU_INFERENCE_H