#ifndef SPLIT_INFERENCE_H
#define SPLIT_INFERENCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void run_split_inference(void);
void set_late_weights_buffer(uint8_t *buf, size_t size);
uint8_t *get_late_weights_buffer(void);
size_t get_late_weights_size(void);
int precompute_late_weights_hash(void);  /* Pre-compute hash of code+late weights */

#ifdef __cplusplus
}
#endif

#endif
