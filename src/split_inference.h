#ifndef SPLIT_INFERENCE_H
#define SPLIT_INFERENCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void run_split_inference(void);
void set_atomic_inference_window_open(bool open);
bool is_atomic_inference_window_open(void);
int set_custom_test_image(const uint8_t *image, uint8_t label);
void clear_custom_test_image(void);
void set_late_weights_buffer(uint8_t *buf, size_t size);
uint8_t *get_late_weights_buffer(void);
size_t get_late_weights_size(void);
int precompute_late_weights_hash(void);  /* Pre-compute hash of code+late weights */

/* Get last inference result */
uint8_t get_last_prediction(void);
uint8_t get_last_expected_label(void);

/* Entry point (Étape 5 - Étape 5): Callable from Secure for atomic F execution
 * Takes an input image and executes inference, returning the prediction.
 * Marked as Non-Secure Callable (NSC) so Secure World can call it.
 */
uint8_t entry(const uint8_t *input);

#ifdef __cplusplus
}
#endif

#endif
