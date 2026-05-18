#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <psa/crypto.h>

#include "arm_nn_types.h"
#include "arm_nnfunctions.h"

#include "split_inference.h"
#include "benchmark.h"
#include "test_images.h"

#include "../split_inference/early/E_nn_wt.h"
#include "../split_inference/early/E_nn_params.h"

static constexpr int kEarlyCtxSize = 8192;
static constexpr int kEarlyInputSize = INPUT_DATA_SIZE;
static constexpr int kEarlyLayersWithCtx = NUM_LAYERS_WITH_CTX;

#undef CTX_SIZE
#undef INPUT_DATA_SIZE
#undef NUM_LAYERS_WITH_CTX
#undef DATASET_SIZE

#include "../split_inference/late/L_nn_wt_encrypted.h"
#include "../split_inference/late/L_nn_biases.h"
#include "../split_inference/late/L_nn_params.h"

static constexpr int kLateCtxSize = 4096;
static constexpr int kLateInputSize = INPUT_DATA_SIZE;
static constexpr int kLateLayersWithCtx = NUM_LAYERS_WITH_CTX;

#define INPUT_H 32
#define INPUT_W 32
#define INPUT_C 3
#define NUM_CLASSES 10

alignas(16) static int8_t early_buf0[16384];
alignas(16) static int8_t early_buf1[16384];
alignas(16) static int8_t early_buf2[16384];
alignas(16) static int8_t early_ctx_buf[kEarlyCtxSize];

static int8_t *const late_buf0 = early_buf0;
static int8_t *const late_buf1 = early_buf1;
static int8_t *const late_buf2 = early_buf2;
alignas(16) static int8_t late_ctx_buf[kLateCtxSize];

alignas(16) static int8_t early_output[output_size_conv2d_6];
alignas(16) static int8_t early_skip[output_size_conv2d_5];
alignas(16) static int8_t input_buffer[kEarlyInputSize];

static uint8_t *late_wt_ram = nullptr;
static size_t late_wt_ram_size = 0;
static const int8_t *wt_conv2d_7 = nullptr;
static const int8_t *wt_conv2d_8 = nullptr;
static const int8_t *wt_fc = nullptr;

void set_late_weights_buffer(uint8_t *buf, size_t size)
{
    late_wt_ram = buf;
    late_wt_ram_size = size;

    if (late_wt_ram && late_wt_ram_size >= (size_t)LATE_WT_TOTAL_SIZE) {
        wt_conv2d_7 = reinterpret_cast<const int8_t *>(late_wt_ram + LATE_WT_CONV2D_7_OFFSET);
        wt_conv2d_8 = reinterpret_cast<const int8_t *>(late_wt_ram + LATE_WT_CONV2D_8_OFFSET);
        wt_fc = reinterpret_cast<const int8_t *>(late_wt_ram + LATE_WT_FC_OFFSET);
    } else {
        wt_conv2d_7 = nullptr;
        wt_conv2d_8 = nullptr;
        wt_fc = nullptr;
    }
}

uint8_t *get_late_weights_buffer(void)
{
    return late_wt_ram;
}

size_t get_late_weights_size(void)
{
    return late_wt_ram_size;
}

// Input image is provided from host UART upload for case-study runs.
static const uint8_t *custom_test_image = nullptr;
static uint8_t custom_test_label = 255;
static bool custom_test_image_ready = false;
static uint8_t last_integrity_hash[32];  /* Store last computed hash */
static uint8_t late_weights_hash[32];     /* Pre-computed hash of code+late weights */
static bool late_hash_computed = false;  /* Flag to track if late hash is ready */
static uint8_t last_prediction = 255;     /* Store last inference prediction result */
static uint8_t last_expected_label = 255; /* Store last expected label for comparison */
static bool atomic_inference_window_open = false;

void set_atomic_inference_window_open(bool open)
{
    atomic_inference_window_open = open;
}

bool is_atomic_inference_window_open(void)
{
    return atomic_inference_window_open;
}

/* ============================================================
 *                 INTEGRITY HASH (CNT)
 * ============================================================ */

/* Helper function to hash a buffer in chunks to avoid PSA buffer size limits */
static psa_status_t hash_buffer_chunked(psa_hash_operation_t *operation, 
                                         const uint8_t *data, 
                                         size_t size,
                                         const char *label)
{
    const size_t chunk_size = 4096;
    size_t remaining = size;
    const uint8_t *ptr = data;
    
    while (remaining > 0) {
        size_t to_hash = (remaining > chunk_size) ? chunk_size : remaining;
        psa_status_t status = psa_hash_update(operation, ptr, to_hash);
        if (status != PSA_SUCCESS) {
            printk("[CNT] Hash %s chunk failed: %d\n", label, status);
            return status;
        }
        ptr += to_hash;
        remaining -= to_hash;
    }
    return PSA_SUCCESS;
}

/* Pre-compute hash of code pointers and late weights (called once after decryption) */
int precompute_late_weights_hash(void)
{
    psa_status_t status;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    size_t hash_len;

    printk("[CNT] Computing late weights hash...\n");

    /* Initialize hash operation (SHA-256) */
    status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        printk("[CNT] Late hash setup failed: %d\n", status);
        return -1;
    }

    if (!late_wt_ram || late_wt_ram_size < (size_t)LATE_WT_TOTAL_SIZE) {
        printk("[CNT] Late weights buffer too small for integrity hash (%zu < %u)\n",
               late_wt_ram_size, (unsigned)LATE_WT_TOTAL_SIZE);
        psa_hash_abort(&operation);
        return -1;
    }

    /* Hash code pointers (early weights addresses) */
    const void* early_weight_ptrs[] = {
        wt_conv2d, wt_conv2d_1, wt_conv2d_2, wt_conv2d_3,
        wt_conv2d_4, wt_conv2d_5, wt_conv2d_6
    };
    status = psa_hash_update(&operation,
                            (const uint8_t*)early_weight_ptrs,
                            sizeof(early_weight_ptrs));
    if (status != PSA_SUCCESS) {
        printk("[CNT] Hash code pointers failed: %d\n", status);
        psa_hash_abort(&operation);
        return -1;
    }

    /* Hash late weights (decrypted RAM) */
    if (late_wt_ram && wt_conv2d_7 && wt_conv2d_8 && wt_fc) {
        status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_7, 
                                    LATE_WT_CONV2D_7_SIZE, "wt_conv2d_7");
        if (status != PSA_SUCCESS) {
            psa_hash_abort(&operation);
            return -1;
        }
        status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_8, 
                                    LATE_WT_CONV2D_8_SIZE, "wt_conv2d_8");
        if (status != PSA_SUCCESS) {
            psa_hash_abort(&operation);
            return -1;
        }
        status = hash_buffer_chunked(&operation, (const uint8_t*)wt_fc, 
                                    LATE_WT_FC_SIZE, "wt_fc");
        if (status != PSA_SUCCESS) {
            psa_hash_abort(&operation);
            return -1;
        }
    } else {
        printk("[CNT] Late weights not available for hashing\n");
        psa_hash_abort(&operation);
        return -1;
    }

    /* Finalize hash */
    status = psa_hash_finish(&operation, late_weights_hash, 32, &hash_len);
    if (status != PSA_SUCCESS || hash_len != 32) {
        printk("[CNT] Late hash finish failed: status=%d, len=%zu\n", status, hash_len);
        return -1;
    }

    late_hash_computed = true;

    printk("[CNT] ✓ Late weights hash (code_ptrs + late_wt): ");
    for (int i = 0; i < 32; i++) {
        printk("%02x", late_weights_hash[i]);
    }
    printk("\n");

    return 0;
}

static int compute_integrity_hash(const int8_t *input_data, 
                                   uint8_t hash_output[32])
{
    psa_status_t status;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    size_t hash_len = 0;

    if (!late_hash_computed) {
        printk("[CNT] ERROR: Late weights hash not pre-computed!\n");
        return -1;
    }

    printk("[CNT] Computing inference hash...\n");

    /* Initialize hash operation (SHA-256) */
    status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        printk("[CNT] Hash setup failed: %d\n", status);
        return -1;
    }

    /* Hash 1: Input data (image) */
    status = psa_hash_update(&operation, 
                            (const uint8_t*)input_data, 
                            kEarlyInputSize);
    if (status != PSA_SUCCESS) {
        printk("[CNT] Hash input failed: %d\n", status);
        psa_hash_abort(&operation);
        return -1;
    }

    /* Hash 2: Early weights (plain ROM) - 7 layers, chunked for large buffers */
    status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d, sizeof(wt_conv2d), "wt_conv2d");
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return -1;
    }
    status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_1, sizeof(wt_conv2d_1), "wt_conv2d_1");
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return -1;
    }
    status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_2, sizeof(wt_conv2d_2), "wt_conv2d_2");
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return -1;
    }
    status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_3, sizeof(wt_conv2d_3), "wt_conv2d_3");
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return -1;
    }
    status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_4, sizeof(wt_conv2d_4), "wt_conv2d_4");
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return -1;
    }
    status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_5, sizeof(wt_conv2d_5), "wt_conv2d_5");
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return -1;
    }
    status = hash_buffer_chunked(&operation, (const uint8_t*)wt_conv2d_6, sizeof(wt_conv2d_6), "wt_conv2d_6");
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&operation);
        return -1;
    }

    /* Hash 3: Pre-computed late weights hash (code + late weights) */
    status = psa_hash_update(&operation, late_weights_hash, 32);
    if (status != PSA_SUCCESS) {
        printk("[CNT] Hash late_hash failed: %d\n", status);
        psa_hash_abort(&operation);
        return -1;
    }

    /* Finalize hash */
    status = psa_hash_finish(&operation, hash_output, 32, &hash_len);
    if (status != PSA_SUCCESS || hash_len != 32) {
        printk("[CNT] Hash finish failed: status=%d, len=%zu\n", status, hash_len);
        return -1;
    }

    printk("[CNT] ✓ Inference hash (input + early_wt + late_hash): ");
    for (int i = 0; i < 32; i++) {
        printk("%02x", hash_output[i]);
    }
    printk("\n");

    return 0;
}

static bool early_check_ctx_size(void)
{
    int32_t buffer_tmp[kEarlyLayersWithCtx];

    buffer_tmp[0] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d, &input_dims_conv2d,
                                                           &filter_dims_conv2d, &output_dims_conv2d);
    buffer_tmp[1] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_1, &input_dims_conv2d_1,
                                                           &filter_dims_conv2d_1, &output_dims_conv2d_1);
    buffer_tmp[2] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_2, &input_dims_conv2d_2,
                                                           &filter_dims_conv2d_2, &output_dims_conv2d_2);
    buffer_tmp[3] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_3, &input_dims_conv2d_3,
                                                           &filter_dims_conv2d_3, &output_dims_conv2d_3);
    buffer_tmp[4] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_4, &input_dims_conv2d_4,
                                                           &filter_dims_conv2d_4, &output_dims_conv2d_4);
    buffer_tmp[5] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_5, &input_dims_conv2d_5,
                                                           &filter_dims_conv2d_5, &output_dims_conv2d_5);
    buffer_tmp[6] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_6, &input_dims_conv2d_6,
                                                           &filter_dims_conv2d_6, &output_dims_conv2d_6);

    int32_t max_required = 0;
    for (int i = 0; i < kEarlyLayersWithCtx; i++) {
        if (buffer_tmp[i] > max_required) {
            max_required = buffer_tmp[i];
        }
    }

    if (max_required > kEarlyCtxSize) {
        printk("[SPLIT] Early ctx required = %d (buffer = %d)\n", max_required, kEarlyCtxSize);
        return false;
    }

    return true;
}

static bool late_check_ctx_size(void)
{
    int32_t buffer_tmp[kLateLayersWithCtx];

    buffer_tmp[0] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_7, &input_dims_conv2d_7,
                                                           &filter_dims_conv2d_7, &output_dims_conv2d_7);
    buffer_tmp[1] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_8, &input_dims_conv2d_8,
                                                           &filter_dims_conv2d_8, &output_dims_conv2d_8);
    buffer_tmp[2] = arm_avgpool_s8_get_buffer_size(output_dims_average_pooling2d.w, input_dims_average_pooling2d.c);

    int32_t max_required = 0;
    for (int i = 0; i < kLateLayersWithCtx; i++) {
        if (buffer_tmp[i] > max_required) {
            max_required = buffer_tmp[i];
        }
    }

    if (max_required > kLateCtxSize) {
        printk("[SPLIT] Late ctx required = %d (buffer = %d)\n", max_required, kLateCtxSize);
        return false;
    }

    return true;
}

static void run_early_layers(const int8_t *input_data, int8_t *output_data, int8_t *skip_data)
{
    BENCHMARK_START(early);
    
    printk("[EARLY] Starting early layers...\n");
    cmsis_nn_context ctx = {.buf = early_ctx_buf, .size = kEarlyCtxSize};

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d, &input_dims_conv2d,
                                                       &filter_dims_conv2d, &output_dims_conv2d);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d, &quant_params_conv2d, &input_dims_conv2d, input_data,
                            &filter_dims_conv2d, wt_conv2d, &bias_dims_conv2d, bias_conv2d,
                            &output_dims_conv2d, early_buf1);
    memcpy(early_buf2, early_buf1, output_size_conv2d);

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_1, &input_dims_conv2d_1,
                                                       &filter_dims_conv2d_1, &output_dims_conv2d_1);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_1, &quant_params_conv2d_1, &input_dims_conv2d_1, early_buf1,
                            &filter_dims_conv2d_1, wt_conv2d_1, &bias_dims_conv2d_1, bias_conv2d_1,
                            &output_dims_conv2d_1, early_buf0);

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_2, &input_dims_conv2d_2,
                                                       &filter_dims_conv2d_2, &output_dims_conv2d_2);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_2, &quant_params_conv2d_2, &input_dims_conv2d_2, early_buf0,
                            &filter_dims_conv2d_2, wt_conv2d_2, &bias_dims_conv2d_2, bias_conv2d_2,
                            &output_dims_conv2d_2, early_buf1);

    arm_elementwise_add_s8(early_buf2, early_buf1, input_1_offset_add, input_1_mult_add, input_1_shift_add,
                           input_2_offset_add, input_2_mult_add, input_2_shift_add, left_shift_add, early_buf0,
                           out_offset_add, out_mult_add, out_shift_add, out_activation_min_add,
                           out_activation_max_add, block_size_add);
    memcpy(early_buf1, early_buf0, block_size_add);

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_3, &input_dims_conv2d_3,
                                                       &filter_dims_conv2d_3, &output_dims_conv2d_3);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_3, &quant_params_conv2d_3, &input_dims_conv2d_3, early_buf0,
                            &filter_dims_conv2d_3, wt_conv2d_3, &bias_dims_conv2d_3, bias_conv2d_3,
                            &output_dims_conv2d_3, early_buf2);

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_4, &input_dims_conv2d_4,
                                                       &filter_dims_conv2d_4, &output_dims_conv2d_4);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_4, &quant_params_conv2d_4, &input_dims_conv2d_4, early_buf2,
                            &filter_dims_conv2d_4, wt_conv2d_4, &bias_dims_conv2d_4, bias_conv2d_4,
                            &output_dims_conv2d_4, early_buf0);

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_5, &input_dims_conv2d_5,
                                                       &filter_dims_conv2d_5, &output_dims_conv2d_5);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_5, &quant_params_conv2d_5, &input_dims_conv2d_5, early_buf1,
                            &filter_dims_conv2d_5, wt_conv2d_5, &bias_dims_conv2d_5, bias_conv2d_5,
                            &output_dims_conv2d_5, early_buf2);

    arm_elementwise_add_s8(early_buf2, early_buf0, input_1_offset_add_1, input_1_mult_add_1, input_1_shift_add_1,
                           input_2_offset_add_1, input_2_mult_add_1, input_2_shift_add_1, left_shift_add_1, early_buf1,
                           out_offset_add_1, out_mult_add_1, out_shift_add_1, out_activation_min_add_1,
                           out_activation_max_add_1, block_size_add_1);
    memcpy(early_buf0, early_buf1, block_size_add_1);

    memcpy(skip_data, early_buf0, output_size_conv2d_5);

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_6, &input_dims_conv2d_6,
                                                       &filter_dims_conv2d_6, &output_dims_conv2d_6);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_6, &quant_params_conv2d_6, &input_dims_conv2d_6, early_buf1,
                            &filter_dims_conv2d_6, wt_conv2d_6, &bias_dims_conv2d_6, bias_conv2d_6,
                            &output_dims_conv2d_6, early_buf2);

    memcpy(output_data, early_buf2, output_size_conv2d_6);
    
    BENCHMARK_END(early, g_benchmark_metrics.early_layers_cycles);
    BENCHMARK_ACCUMULATE(g_benchmark_metrics.early_layers_cycles,
                         g_benchmark_metrics.early_layers_sum_cycles,
                         g_benchmark_metrics.early_layers_min_cycles,
                         g_benchmark_metrics.early_layers_max_cycles,
                         g_benchmark_metrics.early_layers_count);
    printk("[EARLY] ✓ Early layers complete (%u cycles, %u ms)\n",
           g_benchmark_metrics.early_layers_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.early_layers_cycles));
}

static int8_t run_late_layers(const int8_t *main_data, const int8_t *skip_data)
{
    BENCHMARK_START(late);
    
    printk("[LATE] Starting late layers...\n");
    cmsis_nn_context ctx = {.buf = late_ctx_buf, .size = kLateCtxSize};
    int8_t prediction = 0;

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_7, &input_dims_conv2d_7,
                                                       &filter_dims_conv2d_7, &output_dims_conv2d_7);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_7, &quant_params_conv2d_7, &input_dims_conv2d_7, main_data,
                            &filter_dims_conv2d_7, wt_conv2d_7, &bias_dims_conv2d_7, bias_conv2d_7,
                            &output_dims_conv2d_7, late_buf1);

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_8, &input_dims_conv2d_8,
                                                       &filter_dims_conv2d_8, &output_dims_conv2d_8);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_8, &quant_params_conv2d_8, &input_dims_conv2d_8, skip_data,
                            &filter_dims_conv2d_8, wt_conv2d_8, &bias_dims_conv2d_8, bias_conv2d_8,
                            &output_dims_conv2d_8, late_buf2);

    arm_elementwise_add_s8(late_buf2, late_buf1, input_1_offset_add_2, input_1_mult_add_2, input_1_shift_add_2,
                           input_2_offset_add_2, input_2_mult_add_2, input_2_shift_add_2, left_shift_add_2, late_buf0,
                           out_offset_add_2, out_mult_add_2, out_shift_add_2, out_activation_min_add_2,
                           out_activation_max_add_2, block_size_add_2);

    ctx.size = arm_avgpool_s8_get_buffer_size(output_dims_average_pooling2d.w, input_dims_average_pooling2d.c);
    arm_avgpool_s8(&ctx, &pool_params_average_pooling2d, &input_dims_average_pooling2d, late_buf0,
                   &filter_dims_average_pooling2d, &output_dims_average_pooling2d, late_buf1);

    ctx.size = 0;
    arm_fully_connected_s8(&ctx, &fc_params_fc, &quant_params_fc, &input_dims_fc, late_buf1, &filter_dims_fc, wt_fc,
                           &bias_dims_fc, bias_fc, &output_dims_fc, late_buf0);

    arm_softmax_s8(late_buf0, num_rows_softmax_int8, row_size_softmax_int8, mult_softmax_int8, shift_softmax_int8,
                   diff_min_softmax_int8, late_buf1);

    for (uint16_t i = 0; i < NUM_CLASSES; i++) {
        if (late_buf1[i] > late_buf1[prediction]) {
            prediction = i;
        }
    }

    BENCHMARK_END(late, g_benchmark_metrics.late_layers_cycles);
    BENCHMARK_ACCUMULATE(g_benchmark_metrics.late_layers_cycles,
                         g_benchmark_metrics.late_layers_sum_cycles,
                         g_benchmark_metrics.late_layers_min_cycles,
                         g_benchmark_metrics.late_layers_max_cycles,
                         g_benchmark_metrics.late_layers_count);
    printk("[LATE] ✓ Late layers complete (pred=%d, %u cycles, %u ms)\n",
           prediction,
           g_benchmark_metrics.late_layers_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.late_layers_cycles));

    return prediction;
}

static void load_cifar_image(const uint8_t *img, int8_t *dst)
{
    int size = INPUT_H * INPUT_W * INPUT_C;
    for (int i = 0; i < size; i++) {
        dst[i] = (int8_t)((int)img[i] - 128);
    }
}

static int select_input_image(const uint8_t **img, int *label)
{
    if (custom_test_image_ready && custom_test_image != nullptr) {
        *img = custom_test_image;
        *label = (int)custom_test_label;
        custom_test_image = nullptr;
        custom_test_image_ready = false;
        printk("[SPLIT] Using custom image uploaded from UART (label=%d)\n", *label);
        return 0;
    }

    /* Device-image fallback for benchmark mode without host upload. */
    *img = img_0;
    *label = (int)label_0;
    printk("[SPLIT] No custom image available; using device test image img_0 (label=%d)\n", *label);
    return 0;
}

int set_custom_test_image(const uint8_t *image, uint8_t label)
{
    if (image == nullptr) {
        return -1;
    }

    custom_test_image = image;
    custom_test_label = label;
    custom_test_image_ready = true;
    return 0;
}

void clear_custom_test_image(void)
{
    custom_test_image = nullptr;
    custom_test_image_ready = false;
    custom_test_label = 255;
}

void run_split_inference(void)
{
    printk("\n[SPLIT] ===== CMSIS-NN SPLIT INFERENCE =====\n");

    if (!atomic_inference_window_open) {
        printk("[SPLIT] Refusing to run outside the atomic inference window\n");
        return;
    }
    
    if (!late_wt_ram || late_wt_ram_size < LATE_WT_TOTAL_SIZE) {
        printk("[SPLIT] Late weights not ready (buffer missing)\n");
        return;
    }

    /* Initialize PSA crypto for hash computation */
    psa_status_t crypto_status = psa_crypto_init();
    if (crypto_status != PSA_SUCCESS) {
        printk("[CNT] PSA crypto init failed: %d\n", crypto_status);
        return;
    }
    printk("[CNT] PSA crypto init OK\n");

    if (!early_check_ctx_size()) {
        printk("[SPLIT] Early ctx buffer too small\n");
        return;
    }
    if (!late_check_ctx_size()) {
        printk("[SPLIT] Late ctx buffer too small\n");
        return;
    }

    BENCHMARK_START(total_inf);

    const uint8_t *img = nullptr;
    int expected_label = 255;
    if (select_input_image(&img, &expected_label) != 0) {
        last_prediction = 255;
        last_expected_label = 255;
        return;
    }

    printk("[SPLIT] expected = %d\n", expected_label);
    load_cifar_image(img, input_buffer);

    /* Compute integrity hash (CNT) - store for final display */
    int hash_result = compute_integrity_hash(input_buffer, last_integrity_hash);
    if (hash_result != 0) {
        printk("[CNT] Hash computation failed with code %d\n", hash_result);
    }

    run_early_layers(input_buffer, early_output, early_skip);
    int pred = run_late_layers(early_output, early_skip);

    /* Store prediction and expected label for UART query */
    last_prediction = (uint8_t)(pred & 0xFF);
    last_expected_label = (uint8_t)expected_label;

    BENCHMARK_END(total_inf, g_benchmark_metrics.total_inference_cycles);
    BENCHMARK_ACCUMULATE(g_benchmark_metrics.total_inference_cycles,
                 g_benchmark_metrics.total_inference_sum_cycles,
                 g_benchmark_metrics.total_inference_min_cycles,
                 g_benchmark_metrics.total_inference_max_cycles,
                 g_benchmark_metrics.total_inference_count);
    printk("[SPLIT] Prediction = %d (total inference: %u cycles, %u ms)\n",
           pred,
           total_inf_start - total_inf_start + g_benchmark_metrics.total_inference_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.total_inference_cycles));

    printk("\n[CNT] ✓ All hash computations complete\n");

    printk("[SPLIT] ===== DONE =====\n\n");
}

/* Get last inference result */
uint8_t get_last_prediction(void)
{
    return last_prediction;
}

uint8_t get_last_expected_label(void)
{
    return last_expected_label;
}

/* Étape 5: Entry point for atomic Secure-to-NS function call
 * 
 * This function is called directly from Secure World during DP_CMD_RUN_INFERENCE.
 * It executes the inference function F and returns the output.
 * 
 * Marked as Non-Secure Callable (NSC) with cmse_nsfentry so it can be invoked
 * from Secure World and ensures control returns to Secure after completion.
 *
 * Parameter:
 *  - input: pointer to the input image (NULL to use pre-loaded custom image)
 *
 * Returns: prediction (class label 0-9, or 255 on error)
 * 
 * Note: The image should be pre-loaded via set_custom_test_image() in NS before
 * the Secure IPC call. This function will use the pre-loaded image if input is NULL.
 */
__attribute__((cmse_nsfentry))
uint8_t entry(const uint8_t *input)
{
    /* If an explicit input is provided, use it; otherwise rely on pre-loaded custom image */
    if (input != nullptr) {
        if (set_custom_test_image(input, 0U) != 0) {
            printk("[ENTRY] ✗ Failed to set custom test image\n");
            return 255;
        }
    } else {
        printk("[ENTRY] Using pre-loaded image from earlier set_custom_test_image() call\n");
    }

    /* Execute the split inference (will use either the provided input or pre-loaded image) */
    run_split_inference();

    /* Return the prediction result */
    uint8_t pred = get_last_prediction();
    printk("[ENTRY] ✓ Inference complete, prediction=%u\n", pred);
    return pred;
}
