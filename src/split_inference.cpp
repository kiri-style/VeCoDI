#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "arm_nn_types.h"
#include "arm_nnfunctions.h"

#include "split_inference.h"
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

    if (late_wt_ram) {
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

static const uint8_t *const test_images[NUM_TEST_IMAGES] = {img_0, img_1};
static const uint8_t test_labels[NUM_TEST_IMAGES] = {label_0, label_1};

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
    printk("[SPLIT][EARLY] Start\n");
    cmsis_nn_context ctx = {.buf = early_ctx_buf, .size = kEarlyCtxSize};

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d, &input_dims_conv2d,
                                                       &filter_dims_conv2d, &output_dims_conv2d);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d, &quant_params_conv2d, &input_dims_conv2d, input_data,
                            &filter_dims_conv2d, wt_conv2d, &bias_dims_conv2d, bias_conv2d,
                            &output_dims_conv2d, early_buf1);
    memcpy(early_buf2, early_buf1, output_size_conv2d);
    printk("[SPLIT][EARLY] conv2d_0 done\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_1, &input_dims_conv2d_1,
                                                       &filter_dims_conv2d_1, &output_dims_conv2d_1);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_1, &quant_params_conv2d_1, &input_dims_conv2d_1, early_buf1,
                            &filter_dims_conv2d_1, wt_conv2d_1, &bias_dims_conv2d_1, bias_conv2d_1,
                            &output_dims_conv2d_1, early_buf0);
    printk("[SPLIT][EARLY] conv2d_1 done\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_2, &input_dims_conv2d_2,
                                                       &filter_dims_conv2d_2, &output_dims_conv2d_2);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_2, &quant_params_conv2d_2, &input_dims_conv2d_2, early_buf0,
                            &filter_dims_conv2d_2, wt_conv2d_2, &bias_dims_conv2d_2, bias_conv2d_2,
                            &output_dims_conv2d_2, early_buf1);
    printk("[SPLIT][EARLY] conv2d_2 done\n");

    arm_elementwise_add_s8(early_buf2, early_buf1, input_1_offset_add, input_1_mult_add, input_1_shift_add,
                           input_2_offset_add, input_2_mult_add, input_2_shift_add, left_shift_add, early_buf0,
                           out_offset_add, out_mult_add, out_shift_add, out_activation_min_add,
                           out_activation_max_add, block_size_add);
    memcpy(early_buf1, early_buf0, block_size_add);
    printk("[SPLIT][EARLY] add_0 done\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_3, &input_dims_conv2d_3,
                                                       &filter_dims_conv2d_3, &output_dims_conv2d_3);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_3, &quant_params_conv2d_3, &input_dims_conv2d_3, early_buf0,
                            &filter_dims_conv2d_3, wt_conv2d_3, &bias_dims_conv2d_3, bias_conv2d_3,
                            &output_dims_conv2d_3, early_buf2);
    printk("[SPLIT][EARLY] conv2d_3 done\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_4, &input_dims_conv2d_4,
                                                       &filter_dims_conv2d_4, &output_dims_conv2d_4);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_4, &quant_params_conv2d_4, &input_dims_conv2d_4, early_buf2,
                            &filter_dims_conv2d_4, wt_conv2d_4, &bias_dims_conv2d_4, bias_conv2d_4,
                            &output_dims_conv2d_4, early_buf0);
    printk("[SPLIT][EARLY] conv2d_4 done\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_5, &input_dims_conv2d_5,
                                                       &filter_dims_conv2d_5, &output_dims_conv2d_5);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_5, &quant_params_conv2d_5, &input_dims_conv2d_5, early_buf1,
                            &filter_dims_conv2d_5, wt_conv2d_5, &bias_dims_conv2d_5, bias_conv2d_5,
                            &output_dims_conv2d_5, early_buf2);
    printk("[SPLIT][EARLY] conv2d_5 done\n");

    arm_elementwise_add_s8(early_buf2, early_buf0, input_1_offset_add_1, input_1_mult_add_1, input_1_shift_add_1,
                           input_2_offset_add_1, input_2_mult_add_1, input_2_shift_add_1, left_shift_add_1, early_buf1,
                           out_offset_add_1, out_mult_add_1, out_shift_add_1, out_activation_min_add_1,
                           out_activation_max_add_1, block_size_add_1);
    memcpy(early_buf0, early_buf1, block_size_add_1);
    printk("[SPLIT][EARLY] add_1 done\n");

    memcpy(skip_data, early_buf0, output_size_conv2d_5);
    printk("[SPLIT][EARLY] skip saved\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_6, &input_dims_conv2d_6,
                                                       &filter_dims_conv2d_6, &output_dims_conv2d_6);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_6, &quant_params_conv2d_6, &input_dims_conv2d_6, early_buf1,
                            &filter_dims_conv2d_6, wt_conv2d_6, &bias_dims_conv2d_6, bias_conv2d_6,
                            &output_dims_conv2d_6, early_buf2);

    memcpy(output_data, early_buf2, output_size_conv2d_6);
    printk("[SPLIT][EARLY] conv2d_6 done\n");
    printk("[SPLIT][EARLY] Done\n");
}

static int8_t run_late_layers(const int8_t *main_data, const int8_t *skip_data)
{
    printk("[SPLIT][LATE] Start\n");
    cmsis_nn_context ctx = {.buf = late_ctx_buf, .size = kLateCtxSize};
    int8_t prediction = 0;
    printk("[SPLIT][LATE] inputs ready\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_7, &input_dims_conv2d_7,
                                                       &filter_dims_conv2d_7, &output_dims_conv2d_7);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_7, &quant_params_conv2d_7, &input_dims_conv2d_7, main_data,
                            &filter_dims_conv2d_7, wt_conv2d_7, &bias_dims_conv2d_7, bias_conv2d_7,
                            &output_dims_conv2d_7, late_buf1);
    printk("[SPLIT][LATE] conv2d_7 done\n");

    ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_8, &input_dims_conv2d_8,
                                                       &filter_dims_conv2d_8, &output_dims_conv2d_8);
    arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_8, &quant_params_conv2d_8, &input_dims_conv2d_8, skip_data,
                            &filter_dims_conv2d_8, wt_conv2d_8, &bias_dims_conv2d_8, bias_conv2d_8,
                            &output_dims_conv2d_8, late_buf2);
    printk("[SPLIT][LATE] conv2d_8 done\n");

    arm_elementwise_add_s8(late_buf2, late_buf1, input_1_offset_add_2, input_1_mult_add_2, input_1_shift_add_2,
                           input_2_offset_add_2, input_2_mult_add_2, input_2_shift_add_2, left_shift_add_2, late_buf0,
                           out_offset_add_2, out_mult_add_2, out_shift_add_2, out_activation_min_add_2,
                           out_activation_max_add_2, block_size_add_2);
    printk("[SPLIT][LATE] add_2 done\n");

    ctx.size = arm_avgpool_s8_get_buffer_size(output_dims_average_pooling2d.w, input_dims_average_pooling2d.c);
    arm_avgpool_s8(&ctx, &pool_params_average_pooling2d, &input_dims_average_pooling2d, late_buf0,
                   &filter_dims_average_pooling2d, &output_dims_average_pooling2d, late_buf1);
    printk("[SPLIT][LATE] avgpool done\n");

    ctx.size = 0;
    arm_fully_connected_s8(&ctx, &fc_params_fc, &quant_params_fc, &input_dims_fc, late_buf1, &filter_dims_fc, wt_fc,
                           &bias_dims_fc, bias_fc, &output_dims_fc, late_buf0);
    printk("[SPLIT][LATE] fc done\n");

    arm_softmax_s8(late_buf0, num_rows_softmax_int8, row_size_softmax_int8, mult_softmax_int8, shift_softmax_int8,
                   diff_min_softmax_int8, late_buf1);
    printk("[SPLIT][LATE] softmax done\n");

    for (uint16_t i = 0; i < NUM_CLASSES; i++) {
        if (late_buf1[i] > late_buf1[prediction]) {
            prediction = i;
        }
    }

    printk("[SPLIT][LATE] Done\n");

    return prediction;
}

static void load_cifar_image(const uint8_t *img, int8_t *dst)
{
    int size = INPUT_H * INPUT_W * INPUT_C;
    for (int i = 0; i < size; i++) {
        dst[i] = (int8_t)((int)img[i] - 128);
    }
}

void run_split_inference(void)
{
    printk("\n[SPLIT] ===== CMSIS-NN SPLIT INFERENCE =====\n");

    if (!late_wt_ram || late_wt_ram_size < LATE_WT_TOTAL_SIZE) {
        printk("[SPLIT] Late weights not ready (buffer missing)\n");
        return;
    }

    if (!early_check_ctx_size()) {
        printk("[SPLIT] Early ctx buffer too small\n");
        return;
    }
    if (!late_check_ctx_size()) {
        printk("[SPLIT] Late ctx buffer too small\n");
        return;
    }

    for (int test_id = 0; test_id < NUM_TEST_IMAGES; test_id++) {
        const uint8_t *img = test_images[test_id];
        int expected_label = test_labels[test_id];

        printk("[SPLIT] Test %d | expected = %d\n", test_id, expected_label);
        load_cifar_image(img, input_buffer);

        run_early_layers(input_buffer, early_output, early_skip);
        int pred = run_late_layers(early_output, early_skip);

        printk("[SPLIT] Prediction = %d\n", pred);
        printk("[SPLIT] Loop continue\n");
    }

    printk("[SPLIT] ===== DONE =====\n\n");
}
