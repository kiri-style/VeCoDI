#include "File_Handling.h"
#include "CMSIS_NN/arm_nn_types.h"
#include "CMSIS_NN/arm_nnfunctions.h"
#include "E_nn_wt.h"
#include "E_nn_params.h"

int8_t buffer0[16384];
int8_t buffer1[16384];
int8_t buffer2[16384];
int8_t buffer_ctx[CTX_SIZE];
FIL USBHDataFile;
FIL USBHLabelsFile;

int check_ctx_size();
int8_t run_ann(int8_t *input);

int main()
{
	FRESULT status_data_file;
	FRESULT status_labels_file;
	int8_t ann_out;
	int8_t correct_preds = 0;
	char y_test[DATASET_SIZE];
	float acc = 0;

	if(!check_ctx_size()){
		return 0;
	}

	while(get_usb_status() == 0){
		MX_USB_HOST_Process();
	}

	status_data_file = Open_File("data.bin", &USBHDataFile);
	status_labels_file = Open_File("labels.bin", &USBHLabelsFile);
	if(status_data_file != FR_OK){
		return 0;
	}
	if(status_labels_file != FR_OK){
		return 0;
	}

	status_labels_file = Read_File_Batch("labels.bin", &USBHLabelsFile, DATASET_SIZE, y_test);
	if(status_labels_file != FR_OK){
		return 0;
	}

	for(uint16_t i=0; i<DATASET_SIZE; i++) {
		status_data_file = Read_File_Batch("data.bin", &USBHDataFile, INPUT_DATA_SIZE, (char*)buffer0);
		if(status_data_file != FR_OK){
			break;
		}

		ann_out = run_ann(buffer0);
		if(y_test[i]==ann_out) {
			correct_preds = correct_preds + 1;
		}
	}

	acc = (float)correct_preds / DATASET_SIZE;

	return 1;
}

int check_ctx_size()
{
	int32_t buffer_tmp[NUM_LAYERS_WITH_CTX];

	buffer_tmp[0] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d, &input_dims_conv2d, &filter_dims_conv2d, &output_dims_conv2d);
	buffer_tmp[1] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_1, &input_dims_conv2d_1, &filter_dims_conv2d_1, &output_dims_conv2d_1);
	buffer_tmp[2] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_2, &input_dims_conv2d_2, &filter_dims_conv2d_2, &output_dims_conv2d_2);
	buffer_tmp[3] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_3, &input_dims_conv2d_3, &filter_dims_conv2d_3, &output_dims_conv2d_3);
	buffer_tmp[4] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_4, &input_dims_conv2d_4, &filter_dims_conv2d_4, &output_dims_conv2d_4);
	buffer_tmp[5] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_5, &input_dims_conv2d_5, &filter_dims_conv2d_5, &output_dims_conv2d_5);
	buffer_tmp[6] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_6, &input_dims_conv2d_6, &filter_dims_conv2d_6, &output_dims_conv2d_6);

	for(int i=0; i<NUM_LAYERS_WITH_CTX; i++) {
		if(buffer_tmp[i] > CTX_SIZE) {
			return 0;
		}
	}

	return 1;
}

int8_t run_ann(int8_t *input_data)
{
	cmsis_nn_context ctx = {.buf=buffer_ctx, .size=CTX_SIZE};
	int8_t prediction = 0;

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d, &input_dims_conv2d, &filter_dims_conv2d, &output_dims_conv2d);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d, &quant_params_conv2d, &input_dims_conv2d, input_data, &filter_dims_conv2d, wt_conv2d ,&bias_dims_conv2d, bias_conv2d, &output_dims_conv2d, buffer1);
	memcpy(buffer2, buffer1, output_size_conv2d);

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_1, &input_dims_conv2d_1, &filter_dims_conv2d_1, &output_dims_conv2d_1);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_1, &quant_params_conv2d_1, &input_dims_conv2d_1, buffer1, &filter_dims_conv2d_1, wt_conv2d_1 ,&bias_dims_conv2d_1, bias_conv2d_1, &output_dims_conv2d_1, buffer0);

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_2, &input_dims_conv2d_2, &filter_dims_conv2d_2, &output_dims_conv2d_2);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_2, &quant_params_conv2d_2, &input_dims_conv2d_2, buffer0, &filter_dims_conv2d_2, wt_conv2d_2 ,&bias_dims_conv2d_2, bias_conv2d_2, &output_dims_conv2d_2, buffer1);

	arm_elementwise_add_s8(buffer2, buffer1, input_1_offset_add, input_1_mult_add, input_1_shift_add, input_2_offset_add, input_2_mult_add, input_2_shift_add, left_shift_add, buffer0, out_offset_add, out_mult_add, out_shift_add, out_activation_min_add, out_activation_max_add, block_size_add);
	memcpy(buffer1, buffer0, block_size_add);

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_3, &input_dims_conv2d_3, &filter_dims_conv2d_3, &output_dims_conv2d_3);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_3, &quant_params_conv2d_3, &input_dims_conv2d_3, buffer0, &filter_dims_conv2d_3, wt_conv2d_3 ,&bias_dims_conv2d_3, bias_conv2d_3, &output_dims_conv2d_3, buffer2);

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_4, &input_dims_conv2d_4, &filter_dims_conv2d_4, &output_dims_conv2d_4);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_4, &quant_params_conv2d_4, &input_dims_conv2d_4, buffer2, &filter_dims_conv2d_4, wt_conv2d_4 ,&bias_dims_conv2d_4, bias_conv2d_4, &output_dims_conv2d_4, buffer0);

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_5, &input_dims_conv2d_5, &filter_dims_conv2d_5, &output_dims_conv2d_5);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_5, &quant_params_conv2d_5, &input_dims_conv2d_5, buffer1, &filter_dims_conv2d_5, wt_conv2d_5 ,&bias_dims_conv2d_5, bias_conv2d_5, &output_dims_conv2d_5, buffer2);

	arm_elementwise_add_s8(buffer2, buffer0, input_1_offset_add_1, input_1_mult_add_1, input_1_shift_add_1, input_2_offset_add_1, input_2_mult_add_1, input_2_shift_add_1, left_shift_add_1, buffer1, out_offset_add_1, out_mult_add_1, out_shift_add_1, out_activation_min_add_1, out_activation_max_add_1, block_size_add_1);
	memcpy(buffer0, buffer1, block_size_add_1);

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_6, &input_dims_conv2d_6, &filter_dims_conv2d_6, &output_dims_conv2d_6);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_6, &quant_params_conv2d_6, &input_dims_conv2d_6, buffer1, &filter_dims_conv2d_6, wt_conv2d_6 ,&bias_dims_conv2d_6, bias_conv2d_6, &output_dims_conv2d_6, buffer2);

}

