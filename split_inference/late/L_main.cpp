#include "File_Handling.h"
#include "CMSIS_NN/arm_nn_types.h"
#include "CMSIS_NN/arm_nnfunctions.h"
#include "L_nn_wt.h"
#include "L_nn_params.h"

int8_t buffer0[8192];
int8_t buffer1[8192];
int8_t buffer2[8192];
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

	buffer_tmp[0] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_7, &input_dims_conv2d_7, &filter_dims_conv2d_7, &output_dims_conv2d_7);
	buffer_tmp[1] = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_8, &input_dims_conv2d_8, &filter_dims_conv2d_8, &output_dims_conv2d_8);
	buffer_tmp[2] = arm_avgpool_s8_get_buffer_size(output_dims_average_pooling2d.w,input_dims_average_pooling2d.c);

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

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_7, &input_dims_conv2d_7, &filter_dims_conv2d_7, &output_dims_conv2d_7);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_7, &quant_params_conv2d_7, &input_dims_conv2d_7, input_data, &filter_dims_conv2d_7, wt_conv2d_7 ,&bias_dims_conv2d_7, bias_conv2d_7, &output_dims_conv2d_7, buffer1);

	ctx.size = arm_convolve_wrapper_s8_get_buffer_size(&conv_params_conv2d_8, &input_dims_conv2d_8, &filter_dims_conv2d_8, &output_dims_conv2d_8);
	arm_convolve_wrapper_s8(&ctx, &conv_params_conv2d_8, &quant_params_conv2d_8, &input_dims_conv2d_8, buffer0, &filter_dims_conv2d_8, wt_conv2d_8 ,&bias_dims_conv2d_8, bias_conv2d_8, &output_dims_conv2d_8, buffer2);

	arm_elementwise_add_s8(buffer2, buffer1, input_1_offset_add_2, input_1_mult_add_2, input_1_shift_add_2, input_2_offset_add_2, input_2_mult_add_2, input_2_shift_add_2, left_shift_add_2, buffer0, out_offset_add_2, out_mult_add_2, out_shift_add_2, out_activation_min_add_2, out_activation_max_add_2, block_size_add_2);

	ctx.size = arm_avgpool_s8_get_buffer_size(output_dims_average_pooling2d.w,input_dims_average_pooling2d.c);
	arm_avgpool_s8(&ctx, &pool_params_average_pooling2d, &input_dims_average_pooling2d, buffer0, &filter_dims_average_pooling2d, &output_dims_average_pooling2d, buffer1);

	ctx.size = 0;
	arm_fully_connected_s8(&ctx, &fc_params_fc, &quant_params_fc, &input_dims_fc, buffer1, &filter_dims_fc, wt_fc ,&bias_dims_fc, bias_fc, &output_dims_fc, buffer0);

	arm_softmax_s8(buffer0, num_rows_softmax_int8, row_size_softmax_int8, mult_softmax_int8, shift_softmax_int8, diff_min_softmax_int8, buffer1);


	for(uint16_t i=0; i<10; i++){
		if(buffer1[i] > buffer1[prediction]){
			prediction = i;
		}
	}

	return prediction;
}

