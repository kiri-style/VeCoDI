#ifndef L_NN_PARAMS_H 
#define L_NN_PARAMS_H 

#include "arm_nn_types.h"

#define DATASET_SIZE 10000
#define INPUT_DATA_SIZE 4096
#define NUM_LAYERS_WITH_CTX 3
#define CTX_SIZE 2304
int32_t multiplier_conv2d_7[] = {1506655557,1197665636,1289146488,1337957027,1365408480,1809354009, 1281231667,1305766599,1366071326,1665008872,1501740606,1235049879, 1480513347,1352880822,1581429238,1387829974,1131592792,1379913792, 1366924863,2143322821,1156611874,1412239263,1256648628,1395654520, 1413053969,1591193225,1310067923,1321240952,1802660258,1608862883, 1357438751,1511741041,1112910934,1411459182,1535369755,1473785835, 1396355702,1164579129,1594329994,1424487932,1383527908,1639323853, 1166712602,1270964362,1536717953,1677840004,1302599533,1671268805, 1783069461,1426139728,1356681797,1263418062,1245028549,1337053900, 1323231838,1677602938,1132413063,1708047584,1541609902,1155207779, 1482975151,1553507980,1473736864,1307614281};
int32_t shift_conv2d_7[] = { -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,  -9,-10, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,  -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9,  -9, -9, -9, -9, -9, -9, -9, -9, -9, -9};

cmsis_nn_conv_params conv_params_conv2d_7 = {.input_offset = 128, .output_offset = 0, .stride = {.w = 1, .h = 1}, .padding = {.w = 1, .h = 1}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_7 = {.multiplier = multiplier_conv2d_7, .shift=shift_conv2d_7};
cmsis_nn_dims input_dims_conv2d_7 = {.n = 1, .h = 8, .w = 8, .c = 64};
cmsis_nn_dims filter_dims_conv2d_7 = {.n = 64, .h = 3, .w = 3, .c = 64};
cmsis_nn_dims bias_dims_conv2d_7 = {.n = 1, .h = 1, .w = 1, .c = 64};
cmsis_nn_dims output_dims_conv2d_7 = {.n = 1, .h = 8, .w = 8, .c = 64};
const uint32_t output_size_conv2d_7 = 4096;


int32_t multiplier_conv2d_8[] = {1599659999,1368717259,1482310070,1768622693,2011942734,1675277202, 2129656096,1240405581,1938266505,2096556308,1170628731,1085362866, 1869434973,1732361700,1373445885,1296067724,1617829610,1208434357, 1650618856,1310993479,1495140600,1456658533,1362082268,1860798633, 1723342710,1268306422,1096197405,1704436369,1216567298,1474501106, 2004055199,1766741242,1155133848,1349911767,1505683559,1485931815, 1683870514,1534472831,1484852740,2088316225,1786494177,1732538230, 1226379735,1993484179,1116306545,1705621225,2021373966,1848667078, 2089923527,1972524449,1092398620,1124185236,1123919592,1638690361, 1153206479,1475828989,1501310628,1862634846,1508611942,1317496329, 1499322546,1765223055,1591914810,1671813789};
int32_t shift_conv2d_8[] = {-8,-8,-8,-9,-9,-9,-9,-8,-9,-9,-8,-8,-9,-9,-8,-8,-9,-8,-8,-8,-9,-8,-9,-9, -9,-8,-8,-9,-8,-8,-9,-9,-8,-9,-9,-9,-9,-9,-8,-9,-9,-9,-8,-9,-8,-9,-9,-8, -9,-8,-8,-8,-8,-9,-8,-9,-9,-9,-8,-8,-9,-9,-9,-9};

cmsis_nn_conv_params conv_params_conv2d_8 = {.input_offset = 128, .output_offset = 29, .stride = {.w = 2, .h = 2}, .padding = {.w = 0, .h = 0}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_8 = {.multiplier = multiplier_conv2d_8, .shift=shift_conv2d_8};
cmsis_nn_dims input_dims_conv2d_8 = {.n = 1, .h = 16, .w = 16, .c = 32};
cmsis_nn_dims filter_dims_conv2d_8 = {.n = 64, .h = 1, .w = 1, .c = 32};
cmsis_nn_dims bias_dims_conv2d_8 = {.n = 1, .h = 1, .w = 1, .c = 64};
cmsis_nn_dims output_dims_conv2d_8 = {.n = 1, .h = 8, .w = 8, .c = 64};
const uint32_t output_size_conv2d_8 = 4096;


const int32_t input_1_offset_add_2 = -29;
const int32_t input_1_mult_add_2 = 1761710539;
const int32_t input_1_shift_add_2 = -2;
const int32_t input_2_offset_add_2 = 0;
const int32_t input_2_mult_add_2 = 1073741824;
const int32_t input_2_shift_add_2 = 0;
const int32_t left_shift_add_2 = 20;
const int32_t out_offset_add_2 = -128;
const int32_t out_mult_add_2 = 2029307740;
const int32_t out_shift_add_2 = -18;
const int32_t out_activation_min_add_2 = -128;
const int32_t out_activation_max_add_2 = 127;
const int32_t block_size_add_2 = 4096;

cmsis_nn_pool_params pool_params_average_pooling2d = {.stride = {.w = 8, .h = 8}, .padding = {.w = 0, .h = 0}, .activation = {.min = -128, .max = 127}};
cmsis_nn_dims input_dims_average_pooling2d = {.n = 1, .h = 8, .w = 8, .c = 64};
cmsis_nn_dims filter_dims_average_pooling2d = {.n = 1, .h = 8, .w = 8, .c = 1};
cmsis_nn_dims output_dims_average_pooling2d = {.n = 1, .h = 1, .w = 1, .c = 64};


cmsis_nn_fc_params fc_params_fc = {.input_offset = 128, .filter_offset = 0, .output_offset = 25, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_tensor_quant_params quant_params_fc = {.multiplier = 1486404351, .shift = -5};
cmsis_nn_dims input_dims_fc = {.n = 1, .h = 1, .w = 64, .c = 1};
cmsis_nn_dims filter_dims_fc = {.n = 64, .h = 1, .w = 1, .c = 10};
cmsis_nn_dims bias_dims_fc = {.n = 1, .h = 1, .w = 1, .c = 10};
cmsis_nn_dims output_dims_fc = {.n = 1, .h = 1, .w = 1, .c = 10};


const int32_t num_rows_softmax_int8 = 1;
const int32_t row_size_softmax_int8 = 10;
const int32_t mult_softmax_int8 = 1494629248;
const int32_t shift_softmax_int8 = 24;
const int32_t diff_min_softmax_int8 = -124;


#endif