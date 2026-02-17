#ifndef E_NN_PARAMS_H 
#define E_NN_PARAMS_H 

#include "arm_nn_types.h"

#define DATASET_SIZE 10000
#define INPUT_DATA_SIZE 3072
#define NUM_LAYERS_WITH_CTX 7
#define CTX_SIZE 1152
int32_t multiplier_conv2d[] = {1841044266,1125342834,1246028441,1848786421,1238476058,1441568495, 1762678701,1664371887,1840488682,2055041160,1128430398,1198452527, 1725147980,2009164752,1402968253,1694898492};
int32_t shift_conv2d[] = { -8, -7, -8, -8, -9,-10, -8,-10,-10,-10, -9, -9, -9, -9, -8, -8};

cmsis_nn_conv_params conv_params_conv2d = {.input_offset = 128, .output_offset = -128, .stride = {.w = 1, .h = 1}, .padding = {.w = 1, .h = 1}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d = {.multiplier = multiplier_conv2d, .shift=shift_conv2d};
cmsis_nn_dims input_dims_conv2d = {.n = 1, .h = 32, .w = 32, .c = 3};
cmsis_nn_dims filter_dims_conv2d = {.n = 16, .h = 3, .w = 3, .c = 3};
cmsis_nn_dims bias_dims_conv2d = {.n = 1, .h = 1, .w = 1, .c = 16};
cmsis_nn_dims output_dims_conv2d = {.n = 1, .h = 32, .w = 32, .c = 16};
const uint32_t output_size_conv2d = 16384;


int32_t multiplier_conv2d_1[] = {1694778333,1618364263,1994161930,1220633700,2014719590,1079860431, 1519230200,1413753991,1403163689,1750809887,1774401379,2108080481, 1718176221,1227566522,1529362559,1262916420};
int32_t shift_conv2d_1[] = {-8,-8,-8,-8,-8,-8,-8,-8,-8,-8,-9,-9,-9,-7,-8,-8};

cmsis_nn_conv_params conv_params_conv2d_1 = {.input_offset = 128, .output_offset = -128, .stride = {.w = 1, .h = 1}, .padding = {.w = 1, .h = 1}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_1 = {.multiplier = multiplier_conv2d_1, .shift=shift_conv2d_1};
cmsis_nn_dims input_dims_conv2d_1 = {.n = 1, .h = 32, .w = 32, .c = 16};
cmsis_nn_dims filter_dims_conv2d_1 = {.n = 16, .h = 3, .w = 3, .c = 16};
cmsis_nn_dims bias_dims_conv2d_1 = {.n = 1, .h = 1, .w = 1, .c = 16};
cmsis_nn_dims output_dims_conv2d_1 = {.n = 1, .h = 32, .w = 32, .c = 16};
const uint32_t output_size_conv2d_1 = 16384;


int32_t multiplier_conv2d_2[] = {1588365829,1420245086,1149767771,1121454441,2053346872,1968321955, 1346927641,1789841386,1337735859,1948828033,1447994319,1291016742, 1279230128,1118488350,1511831003,1852570079};
int32_t shift_conv2d_2[] = {-10, -9, -9, -9,-10, -9, -9, -9, -8,-10,-10, -9, -9, -9, -9, -9};

cmsis_nn_conv_params conv_params_conv2d_2 = {.input_offset = 128, .output_offset = 10, .stride = {.w = 1, .h = 1}, .padding = {.w = 1, .h = 1}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_2 = {.multiplier = multiplier_conv2d_2, .shift=shift_conv2d_2};
cmsis_nn_dims input_dims_conv2d_2 = {.n = 1, .h = 32, .w = 32, .c = 16};
cmsis_nn_dims filter_dims_conv2d_2 = {.n = 16, .h = 3, .w = 3, .c = 16};
cmsis_nn_dims bias_dims_conv2d_2 = {.n = 1, .h = 1, .w = 1, .c = 16};
cmsis_nn_dims output_dims_conv2d_2 = {.n = 1, .h = 32, .w = 32, .c = 16};
const uint32_t output_size_conv2d_2 = 16384;


const int32_t input_1_offset_add = 128;
const int32_t input_1_mult_add = 1286669568;
const int32_t input_1_shift_add = -2;
const int32_t input_2_offset_add = -10;
const int32_t input_2_mult_add = 1073741824;
const int32_t input_2_shift_add = 0;
const int32_t left_shift_add = 20;
const int32_t out_offset_add = -128;
const int32_t out_mult_add = 1109345390;
const int32_t out_shift_add = -17;
const int32_t out_activation_min_add = -128;
const int32_t out_activation_max_add = 127;
const int32_t block_size_add = 16384;

int32_t multiplier_conv2d_3[] = {1244984513,1873770797,1240728138,1662140278,1530305454,1206532334, 1211246388,1657912718,1543814957,1510272448,1508582896,1304490684, 1622838914,1707709717,1277805915,1372017655,1186756937,1364379541, 1369438197,1093735255,1515879319,1307150861,1762632909,1360854635, 2036162986,1522028951,1383667352,1804118410,1130803488,1161610918, 1776509647,1119746730};
int32_t shift_conv2d_3[] = {-8,-8,-7,-8,-8,-8,-8,-8,-8,-8,-8,-7,-8,-8,-8,-8,-8,-8,-8,-7,-8,-7,-8,-8, -8,-8,-8,-8,-7,-7,-8,-7};

cmsis_nn_conv_params conv_params_conv2d_3 = {.input_offset = 128, .output_offset = -128, .stride = {.w = 2, .h = 2}, .padding = {.w = 0, .h = 0}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_3 = {.multiplier = multiplier_conv2d_3, .shift=shift_conv2d_3};
cmsis_nn_dims input_dims_conv2d_3 = {.n = 1, .h = 32, .w = 32, .c = 16};
cmsis_nn_dims filter_dims_conv2d_3 = {.n = 32, .h = 3, .w = 3, .c = 16};
cmsis_nn_dims bias_dims_conv2d_3 = {.n = 1, .h = 1, .w = 1, .c = 32};
cmsis_nn_dims output_dims_conv2d_3 = {.n = 1, .h = 16, .w = 16, .c = 32};
const uint32_t output_size_conv2d_3 = 8192;


int32_t multiplier_conv2d_4[] = {1738091790,1548473929,1127478685,1852143154,1923601968,1881598561, 1367975966,1457243775,1843419938,1624299656,1126251180,1373755585, 1939279337,1372228610,1743650052,1131778262,1099694725,1606683613, 1434755255,1165577320,1389359005,2013235278,1188824512,1924331664, 2081287863,1523319650,2094260132,1095007201,1318012666,1177585394, 2033381099,1091252286};
int32_t shift_conv2d_4[] = { -9, -9, -9, -9,-10,-10, -9, -9, -9, -9, -9, -9,-10, -9,-10, -9, -9, -9,  -9, -9, -9,-10, -9,-10, -9, -9,-10, -9, -9, -9,-10, -9};

cmsis_nn_conv_params conv_params_conv2d_4 = {.input_offset = 128, .output_offset = 19, .stride = {.w = 1, .h = 1}, .padding = {.w = 1, .h = 1}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_4 = {.multiplier = multiplier_conv2d_4, .shift=shift_conv2d_4};
cmsis_nn_dims input_dims_conv2d_4 = {.n = 1, .h = 16, .w = 16, .c = 32};
cmsis_nn_dims filter_dims_conv2d_4 = {.n = 32, .h = 3, .w = 3, .c = 32};
cmsis_nn_dims bias_dims_conv2d_4 = {.n = 1, .h = 1, .w = 1, .c = 32};
cmsis_nn_dims output_dims_conv2d_4 = {.n = 1, .h = 16, .w = 16, .c = 32};
const uint32_t output_size_conv2d_4 = 8192;


int32_t multiplier_conv2d_5[] = {1133865199,1333264245,1527247286,1522131546,1092768803,1539749553, 1279461255,2104541480,1392103312,1333234381,1103023312,1357284658, 1704840152,1245518008,1613395443,1460716951,2009851954,2029015554, 1785448455,1657962142,1621931604,1362833789,1313157860,1157189387, 2052891938,1665152724,1253577976,1636415460,1521792221,1528740149, 1695672213,1145505323};
int32_t shift_conv2d_5[] = {-8,-8,-8,-8,-8,-9,-8,-9,-8,-8,-8,-8,-8,-8,-8,-7,-9,-9,-9,-8,-9,-8,-8,-8, -8,-8,-8,-8,-8,-8,-8,-7};

cmsis_nn_conv_params conv_params_conv2d_5 = {.input_offset = 128, .output_offset = -17, .stride = {.w = 2, .h = 2}, .padding = {.w = 0, .h = 0}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_5 = {.multiplier = multiplier_conv2d_5, .shift=shift_conv2d_5};
cmsis_nn_dims input_dims_conv2d_5 = {.n = 1, .h = 32, .w = 32, .c = 16};
cmsis_nn_dims filter_dims_conv2d_5 = {.n = 32, .h = 1, .w = 1, .c = 16};
cmsis_nn_dims bias_dims_conv2d_5 = {.n = 1, .h = 1, .w = 1, .c = 32};
cmsis_nn_dims output_dims_conv2d_5 = {.n = 1, .h = 16, .w = 16, .c = 32};
const uint32_t output_size_conv2d_5 = 8192;


const int32_t input_1_offset_add_1 = 17;
const int32_t input_1_mult_add_1 = 1529705383;
const int32_t input_1_shift_add_1 = -2;
const int32_t input_2_offset_add_1 = -19;
const int32_t input_2_mult_add_1 = 1073741824;
const int32_t input_2_shift_add_1 = 0;
const int32_t left_shift_add_1 = 20;
const int32_t out_offset_add_1 = -128;
const int32_t out_mult_add_1 = 1247702269;
const int32_t out_shift_add_1 = -17;
const int32_t out_activation_min_add_1 = -128;
const int32_t out_activation_max_add_1 = 127;
const int32_t block_size_add_1 = 8192;

int32_t multiplier_conv2d_6[] = {1233741632,1256968419,1905476261,1823184151,1645695616,1285449006, 2135297161,1993148237,2043984984,1438114628,1895455022,2037760627, 1232276771,1598052565,1972424016,1406085971,1210219317,1334384496, 1809613832,1962629062,1486460939,1235952641,1962089415,1761645289, 2074400619,1902020467,1697353459,1266074409,1722718618,1192080334, 1940952769,1126291369,1811690110,1286455375,1501614387,1203368380, 1363495995,1211952268,1454401379,1899316309,1716161405,2063923633, 1355393342,2048251476,2050603571,1118103011,1975273735,2112592404, 1806725123,1191469422,1179749168,2122239341,1403234375,1844152564, 1638190518,1229405824,2012296982,2138825303,1092855760,1877017912, 1833432542,2032438667,1756596546,1304834289};
int32_t shift_conv2d_6[] = {-8,-8,-9,-9,-9,-8,-9,-9,-9,-8,-9,-9,-8,-9,-9,-8,-8,-8,-9,-9,-8,-8,-9,-9, -9,-9,-9,-8,-9,-7,-9,-8,-9,-8,-8,-8,-8,-8,-9,-9,-9,-9,-8,-9,-9,-8,-9,-9, -9,-8,-8,-9,-8,-9,-9,-8,-9,-9,-8,-9,-9,-9,-9,-8};

cmsis_nn_conv_params conv_params_conv2d_6 = {.input_offset = 128, .output_offset = -128, .stride = {.w = 2, .h = 2}, .padding = {.w = 0, .h = 0}, .dilation = {.w = 1, .h = 1}, .activation = {.min = -128, .max = 127}};
cmsis_nn_per_channel_quant_params quant_params_conv2d_6 = {.multiplier = multiplier_conv2d_6, .shift=shift_conv2d_6};
cmsis_nn_dims input_dims_conv2d_6 = {.n = 1, .h = 16, .w = 16, .c = 32};
cmsis_nn_dims filter_dims_conv2d_6 = {.n = 64, .h = 3, .w = 3, .c = 32};
cmsis_nn_dims bias_dims_conv2d_6 = {.n = 1, .h = 1, .w = 1, .c = 64};
cmsis_nn_dims output_dims_conv2d_6 = {.n = 1, .h = 8, .w = 8, .c = 64};
const uint32_t output_size_conv2d_6 = 4096;


#endif