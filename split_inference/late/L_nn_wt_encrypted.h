#ifndef L_NN_WT_ENCRYPTED_H
#define L_NN_WT_ENCRYPTED_H

#include <stdint.h>

#define LATE_WT_CONV2D_7_SIZE 36864
#define LATE_WT_CONV2D_8_SIZE 2048
#define LATE_WT_FC_SIZE 640
#define LATE_WT_TOTAL_SIZE 39552

#define LATE_WT_CONV2D_7_OFFSET 0
#define LATE_WT_CONV2D_8_OFFSET 36864
#define LATE_WT_FC_OFFSET 38912

extern const uint8_t late_wt_iv[16];
extern const uint8_t late_wt_encrypted[39552];
extern const uint32_t late_wt_encrypted_len;

#endif
