from pathlib import Path

data = Path("split_inference/late/late_wt_enc.bin").read_bytes()

conv7 = 36864
conv8 = 2048
fc = 640

o_conv7 = 0
o_conv8 = o_conv7 + conv7
o_fc = o_conv8 + conv8

def format_bytes(bs):
    return ",".join(str(b) for b in bs)

iv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")

header = f"""#ifndef L_NN_WT_ENCRYPTED_H
#define L_NN_WT_ENCRYPTED_H

#include <stdint.h>

#define LATE_WT_CONV2D_7_SIZE {conv7}
#define LATE_WT_CONV2D_8_SIZE {conv8}
#define LATE_WT_FC_SIZE {fc}
#define LATE_WT_TOTAL_SIZE {len(data)}

#define LATE_WT_CONV2D_7_OFFSET {o_conv7}
#define LATE_WT_CONV2D_8_OFFSET {o_conv8}
#define LATE_WT_FC_OFFSET {o_fc}

extern const uint8_t late_wt_iv[16];
extern const uint8_t late_wt_encrypted[{len(data)}];
extern const uint32_t late_wt_encrypted_len;

#endif
"""

data_c = f"""#include <stdint.h>

const uint8_t late_wt_iv[16] = {{{format_bytes(iv)}}};

const uint8_t late_wt_encrypted[{len(data)}] = {{{format_bytes(data)}}};

const uint32_t late_wt_encrypted_len = {len(data)};
"""

Path("split_inference/late/L_nn_wt_encrypted.h").write_text(header)
Path("split_inference/late/L_nn_wt_encrypted_data.c").write_text(data_c)
print("wrote split_inference/late/L_nn_wt_encrypted.h and L_nn_wt_encrypted_data.c")
