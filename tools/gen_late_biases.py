import re
from pathlib import Path

src = Path("split_inference/late/L_nn_wt.h")
text = src.read_text()

names = ["bias_conv2d_7", "bias_conv2d_8", "bias_fc"]
arrays = {}
for name in names:
    m = re.search(rf"const int32_t\s+{name}\[(\d+)\]\s*=\s*\{{(.*?)\}};", text, re.S)
    if not m:
        raise SystemExit(f"Missing {name}")
    size = int(m.group(1))
    values = [v.strip() for v in m.group(2).replace("\n", " ").split(",") if v.strip()]
    if len(values) != size:
        raise SystemExit(f"Size mismatch {name}: expected {size}, got {len(values)}")
    arrays[name] = [int(v) for v in values]

lines = ["#ifndef L_NN_BIASES_H", "#define L_NN_BIASES_H", "", "#include <stdint.h>", ""]
for name in names:
    vals = ",".join(str(v) for v in arrays[name])
    lines.append(f"const int32_t {name}[{len(arrays[name])}] = {{{vals}}};")
    lines.append("")
lines.append("#endif")

Path("split_inference/late/L_nn_biases.h").write_text("\n".join(lines))
print("wrote split_inference/late/L_nn_biases.h")
