import re
from pathlib import Path

src = Path("split_inference/late/L_nn_wt.h")
text = src.read_text()

names = ["wt_conv2d_7", "wt_conv2d_8", "wt_fc"]
arrays = {}
for name in names:
    m = re.search(rf"const int8_t\s+{name}\[(\d+)\]\s*=\s*\{{(.*?)\}};", text, re.S)
    if not m:
        raise SystemExit(f"Missing {name}")
    size = int(m.group(1))
    values = [v.strip() for v in m.group(2).replace("\n", " ").split(",") if v.strip()]
    if len(values) != size:
        raise SystemExit(f"Size mismatch {name}: expected {size}, got {len(values)}")
    arrays[name] = [int(v) for v in values]

plain = bytes((v & 0xFF) for name in names for v in arrays[name])
Path("split_inference/late/late_wt_plain.bin").write_bytes(plain)

sizes = {name: len(arrays[name]) for name in names}
print("sizes", sizes, "total", len(plain))
