import pickle
import numpy as np
with open("cifar-10-batches-py/data_batch_1", "rb") as f:
    data = pickle.load(f, encoding="bytes")

img = data[b"data"][0]      # image 0
label = data[b"labels"][0]

img = img.reshape(3, 32, 32).transpose(1,2,0)  # HWC

print("Label =", label)
print(img.flatten()[:20])
flat = img.flatten().astype(np.uint8)

print("static const uint8_t test_img[3072] = {")
for i,v in enumerate(flat):
    print(f"{v},", end="")
    if (i+1) % 16 == 0:
        print()
print("};")
