import pickle
import numpy as np

with open("cifar-10-batches-py/data_batch_1", "rb") as f:
    data = pickle.load(f, encoding="bytes")

images = data[b'data']
labels = data[b'labels']

IDX = [0, 1, 2]  # 3 images suffisent

for k, i in enumerate(IDX):
    img = images[i]
    label = labels[i]

    # CIFAR → RGB interleaved
    r = img[0:1024]
    g = img[1024:2048]
    b = img[2048:3072]

    rgb = np.zeros(3072, dtype=np.uint8)
    for p in range(1024):
        rgb[3*p+0] = r[p]
        rgb[3*p+1] = g[p]
        rgb[3*p+2] = b[p]

    print(f"// Image {k} - Label {label}")
    print("static const uint8_t img_%d[3072] = {" % k)
    print(",".join(map(str, rgb)))
    print("};\n")
