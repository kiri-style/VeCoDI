import pickle
import numpy as np
import random

# Load CIFAR-10 batch
with open("cifar-10-batches-py/data_batch_1", "rb") as f:
    data = pickle.load(f, encoding="bytes")

images = data[b'data']
labels = data[b'labels']

# Find 2 images for each label (0-9) = 20 images total
all_images = {}  # {label: [indices]}
for label in range(10):
    all_images[label] = []

for i, label in enumerate(labels):
    if len(all_images[label]) < 2:
        all_images[label].append(i)
    if all([len(indices) == 2 for indices in all_images.values()]):
        break

# Flatten to get 20 images
all_indices = []
for label in range(10):
    all_indices.extend(all_images[label])

print(f"// Total images: {len(all_indices)}")
print(f"// Image distribution per label:")
for label in range(10):
    print(f"//   Label {label}: indices {all_images[label]}")

# Select 5 random test images
random.seed(42)  # For reproducibility
test_indices = random.sample(range(len(all_indices)), 5)
test_indices.sort()

print(f"\n// Test images (5 random): positions {test_indices}")
print(f"// Test labels: {[labels[all_indices[i]] for i in test_indices]}\n")

# Generate all 20 images
for k, img_idx in enumerate(all_indices):
    img = images[img_idx]
    label = labels[img_idx]

    # CIFAR → RGB interleaved
    r = img[0:1024]
    g = img[1024:2048]
    b = img[2048:3072]

    rgb = np.zeros(3072, dtype=np.uint8)
    for p in range(1024):
        rgb[3*p+0] = r[p]
        rgb[3*p+1] = g[p]
        rgb[3*p+2] = b[p]

    print(f"// Image {k} - Label {label} (CIFAR index {img_idx})")
    print(f"const uint8_t img_{k}[3072] = {{")
    print(",".join(map(str, rgb)))
    print("};\n")

# Print all labels
print("\n// All labels (20 images)")
for k, img_idx in enumerate(all_indices):
    print(f"const uint8_t label_{k} = {labels[img_idx]};")

# Print test configuration
print("\n// Test configuration")
print(f"#define NUM_TEST_IMAGES 5")
print(f"static const uint8_t *const test_images[NUM_TEST_IMAGES] = {{")
for i in test_indices:
    print(f"    img_{i},")
print("};")
print(f"static const uint8_t test_labels[NUM_TEST_IMAGES] = {{")
for i in test_indices:
    print(f"    label_{i},")
print("};")
print(f"static const int test_image_ids[NUM_TEST_IMAGES] = {{{', '.join(map(str, test_indices))}}};")

