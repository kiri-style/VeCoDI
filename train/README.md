# Model Training & Encryption

## Overview
This directory contains Python scripts for training, quantizing, and encrypting the CIFAR-10 model used by the firmware.

### Workflow
```
CIFAR-10 Dataset → train_lite_resnet.py → .tflite model
                         ↓
                   Quantize to INT8
                         ↓
                   Generate C arrays
                         ↓
             encrypt_model.py → Encrypted .h file
                         ↓
                   Include in firmware
```

## Prerequisites

### Python Environment
```bash
python3.12 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows
pip install tensorflow==2.20.0 numpy
```

**Requirements**:
- Python 3.12 (TensorFlow not compatible with 3.14+)
- TensorFlow 2.20.0
- Keras 3.13.2 (auto-installed with TensorFlow)
- NumPy

## Scripts

### train_lite_resnet.py

**Purpose**: Train a lightweight ResNet for CIFAR-10 classification optimized for embedded use.

**Usage**:
```bash
cd train/
python train_lite_resnet.py
```

**Outputs**:
- ../src/cifar_resnet_lite_int8.tflite
- ../src/cifar_resnet_lite_int8_data.cc
- ../src/cifar_resnet_lite_int8_data.h

**Model Architecture (summary)**:
```
Input (32×32×3)
  → Conv2D(16)
  → ResidualBlock(16)
  → ResidualBlock(32, stride 2)
  → ResidualBlock(64, stride 2)
  → GlobalAveragePooling
  → Dropout(0.3)
  → Dense(10)
```

**Training Parameters**:
- Optimizer: Adam (lr=0.001)
- Epochs: 50 (early stopping)
- Batch Size: 64
- Augmentation: Flip, Rotation, Zoom

**Expected Results**:
- Accuracy: ~71.7%
- Model size: 39,504 bytes

**Quantization**:
```python
converter = tf.lite.TFLiteConverter.from_keras_model(model)
converter.optimizations = [tf.lite.Optimize.DEFAULT]
converter.representative_dataset = representative_dataset
converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
converter.inference_input_type = tf.int8
converter.inference_output_type = tf.int8
```

---

### encrypt_model.py

**Purpose**: Encrypt the model for secure ROM storage using XOR (demo only).

**Usage**:
```bash
cd train/
python encrypt_model.py
```

**Input**: ../src/cifar_resnet_lite_int8.tflite  
**Output**: ../src/cifar_resnet_lite_int8_encrypted.h

**XOR Encryption**:
```python
XOR_KEY = 0x42
encrypted_byte = plaintext_byte ^ XOR_KEY
```

---

## End-to-End Workflow

```bash
# 1) Train
python train_lite_resnet.py

# 2) Encrypt
python encrypt_model.py

# 3) Build firmware
cd ..
west build -p auto -b nucleo_l552ze_q .
west flash
```

Expected device output:
```
[NS] Model encrypted in ROM at 0x8049490 (39504 bytes)
[S] Decryption successful: 39504 bytes
[NS] Model loaded from RAM enclave at 0x200000a0
[NS] Prediction: 6 (ship)
[NS] Prediction: 9 (truck)
```

---

## Troubleshooting

### TensorFlow install fails
```bash
python --version  # must be 3.12 or lower
pip uninstall tensorflow
pip install tensorflow==2.20.0
```

### Training runs out of memory
```python
# reduce batch size
batch_size = 32
```

### Encrypted model fails to decrypt
```bash
grep "XOR_KEY" encrypt_model.py
grep "XOR_KEY" ../dummy_partition/dummy_partition.c
```

---

## References
- https://www.tensorflow.org/lite/microcontrollers
- https://www.tensorflow.org/model_optimization
- https://www.cs.toronto.edu/~kriz/cifar.html

---

**License**: Apache 2.0  
**Last Updated**: 2024 (TensorFlow 2.20.0, Python 3.12)# Hello World Training

This example shows how to train a 2.5 kB model to generate a `sine` wave.

## Table of contents

-   [Overview](#overview)
-   [Training](#training)
-   [Trained Models](#trained-models)
-   [Model Architecture](#model-architecture)

## Overview

1. Dataset: Data is generated locally in the Jupyter Notebook.
2. Dataset Type: **Structured Data**
3. Deep Learning Framework: **TensorFlow 2**
4. Language: **Python 3.7**
5. Model Size: **2.5 kB**
6. Model Category: **Regression**

## Training

Train the model in the cloud using Google Colaboratory or locally using a
Jupyter Notebook.

<table class="tfo-notebook-buttons" align="left">
  <td>
    <a target="_blank" href="https://colab.research.google.com/github/tensorflow/tensorflow/blob/master/tensorflow/lite/micro/examples/hello_world/train/train_hello_world_model.ipynb"><img src="https://www.tensorflow.org/images/colab_logo_32px.png" />Google Colaboratory</a>
  </td>
  <td>
    <a target="_blank" href="https://github.com/tensorflow/tensorflow/blob/master/tensorflow/lite/micro/examples/hello_world/train/train_hello_world_model.ipynb"><img src="https://www.tensorflow.org/images/GitHub-Mark-32px.png" />Jupyter Notebook</a>
  </td>
</table>

*Estimated Training Time: 10 minutes.*


## Trained Models

Download Link | [hello_world.zip](https://storage.googleapis.com/download.tensorflow.org/models/tflite/micro/hello_world_2020_12_28.zip)
------------- | ------------------------------------------------------------------------------------------------------------------------

The `models` directory in the above zip file can be generated by following the
instructions in the [Training](#training) section above. It
includes the following 3 model files:

| Name | Format | Target Framework | Target Device |
| :------------- |:-------------|:-------------|-----|
| `model.pb` | Keras SavedModel | TensorFlow | Large-Scale/Cloud/Servers   |
| `model.tflite` *(2.5 kB)*  | Integer Only Quantized TFLite Model | TensorFlow Lite | Mobile Devices|
| `model.cc`  | C Source File | TensorFlow Lite for Microcontrollers | Microcontrollers |


## Model Architecture

The final model used to simulate a sine wave is displayed below. It is a
simple feed forward deep neural network with 2 fully connected layers with
ReLu activations and a final fully connected output layer with as shown below.

![model_architecture.png](../images/model_architecture.png)

*This image was derived from visualizing the 'model.tflite' file in [Netron](https://github.com/lutzroeder/netron)*

