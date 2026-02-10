.. zephyr:code-sample:: tflite-hello-world
   :name: Hello World

   Replicate a sine wave using TensorFlow Lite for Microcontrollers.

Overview
********

This sample TensorFlow application replicates a sine wave and
demonstrates the absolute basics of using TensorFlow Lite Micro.

The model included with the sample is trained to replicate a
sine function and generates x values to print alongside the
y values predicted by the model. The x values iterate from 0 to
an approximation of 2π.

The sample also includes a full end-to-end workflow of training
a model and converting it for use with TensorFlow Lite Micro for
running inference on a microcontroller.

The sample comes in two flavors. One with TensorFlow Lite Micro
reference kernels and one with CMSIS-NN optimized kernels.

.. Note::
   This README and sample have been modified from
   `the TensorFlow Hello World sample for Zephyr`_.

.. _the TensorFlow Hello World sample for Zephyr:
   https://github.com/tensorflow/tflite-micro/tree/main/tensorflow/lite/micro/examples/hello_world

Building and Running
********************

The sample should work on most boards since it does not rely
on any sensors.

Add the tflite-micro module to your West manifest and pull it:

.. code-block:: console

    west config manifest.project-filter -- +tflite-micro
    west update

The reference kernel application can be built and executed on QEMU as follows:

.. zephyr-app-commands::
   :zephyr-app: samples/modules/tflite-micro/hello_world
   :host-os: unix
   :board: qemu_x86
   :goals: run
   :compact:

Exit QEMU by pressing :kbd:`CTRL+A` :kbd:`x`.

The CMSIS-NN kernel application can be built and executed on any Arm(R) Cortex(R)-M core based platform,
for example based on Arm Corstone(TM)-300 software. A reference implementation of Corstone-300
can be downloaded either as a FPGA bitfile for the
[MPS3 FPGA prototyping board](https://developer.arm.com/tools-and-software/development-boards/fpga-prototyping-boards/mps3),
or as a
[Fixed Virtual Platform](https://developer.arm.com/tools-and-software/open-source-software/arm-platforms-software/arm-ecosystem-fvps)
that can be emulated on a host machine.

Assuming that the Corstone-300 FVP has been downloaded, installed and added to
the :envvar:`PATH` variable, then building and testing can be done with following
commands.

```
$ west build -p auto -b mps3/corstone300/fvp samples/modules/tflite-micro/hello_world/ -T sample.tensorflow.helloworld.cmsis_nn
$ FVP_Corstone_SSE-300_Ethos-U55 build/zephyr/zephyr.elf
```

Sample Output
=============

.. code-block:: console

    ...

    x_value: 1.0995567*2^1, y_value: 1.6951603*2^-1

    x_value: 1.2566366*2^1, y_value: 1.1527088*2^-1

    x_value: 1.4137159*2^1, y_value: 1.1527088*2^-2

    x_value: 1.5707957*2^1, y_value: -1.0849024*2^-6

    x_value: 1.7278753*2^1, y_value: -1.0509993*2^-2

    ...

The modified sample prints 10 generated-x-and-predicted-y pairs. To see
the full period of the sine curve, increase the number of loops in :file:`main.c`.

Modifying Sample for Your Own Project
*************************************

It is recommended that you copy and modify one of the two TensorFlow
samples when creating your own TensorFlow project. To build with
TensorFlow, you must enable the below Kconfig options in your :file:`prj.conf`:

.. code-block:: cfg

    CONFIG_CPP=y
    CONFIG_REQUIRES_FULL_LIBC=y
    CONFIG_TENSORFLOW_LITE_MICRO=y

Note that the CMSIS-NN kernel sample demonstrates how to use CMSIS-NN optimized kernels with
TensorFlow Lite Micro, in that is sets below Kconfig option. Note also that this
Kconfig option is only set for Arm Cortex-M cores, i.e. option CPU_CORTEX_M is set.

.. code-block:: cfg

    CONFIG_TENSORFLOW_LITE_MICRO_CMSIS_NN_KERNELS=y

Training
********
Follow the instructions in the :file:`train/` directory to train your
own model for use in the sample.





# Split Neural Network Inference (TF-M / Zephyr / CMSIS-NN)

This project implements a **split neural network inference pipeline** on an embedded platform using **Zephyr OS**, **Trusted Firmware-M (TF-M)**, and **CMSIS-NN**.

The neural network is divided into:
- **Early layers** executed in **Non-Secure (NS)** world
- **Late layers** executed either in:
  - a **Secure Partition (S)** via PSA IPC, or
  - a **Dummy Non-Secure partition** for full-pipeline validation and debugging

---

## 1. Project Goals

- Deploy an **int8 quantized neural network**
- Split inference into **Early / Late layers**
- Validate data exchange between layers
- Support **Secure inference (TF-M)** and **Non-Secure debug mode**
- Ensure correctness of quantization, tensor ranges, and outputs

---

## 2. High-Level Architecture

### 2.1 Secure Split Architecture (Final Target)
+–––––––––––+
Non-Secure (NS) App
- main.cpp
- run_early_layers
- dp_run_late (PSA)
+–––––+———–+
       |
       | PSA IPC
       |
+––––––v———–+
- Secure Partition (S)
- run_late_layers
+–––––––––––+
- Early layers run in **Non-Secure**
- Late layers are protected inside a **TF-M Secure Partition**
- Communication is done via **PSA IPC**

---

### 2.2 Dummy Partition Architecture (Debug / Validation Mode)
+–––––––––––+
Non-Secure (NS) App
- main.cpp
- run_early_layers
- dummy_partition
- run_late_layers
+–––––––––––+
- Entire inference runs in **Non-Secure**
- Used for:
  - debugging
  - validation
  - tensor inspection
- Same CMSIS-NN kernels and weights as Secure mode

---

## 3. Directory Structure Overview
.
├── src/
│   ├── ns/                     # Non-Secure inference logic
│   │   ├── run_early_layers.cpp
│   │   ├── dp_run_late.cpp
│   │   ├── dp_run_late.h
│   │   ├── nn_paramsE.h
│   │   └── nn_wtE.h
│   │
│   ├── s/                      # Secure inference logic
│   │   ├── run_late_layers.cpp
│   │   ├── nn_paramsL.h
│   │   └── nn_wtL.h
│   │
│   ├── CMSIS_NN/               # CMSIS-NN library (source + headers)
│   │
│   ├── dummy_partition/        # Non-Secure dummy late inference
│   │   ├── dummy_partition.c
│   │   ├── nn_paramsL.h
│   │   ├── nn_wtL.h
│   │   ├── tfm_dummy_partition.yaml
│   │   └── CMakeLists.txt
│   │
│   ├── main.cpp                # Application entry point
│   └── model_data.cc           # TFLite / model related data
│
├── model_creation/             # Model generation and inspection
│   ├── train_mlp.py
│   ├── cifar10_tiny_int8.tflite
│   ├── inspect_tflite_input.py
│   └── generate_cifar_input.py
│
├── cifar_input.h               # Static quantized input sample
├── prj.conf                    # Zephyr configuration
├── CMakeLists.txt
└── README.md

---

## 4. File-Level Responsibilities

### 4.1 Non-Secure (NS) Files

#### `src/ns/run_early_layers.cpp`
- Executes **early layers** of the neural network
- Uses **CMSIS-NN kernels**
- Input: quantized `int8` tensor
- Output: intermediate feature map passed to late layers
- Instrumented with debug logs:
  - min / max values
  - saturation statistics

---

#### `src/ns/dp_run_late.cpp`
- Acts as the **PSA client**
- Sends early output tensor to Secure world
- Calls Secure late inference via TF-M IPC
- Abstracts Secure communication from the application

---

#### `src/ns/nn_paramsE.h`
- Network parameters for early layers
- Tensor shapes, strides, padding, activation settings

---

#### `src/ns/nn_wtE.h`
- Quantized weights and biases for early layers

---

### 4.2 Secure (S) Files

#### `src/s/run_late_layers.cpp`
- Executes **late layers** inside a Secure Partition
- Uses CMSIS-NN
- Receives input tensor via PSA IPC
- Outputs final prediction

---

#### `src/s/nn_paramsL.h`
- Network parameters for late layers

---

#### `src/s/nn_wtL.h`
- Quantized weights and biases for late layers

---

### 4.3 Dummy Partition (Non-Secure Debug Mode)

#### `dummy_partition/dummy_partition.c`
- Reimplementation of late layers in **Non-Secure**
- Same logic and weights as Secure version
- Allows:
  - full tensor inspection
  - easier debugging
  - validation of end-to-end inference

---

#### `dummy_partition/tfm_dummy_partition.yaml`
- TF-M manifest file
- Used to register the dummy partition during build

---

### 4.4 Application Entry Point

#### `src/main.cpp`
- Initializes the system
- Loads input tensor
- Runs early inference
- Calls late inference (Secure or Dummy)
- Prints final prediction

---

## 5. Quantization Details

- Input type: `int8`
- Quantization parameters:
scale      = 0.0039215689 (1 / 255)
zero_point = -128
- Quantized input formula:
q = round(float_value / scale) + zero_point
---

## 6. Debug and Validation Strategy

- Print early input tensors
- Print early output tensors
- Print late input tensors
- Track:
- min / max values
- saturation at -128 / 127
- Validate correctness before enabling Secure execution

---

## 7. Current Status

- ✅ Early / Late split functional
- ✅ End-to-end inference validated in Dummy mode
- ✅ Quantization pipeline verified
- ✅ Secure integration ready for final deployment

---

## 8. Next Steps

- Re-enable Secure late inference
- Benchmark Secure vs Non-Secure execution
- Extend split to additional layers
- Integrate hardware acceleration if available

---