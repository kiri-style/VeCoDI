#!/usr/bin/env python3
"""
Train a lightweight ResNet for CIFAR-10 and convert to TFLite quantized model.
Target: <50KB model size for embedded deployment.
"""

import tensorflow as tf
from tensorflow import keras
import numpy as np
import os

# ============================================================
#                    CONFIG
# ============================================================
MODEL_NAME = "cifar_resnet_lite_int8"
OUTPUT_DIR = "../src"
TARGET_SIZE_KB = 50  # Target model size


# ============================================================
#              LIGHTWEIGHT RESNET ARCHITECTURE
# ============================================================
def residual_block(x, filters, stride=1, name=""):
    """Lightweight residual block with depthwise separable convs."""
    shortcut = x
    
    # Depthwise separable conv instead of regular conv
    x = keras.layers.SeparableConv2D(filters, 3, strides=stride, padding='same', 
                                      name=f'{name}_sep1')(x)
    x = keras.layers.BatchNormalization(name=f'{name}_bn1')(x)
    x = keras.layers.ReLU(name=f'{name}_relu1')(x)
    
    x = keras.layers.SeparableConv2D(filters, 3, padding='same', 
                                      name=f'{name}_sep2')(x)
    x = keras.layers.BatchNormalization(name=f'{name}_bn2')(x)
    
    # Shortcut with 1x1 conv if dimensions change
    if stride != 1 or shortcut.shape[-1] != filters:
        shortcut = keras.layers.Conv2D(filters, 1, strides=stride, 
                                        name=f'{name}_shortcut')(shortcut)
        shortcut = keras.layers.BatchNormalization(name=f'{name}_bn_shortcut')(shortcut)
    
    x = keras.layers.Add(name=f'{name}_add')([x, shortcut])
    x = keras.layers.ReLU(name=f'{name}_relu2')(x)
    return x


def create_lite_resnet(input_shape=(32, 32, 3), num_classes=10):
    """Create lightweight ResNet for CIFAR-10."""
    inputs = keras.Input(shape=input_shape)
    
    # Initial conv - reduced filters
    x = keras.layers.Conv2D(16, 3, padding='same', name='conv1')(inputs)
    x = keras.layers.BatchNormalization(name='bn1')(x)
    x = keras.layers.ReLU(name='relu1')(x)
    
    # Residual blocks with fewer filters
    x = residual_block(x, 16, name='block1_1')
    
    x = residual_block(x, 32, stride=2, name='block2_1')
    
    x = residual_block(x, 64, stride=2, name='block3_1')
    
    # Global pooling and classification
    x = keras.layers.GlobalAveragePooling2D(name='gap')(x)
    x = keras.layers.Dropout(0.3, name='dropout')(x)
    outputs = keras.layers.Dense(num_classes, name='fc')(x)
    
    model = keras.Model(inputs, outputs, name='lite_resnet')
    return model


# ============================================================
#                    TRAINING
# ============================================================
def train_model():
    print("="*60)
    print("Loading CIFAR-10 dataset...")
    print("="*60)
    
    # Load data
    (x_train, y_train), (x_test, y_test) = keras.datasets.cifar10.load_data()
    
    # Normalize to [-1, 1]
    x_train = x_train.astype('float32') / 127.5 - 1.0
    x_test = x_test.astype('float32') / 127.5 - 1.0
    
    # One-hot encode labels
    y_train = keras.utils.to_categorical(y_train, 10)
    y_test = keras.utils.to_categorical(y_test, 10)
    
    print(f"Train samples: {len(x_train)}")
    print(f"Test samples: {len(x_test)}")
    
    # Create model
    print("\n" + "="*60)
    print("Creating lightweight ResNet...")
    print("="*60)
    model = create_lite_resnet()
    model.summary()
    
    # Compile
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss=keras.losses.CategoricalCrossentropy(from_logits=True),
        metrics=['accuracy']
    )
    
    # Callbacks
    callbacks = [
        keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, 
                                          patience=3, verbose=1),
        keras.callbacks.EarlyStopping(monitor='val_accuracy', patience=10, 
                                      restore_best_weights=True, verbose=1)
    ]
    
    # Train
    print("\n" + "="*60)
    print("Training model...")
    print("="*60)
    history = model.fit(
        x_train, y_train,
        batch_size=128,
        epochs=50,
        validation_data=(x_test, y_test),
        callbacks=callbacks,
        verbose=1
    )
    
    # Evaluate
    test_loss, test_acc = model.evaluate(x_test, y_test, verbose=0)
    print(f"\n✓ Test accuracy: {test_acc*100:.2f}%")
    
    return model, (x_test, y_test)


# ============================================================
#                 QUANTIZATION & CONVERSION
# ============================================================
def representative_dataset(x_test):
    """Generator for calibration data."""
    for i in range(100):
        yield [x_test[i:i+1].astype(np.float32)]


def convert_to_tflite(model, x_test):
    print("\n" + "="*60)
    print("Converting to TFLite INT8...")
    print("="*60)
    
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    
    # Full integer quantization
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    converter.representative_dataset = lambda: representative_dataset(x_test)
    converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
    converter.inference_input_type = tf.int8
    converter.inference_output_type = tf.int8
    
    tflite_model = converter.convert()
    
    print(f"✓ Model size: {len(tflite_model) / 1024:.2f} KB")
    
    return tflite_model


def save_tflite(tflite_model, name="model"):
    """Save TFLite model as .tflite and .cc files."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Save .tflite
    tflite_path = os.path.join(OUTPUT_DIR, f"{name}.tflite")
    with open(tflite_path, 'wb') as f:
        f.write(tflite_model)
    print(f"✓ Saved: {tflite_path}")
    
    # Convert to C array
    cc_path = os.path.join(OUTPUT_DIR, f"{name}_data.cc")
    h_path = os.path.join(OUTPUT_DIR, f"{name}_data.h")
    
    var_name = name.replace('-', '_')
    
    # Write .cc file
    with open(cc_path, 'w') as f:
        f.write(f'#include "{os.path.basename(h_path)}"\n\n')
        f.write(f'alignas(8) const unsigned char {var_name}[] = {{\n')
        
        for i, byte in enumerate(tflite_model):
            if i % 12 == 0:
                f.write('  ')
            f.write(f'0x{byte:02x}, ')
            if (i + 1) % 12 == 0:
                f.write('\n')
        
        f.write('\n};\n\n')
        f.write(f'const unsigned int {var_name}_len = {len(tflite_model)};\n')
    
    # Write .h file
    with open(h_path, 'w') as f:
        guard = f"{var_name.upper()}_DATA_H"
        f.write(f'#ifndef {guard}\n')
        f.write(f'#define {guard}\n\n')
        f.write('#ifdef __cplusplus\n')
        f.write('extern "C" {\n')
        f.write('#endif\n\n')
        f.write(f'extern const unsigned char {var_name}[];\n')
        f.write(f'extern const unsigned int {var_name}_len;\n\n')
        f.write('#ifdef __cplusplus\n')
        f.write('}\n')
        f.write('#endif\n\n')
        f.write(f'#endif  // {guard}\n')
    
    print(f"✓ Saved: {cc_path}")
    print(f"✓ Saved: {h_path}")


# ============================================================
#                      MAIN
# ============================================================
def main():
    print("\n" + "="*60)
    print("CIFAR-10 Lightweight ResNet Training")
    print("="*60)
    
    # Train
    model, (x_test, y_test) = train_model()
    
    # Convert to TFLite
    tflite_model = convert_to_tflite(model, x_test)
    
    # Check size
    size_kb = len(tflite_model) / 1024
    if size_kb > TARGET_SIZE_KB:
        print(f"\n⚠ Warning: Model size ({size_kb:.2f} KB) exceeds target ({TARGET_SIZE_KB} KB)")
        print("Consider reducing filters or depth further.")
    
    # Save
    save_tflite(tflite_model, MODEL_NAME)
    
    print("\n" + "="*60)
    print("✓ Done!")
    print("="*60)
    print(f"\nNext steps:")
    print(f"1. Update inference.cpp to use '{MODEL_NAME}_data.h'")
    print(f"2. Rebuild and flash to STM32")


if __name__ == "__main__":
    main()
