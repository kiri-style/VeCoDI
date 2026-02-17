#!/usr/bin/env python3
"""
Encrypt TFLite model with XOR cipher for secure enclave demo.
"""

import os

# Simple XOR key (in real system, use proper crypto)
XOR_KEY = 0x42

INPUT_MODEL = "../src/cifar_resnet_lite_int8.tflite"
OUTPUT_H = "../src/cifar_resnet_lite_int8_encrypted.h"

def encrypt_file(input_path, output_path, key):
    """Encrypt file with XOR cipher."""
    with open(input_path, 'rb') as f:
        data = f.read()
    
    encrypted = bytes([b ^ key for b in data])
    
    # Generate C header
    var_name = "cifar_resnet_lite_int8_encrypted"
    
    with open(output_path, 'w') as f:
        f.write(f'#ifndef CIFAR_RESNET_LITE_INT8_ENCRYPTED_H\n')
        f.write(f'#define CIFAR_RESNET_LITE_INT8_ENCRYPTED_H\n\n')
        f.write(f'#ifdef __cplusplus\n')
        f.write(f'extern "C" {{\n')
        f.write(f'#endif\n\n')
        
        f.write(f'/* XOR-encrypted TFLite model (key: 0x{key:02x}) */\n')
        f.write(f'const unsigned char {var_name}[] __attribute__((aligned(8))) = {{\n')
        
        for i, byte in enumerate(encrypted):
            if i % 12 == 0:
                f.write('  ')
            f.write(f'0x{byte:02x}, ')
            if (i + 1) % 12 == 0:
                f.write('\n')
        
        f.write('\n};\n\n')
        f.write(f'const unsigned int {var_name}_len = {len(encrypted)};\n\n')
        
        f.write(f'#ifdef __cplusplus\n')
        f.write(f'}}\n')
        f.write(f'#endif\n\n')
        f.write(f'#endif /* CIFAR_RESNET_LITE_INT8_ENCRYPTED_H */\n')
    
    print(f"✓ Encrypted {len(data)} bytes")
    print(f"✓ Saved to: {output_path}")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_full = os.path.join(script_dir, INPUT_MODEL)
    output_full = os.path.join(script_dir, OUTPUT_H)
    
    if not os.path.exists(input_full):
        print(f"Error: {input_full} not found!")
        print("Run train_lite_resnet.py first to generate the model.")
        exit(1)
    
    encrypt_file(input_full, output_full, XOR_KEY)
    print(f"\nNext steps:")
    print(f"1. Include this header in create_enclave.cpp")
    print(f"2. Call decrypt_model_into_enclave() to decrypt in Secure World")
