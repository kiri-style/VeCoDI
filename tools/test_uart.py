#!/usr/bin/env python3
"""Quick test of UART protocol - simplified version"""
import serial
import sys
import struct
import time

def test_protocol(port):
    print(f"Connecting to {port}...")
    ser = serial.Serial(port, 115200, timeout=2)
    time.sleep(2)
    
    print("Sending CMD_GET_MAX_INFERENCES (0x03)...")
    # [CMD:1][LEN:4][DATA:0]
    packet = struct.pack('<BI', 0x03, 0)  # CMD=3, LEN=0
    ser.write(packet)
    ser.flush()
    
    print("Reading response...")
    # [STATUS:1][LEN:4][DATA:n]
    status = ser.read(1)
    if len(status) != 1:
        print("✗ Timeout reading status")
        return
    
    print(f"Status: 0x{status[0]:02X}")
    
    len_bytes = ser.read(4)
    if len(len_bytes) != 4:
        print("✗ Timeout reading length")
        return
    
    data_len = struct.unpack('<I', len_bytes)[0]
    print(f"Length: {data_len} bytes")
    
    if data_len > 0:
        data = ser.read(data_len)
        print(f"Data: {data.hex()}")
        
        if data_len == 4:
            value = struct.unpack('<I', data)[0]
            print(f"max_inferences = {value}")
    
    ser.close()
    print("✓ Test complete")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_uart.py /dev/tty.usbmodem14203")
        sys.exit(1)
    
    test_protocol(sys.argv[1])
