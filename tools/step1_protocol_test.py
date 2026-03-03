#!/usr/bin/env python3
import sys
import time
import struct
import serial

if len(sys.argv) < 2:
    print("Usage: python3 tools/step1_protocol_test.py /dev/tty.usbmodemXXXX")
    sys.exit(1)

port = sys.argv[1]
print(f"Connecting to {port}...")
ser = serial.Serial(port=port, baudrate=115200, timeout=5.0, write_timeout=5.0)

print("Waiting 2 seconds for device...")
time.sleep(2)
print("Flushing buffers...")
ser.reset_input_buffer()
ser.reset_output_buffer()

# Send CMD 0x01 with LEN=0
packet = struct.pack('<BI', 0x01, 0)
print(f"Sending packet: {packet.hex()} ({len(packet)} bytes)")
ser.write(packet)
ser.flush()
print("Sent. Waiting for response...")

# Read response: [status][len][data]
print("Reading status byte...")
status = ser.read(1)
if len(status) != 1:
    print(f"Timeout: no status (got {len(status)} bytes)")
    sys.exit(0)
print(f"Got status: 0x{status[0]:02X}")

print("Reading 4 length bytes...")
length_bytes = ser.read(4)
if len(length_bytes) != 4:
    print(f"Timeout: no length (got {len(length_bytes)} bytes)")
    sys.exit(0)
print(f"Got length bytes: {length_bytes.hex()}")

length = struct.unpack('<I', length_bytes)[0]
print(f"Decoded length: {length}")

data = ser.read(length) if length > 0 else b""

print(f"status=0x{status[0]:02X}, len={length}, data={data.hex()}")

ser.close()
