#!/usr/bin/env python3
import sys
import time
import serial

if len(sys.argv) < 2:
    print("Usage: python3 tools/simple_uart_test.py /dev/tty.usbmodemXXXX")
    sys.exit(1)

port = sys.argv[1]
ser = serial.Serial(port=port, baudrate=115200, timeout=2.0, write_timeout=2.0)

# Give device time to boot
time.sleep(2)
ser.reset_input_buffer()
ser.reset_output_buffer()

print(f"Connected to {port}")

# Send 0x01
ser.write(b"\x01")
ser.flush()

# Read one byte back
resp = ser.read(1)
if resp == b"\x02":
    print("OK: received 0x02")
elif len(resp) == 0:
    print("Timeout: no response")
else:
    print(f"Unexpected response: 0x{resp[0]:02X}")

ser.close()
