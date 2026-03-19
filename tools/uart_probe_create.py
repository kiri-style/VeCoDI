import struct
import time
import serial

PORT = "/dev/tty.usbmodem11203"
BAUD = 115200


def read_console(ser, duration=1.5):
    end = time.time() + duration
    lines = []
    while time.time() < end:
        if ser.in_waiting:
            try:
                line = ser.readline().decode("utf-8", errors="ignore").strip()
                if line:
                    lines.append(line)
            except Exception:
                pass
        time.sleep(0.02)
    return lines


def send_cmd(ser, cmd: int, data: bytes = b""):
    pkt = struct.pack("<BI", cmd, len(data)) + data
    ser.write(pkt)
    ser.flush()
    time.sleep(0.05)

    st = ser.read(1)
    if len(st) != 1:
        return None, None
    ln = ser.read(4)
    if len(ln) != 4:
        return st[0], None
    n = struct.unpack("<I", ln)[0]
    payload = ser.read(n) if n else b""
    return st[0], payload


def main():
    print(f"Opening {PORT} @ {BAUD}")
    ser = serial.Serial(PORT, BAUD, timeout=1, write_timeout=2)
    time.sleep(2)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    print("\n=== BOOT CONSOLE ===")
    for line in read_console(ser, 2.0):
        print(line)

    print("\n=== CMD 0x10 GET_ENCLAVE_STATE ===")
    st, pl = send_cmd(ser, 0x10)
    print("resp:", st, pl)

    print("\n=== CMD 0x12 DESTROY_ENCLAVE ===")
    st, pl = send_cmd(ser, 0x12)
    print("resp:", st, pl)
    for line in read_console(ser, 1.5):
        print(line)

    print("\n=== CMD 0x11 CREATE_ENCLAVE ===")
    st, pl = send_cmd(ser, 0x11)
    print("resp:", st, pl)
    for line in read_console(ser, 5.0):
        print(line)

    print("\n=== CMD 0x10 GET_ENCLAVE_STATE ===")
    st, pl = send_cmd(ser, 0x10)
    print("resp:", st, pl)

    ser.close()


if __name__ == "__main__":
    main()
