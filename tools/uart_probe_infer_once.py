import struct
import time
import serial

PORT = "/dev/tty.usbmodem11203"
BAUD = 115200


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


def u32(v: int) -> bytes:
    return struct.pack("<I", v)


def main():
    ser = serial.Serial(PORT, BAUD, timeout=2, write_timeout=2)
    time.sleep(2)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    # Ensure enclave exists
    st, pl = send_cmd(ser, 0x11)
    print("CREATE resp:", st, pl)

    # Set max inferences to 3
    st, pl = send_cmd(ser, 0x0B, u32(3))
    print("SET_MAX resp:", st, pl)

    # Run one inference (legacy no encrypted payload)
    st, pl = send_cmd(ser, 0x04)
    print("RUN_INF resp:", st, pl)

    # Read result (pred + expected)
    st, pl = send_cmd(ser, 0x0A)
    print("GET_RESULT resp:", st, pl)

    ser.close()


if __name__ == "__main__":
    main()
