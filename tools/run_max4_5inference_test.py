import os
import signal
import struct
import subprocess
import time
from pathlib import Path

import serial

PORT = "/dev/tty.usbmodem1203"
OK = 0x00
ERR = 0xFF

CMD_SET_MAX = 0x0B
CMD_GET_MAX = 0x03
CMD_RUN = 0x04
CMD_GET_CNT = 0x05
CMD_GET_REM = 0x06
CMD_GET_BENCH = 0x08
CMD_GET_SEC = 0x09


def release_port(port: str) -> None:
    try:
        pids = subprocess.check_output(["lsof", "-t", port], text=True).strip().splitlines()
    except Exception:
        pids = []
    for pid in pids:
        try:
            os.kill(int(pid), signal.SIGKILL)
        except Exception:
            pass


def send(ser: serial.Serial, cmd: int, data: bytes = b""):
    try:
        ser.reset_input_buffer()
    except Exception:
        pass

    ser.write(struct.pack("<BI", cmd, len(data)) + data)

    status = None
    for _ in range(256):
        b = ser.read(1)
        if not b:
            break
        if b[0] in (OK, ERR):
            status = b[0]
            break

    if status is None:
        return None, None

    length_raw = ser.read(4)
    if len(length_raw) < 4:
        return status, None

    n = struct.unpack("<I", length_raw)[0]
    payload = ser.read(n) if n else b""
    return status, payload


def pct(used: int, total: int) -> float:
    if not total:
        return 0.0
    return (used * 100.0) / total


def status_label(v: int) -> str:
    if v == OK:
        return "OK"
    if v == ERR:
        return "ERROR"
    return str(v)


def main() -> int:
    release_port(PORT)

    lines = []
    lines.append("=== TEST COMPLET: max_inferences=4, demande 5 inferences ===")

    run_rows = []
    ns_metrics = None
    s_metrics = None

    ser = serial.Serial(PORT, 115200, timeout=2)
    time.sleep(0.5)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    st, _ = send(ser, CMD_SET_MAX, struct.pack("<I", 4))
    lines.append(f"SET_MAX_INFERENCES(4): status={st}")

    st, data = send(ser, CMD_GET_MAX)
    max_v = struct.unpack("<I", data[:4])[0] if (st == OK and data and len(data) >= 4) else None
    lines.append(f"GET_MAX_INFERENCES: status={st}, value={max_v}")

    lines.append("RUNS: idx,status,count,remaining")
    for i in range(1, 6):
        st_run, _ = send(ser, CMD_RUN)
        st_cnt, data_cnt = send(ser, CMD_GET_CNT)
        st_rem, data_rem = send(ser, CMD_GET_REM)

        cnt = struct.unpack("<I", data_cnt[:4])[0] if (st_cnt == OK and data_cnt and len(data_cnt) >= 4) else None
        rem = struct.unpack("<I", data_rem[:4])[0] if (st_rem == OK and data_rem and len(data_rem) >= 4) else None
        run_rows.append((i, st_run, cnt, rem))
        lines.append(f"{i},{st_run},{cnt},{rem}")

    st, b = send(ser, CMD_GET_BENCH)
    lines.append(f"GET_BENCHMARK: status={st}, bytes={None if b is None else len(b)}")
    if st == OK and b and len(b) >= 72:
        vals = struct.unpack("<18I", b[:72])
        ns_keys = [
            "enclave_create_cycles",
            "enclave_destroy_cycles",
            "aes_decrypt_cycles",
            "late_hash_cycles",
            "inference_hash_cycles",
            "early_layers_cycles",
            "late_layers_cycles",
            "total_inference_cycles",
            "run_enclave_cycles",
            "heap_used_bytes",
            "heap_free_bytes",
            "stack_used_bytes",
            "ram_used_bytes",
            "ram_total_bytes",
            "flash_used_bytes",
            "flash_total_bytes",
            "inference_count",
            "enclave_recreations",
        ]
        ns_metrics = dict(zip(ns_keys, vals))
        lines.append(
            f"NS_MEMORY_FOOTPRINT: ram_used={vals[12]}, ram_total={vals[13]}, flash_used={vals[14]}, flash_total={vals[15]}"
        )
        lines.append(f"NS_CYCLES: total_inference={vals[7]}, run_enclave={vals[8]}")

    st, s = send(ser, CMD_GET_SEC)
    lines.append(f"GET_SECURE_BENCHMARK: status={st}, bytes={None if s is None else len(s)}")
    if st == OK and s and len(s) >= 88:
        u64 = struct.unpack("<7Q", s[:56])
        u32 = struct.unpack("<8I", s[56:88])
        s_keys_u64 = [
            "aes_decrypt_cycles",
            "late_hash_cycles",
            "digest_compute_cycles",
            "get_max_cycles",
            "check_allowed_cycles",
            "increment_cycles",
            "reset_cycles",
        ]
        s_keys_u32 = [
            "aes_decrypt_count",
            "late_hash_count",
            "digest_count",
            "counter_operations",
            "ram_used_bytes",
            "ram_total_bytes",
            "flash_used_bytes",
            "flash_total_bytes",
        ]
        s_metrics = {}
        for k, v in zip(s_keys_u64, u64):
            s_metrics[k] = v
        for k, v in zip(s_keys_u32, u32):
            s_metrics[k] = v
        lines.append(
            f"S_CYCLES: aes={u64[0]}, late_hash={u64[1]}, digest={u64[2]}, get_max={u64[3]}, check={u64[4]}, incr={u64[5]}, reset={u64[6]}"
        )
        lines.append(
            f"S_MEMORY_FOOTPRINT: ram_used={u32[4]}, ram_total={u32[5]}, flash_used={u32[6]}, flash_total={u32[7]}"
        )

    ser.close()

    out = "\n".join(lines) + "\n"
    print(out)

    out_file = Path("build/device_benchmark_max4_5runs.txt")
    out_file.write_text(out)
    print(f"Saved: {out_file}")

    md = []
    md.append("# Device Benchmark Report — Max Inferences = 4, Requested = 5")
    md.append("")
    md.append("## 1) Résumé")
    md.append("")
    if max_v is not None and run_rows:
        fifth_error = (run_rows[-1][1] == ERR)
        md.append(f"- Quota configuré: **{max_v}**")
        md.append(f"- 5ème inférence refusée: **{'Oui' if fifth_error else 'Non'}**")
        md.append(f"- Inference count final: **{run_rows[-1][2]}**")
        md.append(f"- Remaining final: **{run_rows[-1][3]}**")
    md.append("")

    md.append("## 2) Détail des 5 tentatives")
    md.append("")
    md.append("| Run | Status | Count | Remaining |")
    md.append("|---:|:---:|---:|---:|")
    for i, st_run, cnt, rem in run_rows:
        md.append(f"| {i} | {status_label(st_run)} ({st_run}) | {cnt} | {rem} |")
    md.append("")

    if ns_metrics:
        ns_ram_used = ns_metrics["ram_used_bytes"]
        ns_ram_total = ns_metrics["ram_total_bytes"]
        ns_flash_used = ns_metrics["flash_used_bytes"]
        ns_flash_total = ns_metrics["flash_total_bytes"]

        md.append("## 3) Memory footprint — Non-Secure (NS)")
        md.append("")
        md.append("| Metric | Value |")
        md.append("|---|---:|")
        md.append(f"| RAM used | {ns_ram_used} bytes |")
        md.append(f"| RAM total | {ns_ram_total} bytes |")
        md.append(f"| RAM usage | {pct(ns_ram_used, ns_ram_total):.2f}% |")
        md.append(f"| Flash used | {ns_flash_used} bytes |")
        md.append(f"| Flash total | {ns_flash_total} bytes |")
        md.append(f"| Flash usage | {pct(ns_flash_used, ns_flash_total):.2f}% |")
        md.append("")

        md.append("## 4) Performance — Non-Secure (NS)")
        md.append("")
        md.append("| Metric | Cycles |")
        md.append("|---|---:|")
        md.append(f"| total_inference_cycles | {ns_metrics['total_inference_cycles']} |")
        md.append(f"| run_enclave_cycles | {ns_metrics['run_enclave_cycles']} |")
        md.append(f"| early_layers_cycles | {ns_metrics['early_layers_cycles']} |")
        md.append(f"| late_layers_cycles | {ns_metrics['late_layers_cycles']} |")
        md.append("")

    if s_metrics:
        s_ram_used = s_metrics["ram_used_bytes"]
        s_ram_total = s_metrics["ram_total_bytes"]
        s_flash_used = s_metrics["flash_used_bytes"]
        s_flash_total = s_metrics["flash_total_bytes"]

        md.append("## 5) Memory footprint — Secure (S)")
        md.append("")
        md.append("| Metric | Value |")
        md.append("|---|---:|")
        md.append(f"| RAM used | {s_ram_used} bytes |")
        md.append(f"| RAM total | {s_ram_total} bytes |")
        md.append(f"| RAM usage | {pct(s_ram_used, s_ram_total):.2f}% |")
        md.append(f"| Flash used | {s_flash_used} bytes |")
        md.append(f"| Flash total | {s_flash_total} bytes |")
        md.append(f"| Flash usage | {pct(s_flash_used, s_flash_total):.2f}% |")
        md.append("")

        md.append("## 6) Performance — Secure (S)")
        md.append("")
        md.append("| Metric | Cycles |")
        md.append("|---|---:|")
        for k in [
            "aes_decrypt_cycles",
            "late_hash_cycles",
            "digest_compute_cycles",
            "get_max_cycles",
            "check_allowed_cycles",
            "increment_cycles",
            "reset_cycles",
        ]:
            md.append(f"| {k} | {s_metrics[k]} |")
        md.append("")

    md.append("## 7) Verdict")
    md.append("")
    if run_rows and run_rows[-1][1] == ERR and run_rows[-1][2] == 4 and run_rows[-1][3] == 0:
        md.append("✅ Politique de quota validée: 4 inférences autorisées, 5ème refusée.")
    else:
        md.append("❌ Politique de quota non respectée, vérifier logique de comptage/quota.")
    md.append("")

    md_text = "\n".join(md) + "\n"
    md_file = Path("build/device_benchmark_max4_5runs.md")
    md_file.write_text(md_text)
    print(f"Saved: {md_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
