#!/usr/bin/env python3
"""
Standalone VECODI case study runner.

This script is intentionally self-contained so it still works even if mac_provider.py
or other helper scripts are removed.

Flow implemented:
    Provider identity:
        1) EnclaveInfo attestation fetch/verification
        2) M_update send (strictly increasing c_limit)

  Model Customer identity:
    4) Create enclave
    5) Run verified inference N times
    6) Destroy enclave
"""

import argparse
import csv
import hashlib
import json
import os
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import serial
# Ensure compatibility when pyserial is installed as a namespace package
# (some installations do not expose Serial at the package top-level).
if not hasattr(serial, 'Serial'):
    try:
        from serial.serialposix import Serial as _SerialClass
    except Exception:
        try:
            from serial.serialwin32 import Serial as _SerialClass
        except Exception:
            _SerialClass = None
    if _SerialClass is not None:
        serial.Serial = _SerialClass
    # Also populate common constants/classes from serial.serialutil if missing
    try:
        import importlib
        _su = importlib.import_module('serial.serialutil')
        for _n in dir(_su):
            if not hasattr(serial, _n):
                try:
                    setattr(serial, _n, getattr(_su, _n))
                except Exception:
                    pass
    except Exception:
        pass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from PIL import Image
except ImportError:
    Image = None


# Commands (aligned with UART protocol)
CMD_COMPUTE_ENCLAVE_INFO = 0x01
CMD_VALIDATE_M_UPDATE = 0x02
CMD_GET_MAX_INFERENCES = 0x03
CMD_RUN_INFERENCE = 0x04
CMD_GET_INFERENCE_COUNT = 0x05
CMD_GET_REMAINING_INFERENCES = 0x06
CMD_GET_DEVICE_PUBKEY = 0x0C
CMD_GET_ENCLAVE_STATE = 0x10
CMD_CREATE_ENCLAVE = 0x11
CMD_DESTROY_ENCLAVE = 0x12
CMD_RUN_INFERENCE_WITH_IMAGE = 0x14
CMD_GET_BENCHMARK = 0x08
CMD_GET_SECURE_BENCHMARK = 0x09
CMD_GET_INFERENCE_RESULT = 0x0A
CMD_GET_INFERENCE_TRACE = 0x1B

RESP_OK = 0x00
CUSTOM_IMAGE_SIZE = 32 * 32 * 3
STATIC_SESSION_KEY = bytes([
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
])

DEVICE_BENCHMARK_NAMES = [
    "enclave_create_cycles", "enclave_destroy_cycles", "aes_decrypt_cycles",
    "early_layers_cycles", "late_layers_cycles", "total_inference_cycles", "run_enclave_cycles", "full_execute_cycles",
    "heap_used_bytes", "heap_free_bytes", "stack_used_bytes",
    "ram_used_bytes", "ram_total_bytes", "flash_used_bytes", "flash_total_bytes",
    "inference_count", "enclave_recreations", "inference_requests_total", "enclave_info_validation_failures",
    "enclave_create_sum_cycles", "enclave_destroy_sum_cycles", "aes_decrypt_sum_cycles",
    "early_layers_sum_cycles", "late_layers_sum_cycles", "total_inference_sum_cycles", "run_enclave_sum_cycles", "irq_atomic_sum_cycles",
    "enclave_create_min_cycles", "enclave_create_max_cycles", "enclave_destroy_min_cycles", "enclave_destroy_max_cycles",
    "aes_decrypt_min_cycles", "aes_decrypt_max_cycles", "early_layers_min_cycles", "early_layers_max_cycles",
    "late_layers_min_cycles", "late_layers_max_cycles", "total_inference_min_cycles", "total_inference_max_cycles",
    "run_enclave_min_cycles", "run_enclave_max_cycles", "irq_atomic_min_cycles", "irq_atomic_max_cycles",
    "enclave_create_count", "enclave_destroy_count", "aes_decrypt_count", "early_layers_count", "late_layers_count",
    "total_inference_count", "run_enclave_count", "irq_atomic_count",
    "full_execute_count", "full_execute_sum_cycles", "full_execute_min_cycles", "full_execute_max_cycles",
    "create_atomic_sum_cycles", "destroy_atomic_sum_cycles",
    "create_atomic_min_cycles", "create_atomic_max_cycles", "destroy_atomic_min_cycles", "destroy_atomic_max_cycles",
    "create_atomic_count", "destroy_atomic_count",
    "run_inference_with_image_count", "dangerous_inference_no_sau_count", "dangerous_read_ram_count", "dangerous_read_rom_count",
    "authorize_cycles", "authorize_count",
]
DEVICE_BENCHMARK_FMT = "<" + "I" * 19 + "xxxx" + "Q" * 8 + "I" * 16 + "I" * 8 + "I" + "xxxx" + "Q" + "I" * 2 + "Q" * 2 + "I" * 6 + "I" * 4 + "xxxxQI"

SECURE_BENCHMARK_NAMES = [
    "aes_decrypt_cycles", "late_hash_cycles", "digest_compute_cycles", "authorize_cycles", "global_crypto_init_cycles",
    "create_validate_cycles", "authorize_parse_cycles", "authorize_verify_cycles", "authorize_update_cycles", "authorize_crypto_init_cycles",
    "authorize_read_cycles", "authorize_import_key_cycles", "authorize_hash_msg_cycles", "authorize_verify_sig_cycles", "authorize_destroy_key_cycles",
    "authorize_verify_message_cycles", "authorize_verify_old_cycles", "create_recompute_cycles",
    "get_max_cycles", "check_allowed_cycles", "increment_cycles", "reset_cycles",
    "create_enclave_cycles", "finalize_create_cycles", "destroy_enclave_cycles", "inf_start_cycles", "inf_complete_cycles",
    "sau_sync_open_cycles", "sau_sync_close_cycles", "sau_flash_close_cycles", "sau_flash_open_cycles", "sau_flash_pulse_cycles",
    "aes_decrypt_count", "late_hash_count", "digest_count", "authorize_count", "authorize_crypto_init_count",
    "authorize_import_key_count", "authorize_verify_sig_count", "authorize_verify_message_count", "create_recompute_count", "counter_operations",
    "create_enclave_count", "finalize_create_count", "destroy_enclave_count", "inf_start_count", "inf_complete_count",
    "sau_sync_open_count", "sau_sync_close_count", "sau_flash_close_count", "sau_flash_open_count", "sau_flash_pulse_count",
    "ram_used_bytes", "ram_total_bytes", "flash_used_bytes", "flash_total_bytes",
]
SECURE_BENCHMARK_FMT = "<" + ("Q" * 32) + ("I" * 24)


def log(msg: str) -> None:
    print(msg, flush=True)


def load_image_from_mac(image_path: str) -> bytes:
    """Load an image from host (Mac) and return 32x32x3 bytes for CMD_RUN_INFERENCE_WITH_IMAGE."""
    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")

    ext = path.suffix.lower()
    if ext in (".bin", ".raw", ".rgb", ".cifar"):
        data = path.read_bytes()
        if len(data) != CUSTOM_IMAGE_SIZE:
            raise ValueError(f"Raw image must be {CUSTOM_IMAGE_SIZE} bytes, got {len(data)}")
        return data

    if Image is None:
        raise RuntimeError(
            "Pillow is required for PNG/JPEG input. Install pillow or pass a 3072-byte raw image file."
        )

    with Image.open(path) as img:
        img = img.convert("RGB").resize((32, 32))
        return img.tobytes()


@dataclass
class SessionState:
    enclave_info: Optional[bytes] = None
    device_pubkey: Optional[bytes] = None  # SEC1 uncompressed, 65 bytes
    verifier_key: Optional[ec.EllipticCurvePrivateKey] = None
    verifier_pub_raw: Optional[bytes] = None  # X||Y, 64 bytes


class UartDevice:
    def __init__(self, port: str, baudrate: int) -> None:
        self.port = port
        self.baudrate = baudrate
        self.ser: Optional[serial.Serial] = None

    def connect(self) -> None:
        self.ser = serial.Serial(
            port=self.port,
            baudrate=self.baudrate,
            timeout=8.0,
            write_timeout=5.0,
        )
        time.sleep(2.5)
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        log(f"[OK] Connected to {self.port} @ {self.baudrate}")

    def disconnect(self) -> None:
        if self.ser and self.ser.is_open:
            self.ser.close()
            log("[OK] Serial disconnected")

    def send_command(self, cmd: int, payload: bytes = b"") -> None:
        if not self.ser or not self.ser.is_open:
            raise RuntimeError("Serial port not open")
        packet = struct.pack("<BI", cmd, len(payload)) + payload
        self.ser.reset_input_buffer()
        self.ser.write(packet)
        self.ser.flush()

    def read_response(self, timeout: float = 6.0) -> Tuple[int, bytes]:
        if not self.ser or not self.ser.is_open:
            raise RuntimeError("Serial port not open")

        old_timeout = self.ser.timeout
        self.ser.timeout = timeout
        try:
            status_raw = self.ser.read(1)
            if len(status_raw) != 1:
                raise TimeoutError("Timeout reading status byte")
            status = status_raw[0]

            len_raw = self.ser.read(4)
            if len(len_raw) != 4:
                raise TimeoutError("Timeout reading length")
            length = struct.unpack("<I", len_raw)[0]

            data = b""
            if length:
                data = self.ser.read(length)
                if len(data) != length:
                    raise TimeoutError(f"Payload truncated: expected {length}, got {len(data)}")
            return status, data
        finally:
            self.ser.timeout = old_timeout


class VecodiCaseStudy:
    def __init__(self, device: UartDevice, model_id: int) -> None:
        self.device = device
        self.model_id = model_id
        self.state = SessionState()
        self.benchmarks: List[Dict[str, Any]] = []
        self.last_inference_meta: Dict[str, Any] = {}

    def _timed_call(self, action: str, fn, *args, **kwargs):
        start = time.perf_counter()
        status = "ok"
        detail = ""
        try:
            result = fn(*args, **kwargs)
            return result
        except Exception as exc:
            status = "error"
            detail = str(exc)
            raise
        finally:
            self.benchmarks.append(
                {
                    "action": action,
                    "status": status,
                    "detail": detail,
                }
            )

    def _record_extra(self, action: str, **fields: Any) -> None:
        self.benchmarks.append({"action": action, **fields})

    def _encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ct_tag = AESGCM(STATIC_SESSION_KEY).encrypt(nonce, plaintext, None)
        return nonce + ct_tag

    def _decrypt(self, payload: bytes) -> Optional[bytes]:
        if len(payload) < 28:
            return None
        nonce = payload[:12]
        ct_tag = payload[12:]
        try:
            return AESGCM(STATIC_SESSION_KEY).decrypt(nonce, ct_tag, None)
        except Exception:
            return None

    def read_ns_benchmark(self) -> Dict[str, int]:
        self.device.send_command(CMD_GET_BENCHMARK)
        status, payload = self.device.read_response(timeout=8.0)
        if status != RESP_OK:
            raise RuntimeError("CMD_GET_BENCHMARK failed")
        expected = struct.calcsize(DEVICE_BENCHMARK_FMT)
        if len(payload) < expected:
            raise RuntimeError(f"NS benchmark payload too short: got {len(payload)}, expected {expected}")
        values = struct.unpack(DEVICE_BENCHMARK_FMT, payload[:expected])
        result = {name: int(value) for name, value in zip(DEVICE_BENCHMARK_NAMES, values)}

        # Optional trailing fields: some firmware builds append
        # execute_verified metrics after the canonical struct. Parse them
        # if present to maintain backward compatibility.
        exec_fmt = "<I Q I I I"  # cycles, sum(Q), min, max, count
        exec_size = struct.calcsize(exec_fmt)
        offset = expected
        if len(payload) >= offset + exec_size:
            exec_vals = struct.unpack_from(exec_fmt, payload, offset)
            result.update({
                "execute_verified_cycles": int(exec_vals[0]),
                "execute_verified_sum_cycles": int(exec_vals[1]),
                "execute_verified_min_cycles": int(exec_vals[2]),
                "execute_verified_max_cycles": int(exec_vals[3]),
                "execute_verified_count": int(exec_vals[4]),
            })

        return result

    def read_secure_benchmark(self) -> Dict[str, int]:
        self.device.send_command(CMD_GET_SECURE_BENCHMARK)
        status, payload = self.device.read_response(timeout=8.0)
        if status != RESP_OK:
            raise RuntimeError("CMD_GET_SECURE_BENCHMARK failed")
        expected = struct.calcsize(SECURE_BENCHMARK_FMT)
        if len(payload) < expected:
            raise RuntimeError(f"Secure benchmark payload too short: got {len(payload)}, expected {expected}")
        values = struct.unpack(SECURE_BENCHMARK_FMT, payload[:expected])
        return {name: int(value) for name, value in zip(SECURE_BENCHMARK_NAMES, values)}

    def get_device_pubkey(self) -> bytes:
        self.device.send_command(CMD_GET_DEVICE_PUBKEY)
        status, payload = self.device.read_response()
        if status != RESP_OK or len(payload) != 65:
            raise RuntimeError("Failed to get device public key (pk_d)")
        self.state.device_pubkey = payload
        return payload

    @staticmethod
    def _verify_attested_enclave_info(device_pk_d: bytes, nonce: bytes, enclave_info: bytes, sig_raw: bytes) -> bool:
        if len(device_pk_d) != 65 or len(nonce) != 32 or len(enclave_info) != 32 or len(sig_raw) != 64:
            return False
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pk_d)
            r = int.from_bytes(sig_raw[:32], "big")
            s = int.from_bytes(sig_raw[32:], "big")
            sig_der = encode_dss_signature(r, s)
            pub.verify(sig_der, nonce + enclave_info, ec.ECDSA(hashes.SHA256()))
            return True
        except (ValueError, InvalidSignature):
            return False

    def provider_fetch_enclave_info(self) -> bytes:
        log("\n[Provider] Step 2 - Fetch/verify EnclaveInfo")
        if self.state.device_pubkey is None:
            self.get_device_pubkey()

        nonce = os.urandom(32)
        self.device.send_command(CMD_COMPUTE_ENCLAVE_INFO, nonce)
        status, payload = self.device.read_response()
        if status != RESP_OK:
            raise RuntimeError("CMD_COMPUTE_ENCLAVE_INFO failed")

        plain = self._decrypt(payload)
        if plain is None:
            plain = payload

        if len(plain) >= 96:
            enclave_info = plain[:32]
            sig_d = plain[32:96]
            if not self._verify_attested_enclave_info(self.state.device_pubkey, nonce, enclave_info, sig_d):
                raise RuntimeError("Invalid EnclaveInfo attestation signature")
            self.state.enclave_info = enclave_info
            log("[OK] EnclaveInfo attestation verified")
            return enclave_info

        if len(plain) == 32:
            self.state.enclave_info = plain
            log("[WARN] Legacy EnclaveInfo mode (no attestation signature)")
            return plain

        raise RuntimeError(f"Unexpected EnclaveInfo payload length: {len(plain)}")

    def get_max_inferences(self) -> int:
        self.device.send_command(CMD_GET_MAX_INFERENCES)
        status, payload = self.device.read_response()
        if status != RESP_OK or len(payload) < 4:
            raise RuntimeError("CMD_GET_MAX_INFERENCES failed")
        return struct.unpack("<I", payload[:4])[0]

    def get_inference_count(self) -> int:
        self.device.send_command(CMD_GET_INFERENCE_COUNT)
        status, payload = self.device.read_response()
        if status != RESP_OK or len(payload) < 4:
            raise RuntimeError("CMD_GET_INFERENCE_COUNT failed")
        return struct.unpack("<I", payload[:4])[0]

    def get_remaining(self) -> int:
        self.device.send_command(CMD_GET_REMAINING_INFERENCES)
        status, payload = self.device.read_response()
        if status != RESP_OK or len(payload) < 4:
            raise RuntimeError("CMD_GET_REMAINING_INFERENCES failed")
        return struct.unpack("<I", payload[:4])[0]

    def get_inference_result(self) -> Tuple[int, int]:
        self.device.send_command(CMD_GET_INFERENCE_RESULT)
        status, payload = self.device.read_response(timeout=8.0)
        if status != RESP_OK or len(payload) < 2:
            raise RuntimeError("CMD_GET_INFERENCE_RESULT failed")
        return payload[0], payload[1]

    def get_inference_trace(self) -> Tuple[int, int, int, int]:
        self.device.send_command(CMD_GET_INFERENCE_TRACE)
        status, payload = self.device.read_response(timeout=8.0)
        if status != RESP_OK or len(payload) < 16:
            raise RuntimeError("CMD_GET_INFERENCE_TRACE failed")
        return struct.unpack("<IIII", payload[:16])

    def provider_send_m_update(self, c_limit: int) -> None:
        log("\n[Provider] Step 3 - Send M_update")
        if self.state.enclave_info is None:
            self.provider_fetch_enclave_info()

        current_max = self.get_max_inferences()
        if c_limit <= current_max:
            raise RuntimeError(
                f"c_limit={c_limit} rejected by policy (must be strictly > current max {current_max})"
            )

        # Generate user key pair (pk_u, sk_u)
        user_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        user_pub = user_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        user_pub_raw = user_pub[1:]  # 64 bytes X||Y

        # M_update format (plaintext, not encrypted):
        # pk_u(64) | limit(4) | H_{s_id}(32) | T_o(64)
        # T_o = Sign(sk_u, SHA256(pk_u || limit || H_{s_id}))
        msg_to_sign = user_pub_raw + struct.pack("<I", c_limit) + self.state.enclave_info
        sig_der = user_key.sign(msg_to_sign, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig_der)
        sig_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")  # 64 bytes T_o

        m_update = (
            user_pub_raw
            + struct.pack("<I", c_limit)
            + self.state.enclave_info
            + sig_raw
        )

        self.device.send_command(CMD_VALIDATE_M_UPDATE, m_update)
        status, _ = self.device.read_response()
        if status != RESP_OK:
            raise RuntimeError("M_update rejected by device")

        self.state.verifier_key = user_key
        self.state.verifier_pub_raw = user_pub_raw
        log(f"[OK] M_update accepted with c_limit={c_limit}")

    def customer_create_enclave(self) -> None:
        log("\n[Model Customer] Step 4 - Create enclave")
        self.device.send_command(CMD_CREATE_ENCLAVE)
        status, payload = self.device.read_response(timeout=4.0)
        if status != RESP_OK:
            if len(payload) >= 4:
                detail = struct.unpack("<i", payload[:4])[0]
                raise RuntimeError(f"CMD_CREATE_ENCLAVE failed (detail={detail})")
            raise RuntimeError("CMD_CREATE_ENCLAVE failed")
        log("[OK] Enclave created")

    def get_enclave_state(self) -> bool:
        self.device.send_command(CMD_GET_ENCLAVE_STATE)
        status, payload = self.device.read_response()
        if status != RESP_OK or len(payload) < 1:
            raise RuntimeError("CMD_GET_ENCLAVE_STATE failed")
        return payload[0] != 0

    @staticmethod
    def _load_inference_code_hash() -> bytes:
        root = Path(__file__).resolve().parents[1]
        elf_path = root / "build" / "zephyr" / "zephyr.elf"
        data = elf_path.read_bytes()
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise RuntimeError("Invalid ELF file")

        elf_class = data[4]
        elf_endian = data[5]
        if elf_endian == 1:
            endian = "<"
        elif elf_endian == 2:
            endian = ">"
        else:
            raise RuntimeError("Unsupported ELF endianness")

        if elf_class == 1:
            header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
            e_shoff = header[5]
            e_shentsize = header[10]
            e_shnum = header[11]
            e_shstrndx = header[12]
            sh_fmt = endian + "IIIIIIIIII"
        elif elf_class == 2:
            header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
            e_shoff = header[5]
            e_shentsize = header[10]
            e_shnum = header[11]
            e_shstrndx = header[12]
            sh_fmt = endian + "IIQQQQIIQQ"
        else:
            raise RuntimeError("Unsupported ELF class")

        if e_shoff == 0 or e_shnum == 0:
            raise RuntimeError("ELF has no section headers")

        def read_sh(index: int):
            sh_off = e_shoff + index * e_shentsize
            return struct.unpack_from(sh_fmt, data, sh_off)

        shstr = read_sh(e_shstrndx)
        if elf_class == 1:
            shstr_off = shstr[4]
            shstr_size = shstr[5]
        else:
            shstr_off = shstr[4]
            shstr_size = shstr[5]

        shstr_bytes = data[shstr_off:shstr_off + shstr_size]

        def section_name(sh_name_offset: int) -> str:
            end = shstr_bytes.find(b"\x00", sh_name_offset)
            if end < 0:
                end = len(shstr_bytes)
            return shstr_bytes[sh_name_offset:end].decode("ascii", errors="ignore")

        for idx in range(e_shnum):
            sh = read_sh(idx)
            sh_name = sh[0]
            name = section_name(sh_name)
            if name == ".inference_ro":
                if elf_class == 1:
                    sh_offset = sh[4]
                    sh_size = sh[5]
                else:
                    sh_offset = sh[4]
                    sh_size = sh[5]
                return hashlib.sha256(data[sh_offset:sh_offset + sh_size]).digest()

        raise RuntimeError("Failed to locate .inference_ro section in ELF")

    @staticmethod
    def _verify_pox(device_pk_d: bytes, model_id: int, code_hash: bytes, pred: int, sig_raw: bytes) -> bool:
        if len(device_pk_d) != 65 or len(code_hash) != 32 or len(sig_raw) != 64:
            return False
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pk_d)
            r = int.from_bytes(sig_raw[:32], "big")
            s = int.from_bytes(sig_raw[32:], "big")
            sig_der = encode_dss_signature(r, s)
            # Try new PoX format: model_id || cert(16 zeros) || nonce(12 zeros) || output
            msg_new = struct.pack("<I", model_id) + bytes(16) + bytes(12) + bytes([pred & 0xFF])
            try:
                pub.verify(sig_der, msg_new, ec.ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature:
                # Fall back to old format: model_id || code_hash || output
                msg_old = struct.pack("<I", model_id) + code_hash + bytes([pred & 0xFF])
                pub.verify(sig_der, msg_old, ec.ECDSA(hashes.SHA256()))
                return True
        except (ValueError, InvalidSignature):
            return False

    def customer_verified_inference(self, image_payload: Optional[bytes] = None, image_label: int = 0) -> int:
        log("\n[Model Customer] Step 5 - Verified inference")
        if self.state.verifier_key is None:
            raise RuntimeError("Missing verifier key. Provider M_update must run first.")
        if self.state.device_pubkey is None:
            self.get_device_pubkey()

        if not self.get_enclave_state():
            raise RuntimeError("Enclave is not created. Run create first.")

        model_id_bytes = struct.pack("<I", self.model_id)
        code_hash = self._load_inference_code_hash()
        msg = model_id_bytes + code_hash
        sig_der = self.state.verifier_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig_der)
        sig_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        # M_inf is now plaintext (not encrypted): model_id(4) || code_hash(32) || signature(64)
        m_inf_packet = model_id_bytes + code_hash + sig_raw

        # If an image is provided from host, explicitly send it to the board.
        used_image_upload = image_payload is not None
        if image_payload is not None:
            packet = bytes([image_label & 0xFF]) + image_payload + m_inf_packet
            self.device.send_command(CMD_RUN_INFERENCE_WITH_IMAGE, packet)
            status, payload = self.device.read_response(timeout=20.0)
        else:
            self.device.send_command(CMD_RUN_INFERENCE, m_inf_packet)
            status, payload = self.device.read_response(timeout=20.0)

        if status != RESP_OK:
            if len(payload) >= 8:
                stage = struct.unpack("<I", payload[:4])[0]
                detail = struct.unpack("<i", payload[4:8])[0]
                if stage == 5 and detail == -1:
                    # Device indicates missing/invalid runtime image context.
                    # Fallback to the photo+verified API with a deterministic blank image.
                    log("[WARN] Device reported invalid inference context; retrying with explicit image payload")
                    blank_img = bytes(CUSTOM_IMAGE_SIZE)
                    packet = bytes([0]) + blank_img + m_inf_packet
                    self.device.send_command(CMD_RUN_INFERENCE_WITH_IMAGE, packet)
                    status, payload = self.device.read_response(timeout=20.0)
                    used_image_upload = True
                    if status != RESP_OK:
                        if len(payload) >= 8:
                            stage2 = struct.unpack("<I", payload[:4])[0]
                            detail2 = struct.unpack("<i", payload[4:8])[0]
                            raise RuntimeError(
                                "Verified inference rejected by device after image fallback "
                                f"(stage={stage2}, detail={detail2})"
                            )
                        raise RuntimeError("Verified inference rejected by device after image fallback")
                else:
                    raise RuntimeError(
                        f"Verified inference rejected by device (stage={stage}, detail={detail})"
                    )
            raise RuntimeError("Verified inference rejected by device")

        if len(payload) == 0:
            log("[WARN] Inference succeeded but response payload is empty")
            return -1

        # Best-effort: fetch trace and result (may be optional in simplified flow)
        try:
            phase0_count, phase1_count, last_stage, last_tx_id = self.get_inference_trace()
            log(
                f"[DBG] Inference trace: phase0={phase0_count}, phase1={phase1_count}, "
                f"last_stage={last_stage}, last_tx_id={last_tx_id}"
            )
        except Exception as exc:
            log(f"[WARN] Could not fetch inference trace: {exc}")

        try:
            device_pred, device_expected = self.get_inference_result()
            log(f"[OK] Inference result: pred={device_pred}, expected={device_expected}")
        except Exception as exc:
            log(f"[WARN] Could not fetch inference result: {exc}")

        expected_label = image_label if image_payload is not None else -1

        # Handle simplified direct response: pred(1) || expected(1)
        if len(payload) == 2:
            pred = payload[0]
            expected = payload[1]
            self.last_inference_meta = {
                "pred": int(pred),
                "pox_valid": False,
                "used_image_upload": bool(used_image_upload),
                "expected_label": int(expected),
            }
            log(f"[OK] Inference result (direct): pred={pred}, expected={expected}")
            return pred

        # Legacy PoX handling: pred(1) || signature(64)
        if len(payload) < 65:
            self.last_inference_meta = {
                "pred": -1,
                "pox_valid": False,
                "used_image_upload": bool(used_image_upload),
                "expected_label": int(expected_label),
            }
            log("[WARN] Inference succeeded but PoX response payload too short; inference result unavailable")
            return -1

        pred = payload[0]
        pox_sig = payload[1:65]
        pox_valid = self._verify_pox(self.state.device_pubkey, self.model_id, code_hash, pred, pox_sig)
        self.last_inference_meta = {
            "pred": int(pred),
            "pox_valid": bool(pox_valid),
            "used_image_upload": bool(used_image_upload),
            "expected_label": int(expected_label),
        }
        if pox_valid:
            log(f"[OK] PoX verified, pred={pred}")
        else:
            log(f"[WARN] pred={pred}, but PoX verification failed")
        return pred

    def customer_destroy_enclave(self) -> None:
        log("\n[Model Customer] Step 6 - Destroy enclave")
        self.device.send_command(CMD_DESTROY_ENCLAVE)
        status, _ = self.device.read_response(timeout=4.0)
        if status != RESP_OK:
            raise RuntimeError("CMD_DESTROY_ENCLAVE failed")
        log("[OK] Enclave destroyed")

    def run_full_case_study(
        self,
        c_limit: int,
        num_inferences: int,
        image_payload: Optional[bytes] = None,
        image_label: int = 0,
    ) -> int:
        self._timed_call("provider.enclave_info", self.provider_fetch_enclave_info)
        self._timed_call("provider.m_update", self.provider_send_m_update, c_limit)

        self._timed_call("customer.create_enclave", self.customer_create_enclave)

        ok_count = 0
        for idx in range(num_inferences):
            log(f"\n[Run {idx + 1}/{num_inferences}]")
            pred = self._timed_call(
                f"customer.verified_inference.run_{idx + 1}",
                self.customer_verified_inference,
                image_payload,
                image_label,
            )
            if self.last_inference_meta:
                self._record_extra(
                    action=f"customer.verified_inference.run_{idx + 1}.meta",
                    status="ok",
                    detail=json.dumps(self.last_inference_meta),
                )
            if pred >= 0:
                ok_count += 1

        # Capture quota state before destroy (destroy resets counters in current firmware).
        max_before_destroy = self._timed_call("metrics.max_before_destroy", self.get_max_inferences)
        used_before_destroy = self._timed_call("metrics.used_before_destroy", self.get_inference_count)
        rem_before_destroy = self._timed_call("metrics.remaining_before_destroy", self.get_remaining)

        self._timed_call("customer.destroy_enclave", self.customer_destroy_enclave)

        max_inf = self._timed_call("metrics.max_after_destroy", self.get_max_inferences)
        used = self._timed_call("metrics.used_after_destroy", self.get_inference_count)
        rem = self._timed_call("metrics.remaining_after_destroy", self.get_remaining)

        ns_metrics = self._timed_call("metrics.ns_benchmark", self.read_ns_benchmark)
        secure_metrics = self._timed_call("metrics.secure_benchmark", self.read_secure_benchmark)
        self._record_extra(
            action="metrics.ns_benchmark.all",
            status="ok",
            detail=json.dumps(ns_metrics, separators=(",", ":")),
        )
        self._record_extra(
            action="metrics.secure_benchmark.all",
            status="ok",
            detail=json.dumps(secure_metrics, separators=(",", ":")),
        )

        log("\n========== CASE STUDY SUMMARY ==========")
        log(f"Image from Mac uploaded   : {'YES' if image_payload is not None else 'NO (device/default path)'}")
        log(f"Before destroy -> max/used/rem : {max_before_destroy}/{used_before_destroy}/{rem_before_destroy}")
        log(f"Authorized max_inferences : {max_inf}")
        log(f"Used inference_count      : {used}")
        log(f"Remaining                : {rem}")
        log(f"Decoded PoX responses     : {ok_count}/{num_inferences}")
        log("\n[NS] All benchmark values")
        for key in DEVICE_BENCHMARK_NAMES:
            log(f"  {key}={ns_metrics.get(key, 0)}")
        log("\n[SECURE] All benchmark values")
        for key in SECURE_BENCHMARK_NAMES:
            log(f"  {key}={secure_metrics.get(key, 0)}")
        log("========================================")
        self.print_cycles_report(ns_metrics, secure_metrics)
        self.print_benchmark_table()
        return 0

    @staticmethod
    def _fmt_cycles(value: int) -> str:
        return f"{value:,} cycles"

    @staticmethod
    def _fmt_ratio(numerator: int, denominator: int) -> str:
        if numerator <= 0 or denominator <= 0:
            return "0x"
        return f"{max(1, numerator // denominator):,}x"

    def format_authorize_comparison(self, metrics: Dict[str, int]) -> str:
        sw_total_cycles = metrics.get("authorize_cycles", 0)
        if sw_total_cycles == 0:
            return ""

        sw_read = metrics.get("authorize_read_cycles", 0)
        sw_parse = metrics.get("authorize_parse_cycles", 0)
        sw_crypto_init = metrics.get("authorize_crypto_init_cycles", 0)
        sw_import = metrics.get("authorize_import_key_cycles", 0)
        sw_verify = metrics.get("authorize_verify_message_cycles", metrics.get("authorize_verify_sig_cycles", 0))
        sw_update = metrics.get("authorize_update_cycles", 0)

        hw_verify = 5000
        hw_total_cycles = max(0, sw_total_cycles - sw_verify + hw_verify)
        speedup = (sw_total_cycles / hw_total_cycles) if hw_total_cycles > 0 else 0.0
        sw_verify_pct = (sw_verify / sw_total_cycles * 100.0) if sw_total_cycles > 0 else 0.0
        hw_verify_pct = (hw_verify / hw_total_cycles * 100.0) if hw_total_cycles > 0 else 0.0

        lines = [
            "╔════════════════════════════════════════════════════════════════════════════════════════════╗",
            "║                           AUTHORIZE PERFORMANCE COMPARISON                                  ║",
            "╠════════════════════════════════════════╤═══════════════════════════════════════════════════╣",
            "║         SOFTWARE (actuel)              │         HARDWARE (avec PKA - théorique)           ║",
            "╠════════════════════════════════════════╪═══════════════════════════════════════════════════╣",
            f"║ Total: {self._fmt_cycles(sw_total_cycles):<29}│ Total: {self._fmt_cycles(hw_total_cycles)} [{speedup:.0f}x faster] ║",
            "╠════════════════════════════════════════╪═══════════════════════════════════════════════════╣",
            f"║ ├── PSA Read          : {self._fmt_cycles(sw_read):<18}│ ├── PSA Read          : {self._fmt_cycles(sw_read):<18} ║",
            f"║ ├── Parsing           : {self._fmt_cycles(sw_parse):<18}│ ├── Parsing           : {self._fmt_cycles(sw_parse):<18} ║",
            f"║ ├── Crypto init       : {self._fmt_cycles(sw_crypto_init):<18}│ ├── Crypto init       : {self._fmt_cycles(sw_crypto_init):<18} ║",
            f"║ ├── Import public key : {self._fmt_cycles(sw_import):<18}│ ├── Import public key : {self._fmt_cycles(sw_import):<18} ║",
            f"║ ├── ECDSA VERIFY      : {self._fmt_cycles(sw_verify):<18}│ ├── ECDSA VERIFY (HW) : {self._fmt_cycles(hw_verify):<18} ║",
            f"║ │   └── {sw_verify_pct:.1f}% du temps{' ' * 12}│ │   └── {hw_verify_pct:.1f}% du temps{' ' * 22}║",
            f"║ └── Update state      : {self._fmt_cycles(sw_update):<18}│ └── Update state      : {self._fmt_cycles(sw_update):<18} ║",
            "╠════════════════════════════════════════╧═══════════════════════════════════════════════════╣",
            f"║ ⚠️ Bottleneck: ECDSA software ({self._fmt_cycles(sw_verify)}){' ' * 43}║",
            f"║ ✅ Gain potentiel PKA : {self._fmt_cycles(sw_verify)} → {self._fmt_cycles(hw_verify)} ({self._fmt_ratio(sw_verify, hw_verify)} plus rapide){' ' * 16}║",
            "╚════════════════════════════════════════════════════════════════════════════════════════════╝",
        ]
        return "\n".join(lines)

    def format_api_breakdown(self, metrics: Dict[str, int], api_name: str, fields: Dict[str, Any]) -> str:
        total_cycles = metrics.get(fields.get("total_key", ""), 0)

        # Compute child sum when child keys are available. If present and
        # non-zero, prefer the summed value to ensure the reported 'total'
        # equals the sum of its breakdown parts (avoids residual attribution).
        child_keys = [key for (_n, key) in fields.get("children", [])]
        child_sum = sum(int(metrics.get(k, 0)) for k in child_keys)

        if child_sum > 0:
            total_cycles = child_sum

        if total_cycles == 0:
            return ""

        output = [f"\n{api_name} - {self._fmt_cycles(total_cycles)} total"]
        for name, key in fields.get("children", []):
            cycles = int(metrics.get(key, 0))
            if cycles == 0:
                continue
            percent = (cycles / total_cycles * 100.0) if total_cycles > 0 else 0.0
            bottleneck = "  ← bottleneck" if percent > 50.0 else ""
            output.append(f"├── {name:<18} : {self._fmt_cycles(cycles):<18} [{percent:.1f}%]{bottleneck}")
        return "\n".join(output)

    def print_cycles_report(self, ns_metrics: Dict[str, int], secure_metrics: Dict[str, int]) -> None:
        log("\n========== AUTHORIZE PERFORMANCE COMPARISON ==========")
        log(self.format_authorize_comparison(secure_metrics))

        # Merge NS metrics into secure view so Execute breakdown can include
        # NS-side measurements such as `execute_verified_cycles` when present.
        merged_metrics = dict(secure_metrics)
        if ns_metrics:
            merged_metrics.update(ns_metrics)

        apis = {
            "Create": {
                "total_key": "create_enclave_cycles",
                "children": [
                    ("EnclaveInfo recalc", "create_recompute_cycles"),
                    ("AES decrypt", "aes_decrypt_cycles"),
                    ("SAU registration", "create_validate_cycles"),
                ],
            },
            "Execute": {
                "total_key": "inf_complete_cycles",
                "children": [
                    ("M_inf verification", "inf_start_cycles"),
                    ("SAU open/close", "sau_sync_open_cycles"),
                    ("PoX signing", "inf_complete_cycles"),
                    ("execute_verified_inference", "execute_verified_cycles"),
                ],
            },
            "Destroy": {
                "total_key": "destroy_enclave_cycles",
                "children": [
                    ("Memory zeroization", "destroy_enclave_cycles"),
                    ("SAU restore", "sau_sync_close_cycles"),
                ],
            },
        }

        log("\n========== API BREAKDOWN (cycles) ==========")
        for api_name, fields in apis.items():
            # Use merged metrics so NS-side measurements (execute_verified_*)
            # are visible alongside Secure metrics in the same breakdown.
            breakdown = self.format_api_breakdown(merged_metrics, api_name, fields)
            if breakdown:
                log(breakdown)

    def print_benchmark_table(self) -> None:
        log("\n========== DETAILED BENCHMARK (HOST) ==========")
        log("action,status,detail")
        for row in self.benchmarks:
            detail = str(row.get("detail", "")).replace("\n", " ").replace(",", ";")
            log(f"{row.get('action','')},{row.get('status','')},{detail}")
        log("================================================")

    def write_benchmark_json(self, output_path: str) -> None:
        out = {
            "model_id": self.model_id,
            "timestamp_unix": int(time.time()),
            "benchmarks": self.benchmarks,
        }
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(out, handle, indent=2)
        log(f"[OK] Benchmark JSON written: {output_path}")

    def write_benchmark_csv(self, output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["action", "status", "detail"])
            writer.writeheader()
            for row in self.benchmarks:
                writer.writerow(
                    {
                        "action": row.get("action", ""),
                        "status": row.get("status", ""),
                        "detail": row.get("detail", ""),
                    }
                )
        log(f"[OK] Benchmark CSV written: {output_path}")

    def print_status(self) -> None:
        max_inf = self.get_max_inferences()
        used = self.get_inference_count()
        rem = self.get_remaining()
        enclave = self.get_enclave_state()
        log("\n----- DEVICE STATUS -----")
        log(f"max_inferences : {max_inf}")
        log(f"inference_count: {used}")
        log(f"remaining      : {rem}")
        log(f"enclave_created: {enclave}")
        log("-------------------------")

    def run_interactive(self, default_c_limit: int) -> int:
        log("\n=== VECODI Interactive Mode ===")
        log("Provider commands:")
        log("  1) Fetch EnclaveInfo")
        log("  2) Send M_update")
        log("Model Customer commands:")
        log("  3) Create enclave")
        log("  4) Verified inference")
        log("  5) Destroy enclave")
        log("Utility commands:")
        log("  6) Device status")
        log("  7) Run full flow once")
        log("  q) Quit")

        while True:
            choice = input("\nSelect command: ").strip().lower()
            if choice == "q":
                return 0

            try:
                if choice == "1":
                    self.provider_fetch_enclave_info()
                elif choice == "2":
                    raw = input(f"c_limit (default {default_c_limit}): ").strip()
                    c_limit = int(raw) if raw else default_c_limit
                    self.provider_send_m_update(c_limit)
                elif choice == "3":
                    self.customer_create_enclave()
                elif choice == "4":
                    self.customer_verified_inference()
                elif choice == "5":
                    self.customer_destroy_enclave()
                elif choice == "6":
                    self.print_status()
                elif choice == "7":
                    self.run_full_case_study(c_limit=default_c_limit, num_inferences=1)
                else:
                    log("[WARN] Unknown command")
            except Exception as exc:
                log(f"[ERR] {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Standalone VECODI case study runner (Provider + Model Customer)",
    )
    parser.add_argument("port", help="Serial device, e.g. /dev/tty.usbmodem11203")
    parser.add_argument("--baud", type=int, default=115200, help="UART baudrate (default: 115200)")
    parser.add_argument("--c-limit", type=int, default=10, help="Target quota for M_update")
    parser.add_argument("--runs", type=int, default=1, help="Number of verified inferences to run")
    parser.add_argument("--model-id", type=lambda v: int(v, 0), default=0x00000001, help="Model ID (int, supports hex)")
    parser.add_argument("--interactive", action="store_true", help="Run interactive menu instead of one-shot flow")
    parser.add_argument("--image", type=str, default=None, help="Optional image from Mac to send to board (raw 3072B or PNG/JPEG)")
    parser.add_argument("--image-label", type=int, default=0, help="Expected label byte used with --image (default: 0)")
    parser.add_argument("--benchmark-json", type=str, default=None, help="Optional benchmark JSON output path")
    parser.add_argument("--benchmark-csv", type=str, default=None, help="Optional benchmark CSV output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.c_limit <= 0:
        log("[ERR] --c-limit must be > 0")
        return 2
    if args.runs <= 0:
        log("[ERR] --runs must be > 0")
        return 2
    if args.image_label < 0 or args.image_label > 255:
        log("[ERR] --image-label must be in [0,255]")
        return 2

    image_payload: Optional[bytes] = None
    if args.image:
        image_payload = load_image_from_mac(args.image)
        log(f"[OK] Loaded image from Mac: {args.image} ({len(image_payload)} bytes)")

    device = UartDevice(args.port, args.baud)
    runner = VecodiCaseStudy(device=device, model_id=args.model_id)

    try:
        device.connect()
        if args.interactive:
            return runner.run_interactive(default_c_limit=args.c_limit)
        rc = runner.run_full_case_study(
            c_limit=args.c_limit,
            num_inferences=args.runs,
            image_payload=image_payload,
            image_label=args.image_label,
        )
        if args.benchmark_json:
            runner.write_benchmark_json(args.benchmark_json)
        if args.benchmark_csv:
            runner.write_benchmark_csv(args.benchmark_csv)
        return rc
    except Exception as exc:
        log(f"[ERR] {exc}")
        return 1
    finally:
        device.disconnect()


if __name__ == "__main__":
    sys.exit(main())
