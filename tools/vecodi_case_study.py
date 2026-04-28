#!/usr/bin/env python3
"""
Standalone VECODI case study runner.

This script is intentionally self-contained so it still works even if mac_provider.py
or other helper scripts are removed.

Flow implemented:
  Provider identity:
    1) ECDH handshake
    2) EnclaveInfo attestation fetch/verification
    3) M_update send (strictly increasing c_limit)

  Model Customer identity:
    4) Create enclave
    5) Run verified inference N times
    6) Destroy enclave
"""

import argparse
import csv
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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
CMD_ECDH_HANDSHAKE = 0x07
CMD_GET_DEVICE_PUBKEY = 0x0C
CMD_GET_ENCLAVE_STATE = 0x10
CMD_CREATE_ENCLAVE = 0x11
CMD_DESTROY_ENCLAVE = 0x12
CMD_RUN_INFERENCE_WITH_IMAGE = 0x14

RESP_OK = 0x00
CUSTOM_IMAGE_SIZE = 32 * 32 * 3


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
    session_key: Optional[bytes] = None
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
        # 20 bytes certificate placeholder used in existing flow: model_id(4 LE)+16B payload
        self.cert = struct.pack("<I", model_id) + bytes(range(16))

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
            duration_ms = (time.perf_counter() - start) * 1000.0
            self.benchmarks.append(
                {
                    "action": action,
                    "status": status,
                    "duration_ms": round(duration_ms, 3),
                    "detail": detail,
                }
            )

    def _record_extra(self, action: str, **fields: Any) -> None:
        self.benchmarks.append({"action": action, **fields})

    def _require_session_key(self) -> bytes:
        if self.state.session_key is None:
            raise RuntimeError("No dynamic session key. Run ECDH first.")
        return self.state.session_key

    def _encrypt(self, plaintext: bytes) -> bytes:
        key = self._require_session_key()
        nonce = os.urandom(12)
        ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
        return nonce + ct_tag

    def _decrypt(self, payload: bytes) -> Optional[bytes]:
        if self.state.session_key is None or len(payload) < 28:
            return None
        nonce = payload[:12]
        ct_tag = payload[12:]
        try:
            return AESGCM(self.state.session_key).decrypt(nonce, ct_tag, None)
        except Exception:
            return None

    def provider_ecdh_handshake(self) -> None:
        log("\n[Provider] Step 1 - ECDH handshake")
        mac_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        mac_public = mac_private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        self.device.send_command(CMD_ECDH_HANDSHAKE, mac_public)
        status, payload = self.device.read_response(timeout=8.0)
        if status != RESP_OK or len(payload) != 65:
            raise RuntimeError("ECDH failed: invalid device public key response")

        device_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), payload)
        shared_secret = mac_private.exchange(ec.ECDH(), device_public)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"uart_protocol_v1_salt",
            info=b"uart_protocol_v1_session_key",
            backend=default_backend(),
        )
        self.state.session_key = hkdf.derive(shared_secret)
        log("[OK] ECDH session key established")

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

    def provider_send_m_update(self, c_limit: int) -> None:
        log("\n[Provider] Step 3 - Send M_update")
        if self.state.enclave_info is None:
            self.provider_fetch_enclave_info()

        current_max = self.get_max_inferences()
        if c_limit <= current_max:
            raise RuntimeError(
                f"c_limit={c_limit} rejected by policy (must be strictly > current max {current_max})"
            )

        verifier_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        verifier_pub = verifier_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        verifier_pub_raw = verifier_pub[1:]  # 64 bytes X||Y

        plaintext = (
            struct.pack("<I", c_limit)
            + verifier_pub_raw
            + self.state.enclave_info
            + struct.pack("<I", len(self.cert))
            + self.cert
        )
        packet = self._encrypt(plaintext)

        self.device.send_command(CMD_VALIDATE_M_UPDATE, packet)
        status, _ = self.device.read_response()
        if status != RESP_OK:
            raise RuntimeError("M_update rejected by device")

        self.state.verifier_key = verifier_key
        self.state.verifier_pub_raw = verifier_pub_raw
        log(f"[OK] M_update accepted with c_limit={c_limit}")

    def customer_create_enclave(self) -> None:
        log("\n[Model Customer] Step 4 - Create enclave")
        self.device.send_command(CMD_CREATE_ENCLAVE)
        status, _ = self.device.read_response(timeout=4.0)
        if status != RESP_OK:
            raise RuntimeError("CMD_CREATE_ENCLAVE failed")
        log("[OK] Enclave created")

    def get_enclave_state(self) -> bool:
        self.device.send_command(CMD_GET_ENCLAVE_STATE)
        status, payload = self.device.read_response()
        if status != RESP_OK or len(payload) < 1:
            raise RuntimeError("CMD_GET_ENCLAVE_STATE failed")
        return payload[0] != 0

    @staticmethod
    def _verify_pox(device_pk_d: bytes, model_id: int, cert: bytes, nonce_inf: bytes, pred: int, sig_raw: bytes) -> bool:
        if len(device_pk_d) != 65 or len(nonce_inf) != 32 or len(sig_raw) != 64:
            return False
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pk_d)
            r = int.from_bytes(sig_raw[:32], "big")
            s = int.from_bytes(sig_raw[32:], "big")
            sig_der = encode_dss_signature(r, s)
            msg = struct.pack("<I", model_id) + cert + nonce_inf + bytes([pred & 0xFF])
            pub.verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))
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

        nonce_inf = os.urandom(32)
        model_id_bytes = struct.pack("<I", self.model_id)
        msg = nonce_inf + model_id_bytes
        sig_der = self.state.verifier_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig_der)
        sig_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        m_inf_plain = nonce_inf + model_id_bytes + sig_raw
        m_inf_packet = self._encrypt(m_inf_plain)

        # If an image is provided from host, explicitly send it to the board.
        used_image_upload = image_payload is not None
        if image_payload is not None:
            packet = bytes([image_label & 0xFF]) + image_payload + m_inf_packet
            self.device.send_command(CMD_RUN_INFERENCE_WITH_IMAGE, packet)
            status, payload = self.device.read_response(timeout=12.0)
        else:
            self.device.send_command(CMD_RUN_INFERENCE, m_inf_packet)
            status, payload = self.device.read_response(timeout=8.0)

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
                    status, payload = self.device.read_response(timeout=12.0)
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

        dec = self._decrypt(payload)
        if dec is None or len(dec) < 65:
            log("[WARN] Inference succeeded but encrypted PoX response could not be decoded")
            return -1

        pred = dec[0]
        pox_sig = dec[1:65]
        pox_valid = self._verify_pox(self.state.device_pubkey, self.model_id, self.cert, nonce_inf, pred, pox_sig)
        self.last_inference_meta = {
            "pred": int(pred),
            "pox_valid": bool(pox_valid),
            "used_image_upload": bool(used_image_upload),
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
        self._timed_call("provider.ecdh", self.provider_ecdh_handshake)
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
                    duration_ms=0.0,
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

        log("\n========== CASE STUDY SUMMARY ==========")
        log(f"Image from Mac uploaded   : {'YES' if image_payload is not None else 'NO (device/default path)'}")
        log(f"Before destroy -> max/used/rem : {max_before_destroy}/{used_before_destroy}/{rem_before_destroy}")
        log(f"Authorized max_inferences : {max_inf}")
        log(f"Used inference_count      : {used}")
        log(f"Remaining                : {rem}")
        log(f"Decoded PoX responses     : {ok_count}/{num_inferences}")
        log("========================================")
        self.print_benchmark_table()
        return 0

    def print_benchmark_table(self) -> None:
        log("\n========== DETAILED BENCHMARK (HOST) ==========")
        log("action,status,duration_ms,detail")
        for row in self.benchmarks:
            detail = str(row.get("detail", "")).replace("\n", " ").replace(",", ";")
            log(f"{row.get('action','')},{row.get('status','')},{row.get('duration_ms',0.0)},{detail}")
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
            writer = csv.DictWriter(handle, fieldnames=["action", "status", "duration_ms", "detail"])
            writer.writeheader()
            for row in self.benchmarks:
                writer.writerow(
                    {
                        "action": row.get("action", ""),
                        "status": row.get("status", ""),
                        "duration_ms": row.get("duration_ms", 0.0),
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
        log("  1) ECDH handshake")
        log("  2) Fetch EnclaveInfo")
        log("  3) Send M_update")
        log("Model Customer commands:")
        log("  4) Create enclave")
        log("  5) Verified inference")
        log("  6) Destroy enclave")
        log("Utility commands:")
        log("  7) Device status")
        log("  8) Run full flow once")
        log("  q) Quit")

        while True:
            choice = input("\nSelect command: ").strip().lower()
            if choice == "q":
                return 0

            try:
                if choice == "1":
                    self.provider_ecdh_handshake()
                elif choice == "2":
                    self.provider_fetch_enclave_info()
                elif choice == "3":
                    raw = input(f"c_limit (default {default_c_limit}): ").strip()
                    c_limit = int(raw) if raw else default_c_limit
                    self.provider_send_m_update(c_limit)
                elif choice == "4":
                    self.customer_create_enclave()
                elif choice == "5":
                    self.customer_verified_inference()
                elif choice == "6":
                    self.customer_destroy_enclave()
                elif choice == "7":
                    self.print_status()
                elif choice == "8":
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
    if not args.interactive and not args.image:
        log("[ERR] Case-study mode requires --image (host Mac image upload is mandatory)")
        return 2
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
