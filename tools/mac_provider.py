#!/usr/bin/env python3
"""
Mac-side Provider/Verifier for Enclave Authorization Protocol

This script runs on the Mac and communicates with the STM32L552 device via USB serial.
It acts as the Model Provider, generating and sending M_update messages.

Usage:
    python3 mac_provider.py /dev/tty.usbmodem* 115200
"""

import serial
import sys
import time
import struct
import hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import os

# ========== HARDCODED KEYS (MUST MATCH DEVICE) ==========
# These keys must match the ones in provider_sim.cpp and dummy_partition.c

PROVIDER_SK = bytes([
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
])

PROVIDER_PK = bytes([
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60
])

VERIFIER_SK = bytes([
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
])

VERIFIER_PK = bytes([
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
    0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0
])

SESSION_KEY = bytes([
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
])

# Dynamic session key (set by ECDH handshake)
DYNAMIC_SESSION_KEY = None

# Protocol commands
CMD_COMPUTE_ENCLAVE_INFO = 0x01
CMD_VALIDATE_M_UPDATE = 0x02
CMD_GET_MAX_INFERENCES = 0x03
CMD_RUN_INFERENCE = 0x04
CMD_GET_INFERENCE_COUNT = 0x05
CMD_GET_REMAINING_INFERENCES = 0x06
CMD_ECDH_HANDSHAKE = 0x07
CMD_GET_BENCHMARK = 0x08
CMD_GET_SECURE_BENCHMARK = 0x09
CMD_GET_INFERENCE_RESULT = 0x0A
CMD_SET_MAX_INFERENCES = 0x0B
CMD_GET_DEVICE_PUBKEY = 0x0C
CMD_GET_SAU_STATE = 0x0D

# Response codes
RESP_OK = 0x00
RESP_ERROR = 0xFF

class STM32Device:
    """Communication with STM32L552 device via USB serial"""
    
    def __init__(self, port: str, baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self.ser = None
        
    def connect(self):
        """Establish serial connection"""
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=10.0,
                write_timeout=5.0
            )
            time.sleep(3)  # Wait for device reset
            print(f"✓ Connected to {self.port} at {self.baudrate} baud")
            
            # Flush any pending data
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            
            return True
        except serial.SerialException as e:
            print(f"✗ Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Close serial connection"""
        if self.ser and self.ser.is_open:
            self.ser.close()
            print("✓ Disconnected")
    
    def send_command(self, cmd: int, data: bytes = b"") -> bool:
        """Send command with length prefix"""
        if not self.ser or not self.ser.is_open:
            print("✗ Serial port not open")
            return False
        
        # Protocol: [CMD:1][LEN:4][DATA:n]
        packet = struct.pack('<BI', cmd, len(data)) + data
        
        try:
            # Flush any stale input before sending
            self.ser.reset_input_buffer()
            self.ser.write(packet)
            self.ser.flush()
            time.sleep(0.05)
            print(f"→ Sent command 0x{cmd:02X} ({len(data)} bytes data)")
            return True
        except serial.SerialException as e:
            print(f"✗ Send failed: {e}")
            return False
    
    def read_response(self, timeout: float = 5.0) -> Optional[Tuple[int, bytes]]:
        """Read response: [STATUS:1][LEN:4][DATA:n]"""
        if not self.ser or not self.ser.is_open:
            return None
        
        old_timeout = self.ser.timeout
        self.ser.timeout = timeout
        
        try:
            # Read status byte
            status_byte = self.ser.read(1)
            if len(status_byte) != 1:
                print("✗ Timeout reading status")
                return None
            
            status = struct.unpack('B', status_byte)[0]
            
            # Read length (4 bytes, little-endian)
            len_bytes = self.ser.read(4)
            if len(len_bytes) != 4:
                print("✗ Timeout reading length")
                return None
            
            data_len = struct.unpack('<I', len_bytes)[0]
            
            # Read data
            data = b""
            if data_len > 0:
                data = self.ser.read(data_len)
                if len(data) != data_len:
                    print(f"✗ Expected {data_len} bytes, got {len(data)}")
                    return None
            
            print(f"← Received status 0x{status:02X} ({data_len} bytes data)")
            return (status, data)
            
        except serial.SerialException as e:
            print(f"✗ Read failed: {e}")
            return None
        finally:
            self.ser.timeout = old_timeout
    
    def read_console_output(self, duration: float = 2.0):
        """Read and print device console output for debugging"""
        if not self.ser or not self.ser.is_open:
            return
        
        print("\n--- Device Console Output ---")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            if self.ser.in_waiting > 0:
                try:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        print(f"[DEVICE] {line}")
                except Exception as e:
                    pass
            time.sleep(0.1)
        
        print("--- End Console Output ---\n")

    def capture_console_output(self, duration: float = 2.0) -> list:
        """Capture console lines for a duration and return them."""
        lines = []
        if not self.ser or not self.ser.is_open:
            return lines

        end_time = time.time() + duration
        while time.time() < end_time:
            if self.ser.in_waiting > 0:
                try:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        lines.append(line)
                except Exception:
                    pass
            time.sleep(0.05)
        return lines


class ModelProvider:
    """Model Provider - generates M_update messages"""
    
    def __init__(self):
        self.session_key = SESSION_KEY
        self.verifier_pk = VERIFIER_PK
        
    def generate_m_update(
        self,
        c_limit: int,
        enclave_info: bytes,
        cert: bytes = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Generate M_update message
        
        Returns: (nonce, ciphertext, tag)
        """
        if cert is None:
            cert = bytes(range(16))  # Default test certificate
        
        # Use dynamic session key if available, otherwise fallback to static
        session_key = DYNAMIC_SESSION_KEY if DYNAMIC_SESSION_KEY is not None else self.session_key
        
        # Serialize plaintext: c_limit(4) || pk_v(64) || enclave_info(32) || cert_len(4) || cert(n)
        plaintext = struct.pack('<I', c_limit)  # c_limit
        plaintext += self.verifier_pk  # 64 bytes
        plaintext += enclave_info  # 32 bytes
        plaintext += struct.pack('<I', len(cert))  # cert_len
        plaintext += cert  # certificate
        
        print(f"\n[PROVIDER] Generating M_update:")
        print(f"  - c_limit: {c_limit}")
        print(f"  - plaintext size: {len(plaintext)} bytes")
        print(f"  - enclave_info: {enclave_info[:16].hex()}...")
        if DYNAMIC_SESSION_KEY is not None:
            print(f"  - Using ECDH-derived session key")
        else:
            print(f"  - Using static session key (fallback)")
        
        # Generate random nonce (12 bytes for GCM)
        nonce = os.urandom(12)
        print(f"  - nonce: {nonce.hex()}")
        
        # Encrypt with AES-256-GCM
        aesgcm = AESGCM(session_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        
        # Split ciphertext and tag (last 16 bytes)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        print(f"  - ciphertext size: {len(ciphertext)} bytes")
        print(f"  - tag: {tag.hex()}")
        
        return nonce, ciphertext, tag


def decrypt_response(session_key: bytes, enc_data: bytes):
    """AES-256-GCM decrypt a device response: nonce(12) || ciphertext+tag."""
    if len(enc_data) < 28:
        return None
    nonce = enc_data[:12]
    ct_tag = enc_data[12:]
    try:
        return AESGCM(session_key).decrypt(nonce, ct_tag, None)
    except Exception:
        return None


def encrypt_command(session_key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt a command payload: returns nonce(12) || ciphertext+tag."""
    nonce = os.urandom(12)
    ct_tag = AESGCM(session_key).encrypt(nonce, plaintext, None)
    return nonce + ct_tag


def print_menu():
    """Display interactive menu"""
    print("\n" + "="*74)
    print("  Mac Provider/Verifier - Manual Interactive Test Console")
    print("="*74)
    print("\n Session / auth:")
    print("  1) ECDH handshake (establish dynamic session key)")
    print("  2) Compute EnclaveInfo")
    print("  3) Send M_update (custom quota)")
    print("  4) Get device signing pubkey (pk_d)")
    print("\n Quota / counters:")
    print("  5) Get max inferences")
    print("  6) Set max inferences (manual override)")
    print("  7) Get inference count")
    print("  8) Get remaining inferences")
    print("\n Inference:")
    print("  9) Run inference (verified mode, encrypted M_inf)")
    print(" 10) Run inference (legacy mode, empty payload)")
    print(" 11) Get last inference result (pred/expected)")
    print("\n Bench / debug:")
    print(" 12) Get NS benchmark metrics")
    print(" 13) Get Secure benchmark metrics")
    print(" 14) Read console output")
    print(" 15) Memory protection feedback (deterministic SAU state)")
    print(" 16) Raw UART command (manual)")
    print(" 17) Session status")
    print("\n  q) Quit")
    print()


def parse_ns_benchmark(data: bytes):
    if len(data) < 72:
        print(f"  ✗ NS benchmark payload too short: {len(data)} B")
        return
    vals = struct.unpack('<18I', data[:72])
    print("  NS metrics:")
    print(f"    enclave_create_cycles:   {vals[0]}")
    print(f"    enclave_destroy_cycles:  {vals[1]}")
    print(f"    aes_decrypt_cycles:      {vals[2]}")
    print(f"    run_enclave_cycles:      {vals[8]}")
    print(f"    total_inference_cycles:  {vals[7]}")
    print(f"    inference_count:         {vals[16]}")
    print(f"    RAM used/total:          {vals[12]}/{vals[13]} B")
    print(f"    Flash used/total:        {vals[14]}/{vals[15]} B")


def parse_secure_benchmark(data: bytes):
    if len(data) < 88:
        print(f"  ✗ Secure benchmark payload too short: {len(data)} B")
        return
    vals = struct.unpack('<7Q4I4I', data[:88])
    print("  Secure metrics:")
    print(f"    aes_decrypt_cycles:      {vals[0]}")
    print(f"    late_hash_cycles:        {vals[1]}")
    print(f"    digest_compute_cycles:   {vals[2]}")
    print(f"    counter_ops:             {vals[10]}")
    print(f"    RAM used/total:          {vals[11]}/{vals[12]} B")
    print(f"    Flash used/total:        {vals[13]}/{vals[14]} B")


def decode_enclave_info(payload: bytes) -> Optional[bytes]:
    """Support both legacy plain(32B) and encrypted(60B) EnclaveInfo responses."""
    if len(payload) == 32:
        return payload
    if DYNAMIC_SESSION_KEY is not None:
        dec = decrypt_response(DYNAMIC_SESSION_KEY, payload)
        if dec and len(dec) == 32:
            return dec
    return None


def get_device_max_inferences(device: 'STM32Device') -> Optional[int]:
    """Fetch current max inference quota from device."""
    if not device.send_command(CMD_GET_MAX_INFERENCES):
        return None
    resp = device.read_response()
    if not resp or resp[0] != RESP_OK or len(resp[1]) < 4:
        return None
    return struct.unpack('<I', resp[1][:4])[0]


def perform_ecdh_handshake(device: 'STM32Device') -> bool:
    """
    Perform ECDH key exchange with device to establish dynamic session key
    
    Returns:
        True if handshake succeeded, False otherwise
    """
    global DYNAMIC_SESSION_KEY
    
    print("\n[9] Performing ECDH handshake...")
    
    # Generate ephemeral ECDH key pair (P-256)
    print("  - Generating Mac ephemeral key pair (P-256)...")
    mac_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    mac_public_key = mac_private_key.public_key()
    
    # Serialize Mac's public key (uncompressed format: 0x04 || x || y)
    mac_pubkey_bytes = mac_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    if len(mac_pubkey_bytes) != 65 or mac_pubkey_bytes[0] != 0x04:
        print("✗ Invalid public key format")
        return False
    
    print(f"  - Mac public key: {mac_pubkey_bytes[:16].hex()}... ({len(mac_pubkey_bytes)} bytes)")
    
    # Send Mac's public key to device
    print("  - Sending ECDH handshake command to device...")
    if not device.send_command(CMD_ECDH_HANDSHAKE, mac_pubkey_bytes):
        print("✗ Failed to send ECDH handshake")
        return False
    
    # Receive device's public key
    resp = device.read_response()
    if not resp or resp[0] != RESP_OK or len(resp[1]) != 65:
        print(f"✗ Invalid response from device (status={resp[0] if resp else 'timeout'}, len={len(resp[1]) if resp else 0})")
        return False
    
    device_pubkey_bytes = resp[1]
    print(f"  - Device public key: {device_pubkey_bytes[:16].hex()}... ({len(device_pubkey_bytes)} bytes)")
    
    # Reconstruct device's public key object
    try:
        device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), device_pubkey_bytes
        )
    except Exception as e:
        print(f"✗ Failed to decode device public key: {e}")
        return False
    
    # Perform ECDH key agreement to get shared secret
    print("  - Computing ECDH shared secret...")
    shared_secret = mac_private_key.exchange(ec.ECDH(), device_public_key)
    
    # Derive session key using HKDF-SHA256 (must match device)
    print("  - Deriving session key via HKDF-SHA256...")
    salt = b"uart_protocol_v1_salt"
    info = b"uart_protocol_v1_session_key"
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    session_key = hkdf.derive(shared_secret)
    
    # Store dynamic session key
    DYNAMIC_SESSION_KEY = session_key
    
    print(f"✓ ECDH handshake successful!")
    print(f"  - Session key established: {session_key[:16].hex()}...")
    print(f"  - Use this key for subsequent M_update encryption")
    
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 mac_provider.py <serial_port> [baudrate]")
        print("\nExample:")
        print("  python3 mac_provider.py /dev/tty.usbmodem14203 115200")
        print("\nTo find your device:")
        print("  ls /dev/tty.usbmodem*")
        sys.exit(1)
    
    port = sys.argv[1]
    baudrate = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    
    # Initialize device and provider
    device = STM32Device(port, baudrate)
    provider = ModelProvider()
    
    if not device.connect():
        sys.exit(1)
    
    # Test components (matching device test)
    model_pub = bytes([0xC0 + i for i in range(32)])
    model_secret = bytes([0xE0 + i for i in range(32)])
    code_hash = bytes([0x01 + i for i in range(32)])
    model_id = 0x00000001

    # Interactive session state
    enclave_info_cache = None
    verifier_key = None
    verifier_pk_raw = None
    cert = struct.pack('<I', model_id) + bytes(range(16))  # 20 B
    device_pk_d = None
    
    try:
        while True:
            print_menu()
            choice = input("Enter command: ").strip().lower()
            
            if choice == 'q':
                break
            
            elif choice == '1':
                if perform_ecdh_handshake(device):
                    verifier_key = None
                    verifier_pk_raw = None
                    print("\n✓ Dynamic session key established")
                else:
                    print("\n✗ ECDH handshake failed")

            elif choice == '2':
                print("\n[2] Computing EnclaveInfo...")
                data = model_pub + model_secret + code_hash + struct.pack('<I', model_id)
                if device.send_command(CMD_COMPUTE_ENCLAVE_INFO, data):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK:
                        dec = decode_enclave_info(resp[1])
                        if dec:
                            enclave_info_cache = dec
                            print(f"✓ EnclaveInfo: {dec.hex()}")
                        else:
                            print(f"✗ Unsupported/undecodable EnclaveInfo response len={len(resp[1])}")
                    else:
                        print("✗ Failed to compute EnclaveInfo")

            elif choice == '3':
                current_max = get_device_max_inferences(device)
                suggested = (current_max + 1) if current_max is not None else 10
                if current_max is not None:
                    print(f"  Current device max_inferences = {current_max}")
                    print(f"  M_update must use a strictly larger c_limit to pass anti-replay")

                raw = input(f"c_limit (default {suggested}): ").strip()
                c_limit = int(raw) if raw else suggested
                if enclave_info_cache is None:
                    print("  (no cached EnclaveInfo, computing first)")
                    data = model_pub + model_secret + code_hash + struct.pack('<I', model_id)
                    if not device.send_command(CMD_COMPUTE_ENCLAVE_INFO, data):
                        print("✗ Failed to request EnclaveInfo")
                        continue
                    resp = device.read_response()
                    if not resp or resp[0] != RESP_OK:
                        print("✗ Failed to receive EnclaveInfo")
                        continue
                    enclave_info_cache = decode_enclave_info(resp[1])
                    if enclave_info_cache is None:
                        print("✗ Could not decode EnclaveInfo response")
                        continue

                pending_verifier_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                vk_full = pending_verifier_key.public_key().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                pending_verifier_pk_raw = vk_full[1:]
                provider.verifier_pk = pending_verifier_pk_raw

                nonce, ciphertext, tag = provider.generate_m_update(c_limit, enclave_info_cache, cert)
                m_update_data = nonce + ciphertext + tag
                if device.send_command(CMD_VALIDATE_M_UPDATE, m_update_data):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK:
                        verifier_key = pending_verifier_key
                        verifier_pk_raw = pending_verifier_pk_raw
                        print(f"✓ M_update accepted, quota target={c_limit}")
                    else:
                        if current_max is not None and c_limit <= current_max:
                            print(f"✗ M_update rejected: anti-replay (c_limit={c_limit} must be > current {current_max})")
                        else:
                            print("✗ M_update rejected")
                        print("  Local verifier key was NOT committed; run option 3 again with a higher c_limit")

            elif choice == '4':
                if device.send_command(CMD_GET_DEVICE_PUBKEY):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK and len(resp[1]) == 65:
                        device_pk_d = resp[1]
                        print(f"✓ pk_d: {device_pk_d.hex()}")
                    else:
                        print("✗ Failed to get pk_d")

            elif choice == '5':
                if device.send_command(CMD_GET_MAX_INFERENCES):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK and len(resp[1]) >= 4:
                        print(f"✓ max_inferences = {struct.unpack('<I', resp[1][:4])[0]}")
                    else:
                        print("✗ Failed")

            elif choice == '6':
                raw = input("new max_inferences (uint32): ").strip()
                if not raw:
                    print("✗ value required")
                    continue
                new_max = int(raw)
                payload = struct.pack('<I', new_max)
                if device.send_command(CMD_SET_MAX_INFERENCES, payload):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK:
                        print(f"✓ max_inferences set to {new_max}")
                    else:
                        print("✗ Set max failed")

            elif choice == '7':
                if device.send_command(CMD_GET_INFERENCE_COUNT):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK and len(resp[1]) >= 4:
                        print(f"✓ inference_count = {struct.unpack('<I', resp[1][:4])[0]}")
                    else:
                        print("✗ Failed")

            elif choice == '8':
                if device.send_command(CMD_GET_REMAINING_INFERENCES):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK and len(resp[1]) >= 4:
                        print(f"✓ remaining = {struct.unpack('<I', resp[1][:4])[0]}")
                    else:
                        print("✗ Failed")

            elif choice == '9':
                if DYNAMIC_SESSION_KEY is None:
                    print("✗ Do ECDH first (command 1)")
                    continue
                if verifier_key is None:
                    print("✗ Send a successful M_update first (command 3) to provision verifier key")
                    continue

                nonce_inf = os.urandom(32)
                model_id_bytes = struct.pack('<I', model_id)
                msg_to_sign = nonce_inf + model_id_bytes
                sig_der = verifier_key.sign(msg_to_sign, ec.ECDSA(hashes.SHA256()))
                r_v, s_v = decode_dss_signature(sig_der)
                sig_v_raw = r_v.to_bytes(32, 'big') + s_v.to_bytes(32, 'big')
                minf_plain = nonce_inf + model_id_bytes + sig_v_raw
                minf_enc = encrypt_command(DYNAMIC_SESSION_KEY, minf_plain)

                if device.send_command(CMD_RUN_INFERENCE, minf_enc):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK:
                        if len(resp[1]) > 0:
                            dec = decrypt_response(DYNAMIC_SESSION_KEY, resp[1])
                            if dec and len(dec) >= 65:
                                pred = dec[0]
                                print(f"✓ verified inference OK, pred={pred}")
                            else:
                                print("✓ verified inference OK (response not decoded)")
                        else:
                            print("✓ verified inference OK")
                    else:
                        print("✗ verified inference failed (quota/signature/model_id?)")

            elif choice == '10':
                if device.send_command(CMD_RUN_INFERENCE):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK:
                        print("✓ legacy inference accepted")
                    else:
                        print("✗ legacy inference rejected")

            elif choice == '11':
                if device.send_command(CMD_GET_INFERENCE_RESULT):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK and len(resp[1]) >= 2:
                        pred = resp[1][0]
                        exp = resp[1][1]
                        print(f"✓ result: pred={pred}, expected={exp}")
                    else:
                        print("✗ Failed")

            elif choice == '12':
                if device.send_command(CMD_GET_BENCHMARK):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK:
                        parse_ns_benchmark(resp[1])
                    else:
                        print("✗ Failed")

            elif choice == '13':
                if device.send_command(CMD_GET_SECURE_BENCHMARK):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK:
                        parse_secure_benchmark(resp[1])
                    else:
                        print("✗ Failed")

            elif choice == '14':
                secs = input("duration seconds (default 2): ").strip()
                duration = float(secs) if secs else 2.0
                device.read_console_output(duration)

            elif choice == '15':
                print("\n[15] Memory protection feedback...")
                if device.send_command(CMD_GET_SAU_STATE):
                    resp = device.read_response()
                    if resp and resp[0] == RESP_OK and len(resp[1]) >= 9:
                        state = resp[1][0]
                        base = struct.unpack('<I', resp[1][1:5])[0]
                        size = struct.unpack('<I', resp[1][5:9])[0]
                        state_name = {
                            0: 'UNREGISTERED',
                            1: 'OPEN',
                            2: 'CLOSED',
                        }.get(state, f'UNKNOWN({state})')
                        print(f"✓ SAU state = {state_name}")
                        print(f"  base = 0x{base:08X}")
                        print(f"  size = {size}")
                        if state == 2:
                            print("  Protection status: PROTECTED (window closed to NS)")
                        elif state == 1:
                            print("  Protection status: NOT protected right now (window open to NS)")
                        else:
                            print("  Protection status: no enclave window registered")
                    else:
                        print("✗ Failed to get deterministic SAU state")
                else:
                    print("✗ Failed to send GET_SAU_STATE")

            elif choice == '16':
                raw_cmd = input("cmd hex (ex: 0C): ").strip().replace('0x', '')
                raw_data = input("payload hex (empty=none): ").strip().replace(' ', '')
                try:
                    cmd = int(raw_cmd, 16)
                    payload = bytes.fromhex(raw_data) if raw_data else b''
                except Exception as e:
                    print(f"✗ Invalid input: {e}")
                    continue
                if device.send_command(cmd, payload):
                    resp = device.read_response()
                    if resp:
                        print(f"  status=0x{resp[0]:02X}, data={resp[1].hex()}")
                    else:
                        print("  no response")

            elif choice == '17':
                print("\n[17] Session status")
                print(f"  Dynamic session key: {'YES' if DYNAMIC_SESSION_KEY is not None else 'NO'}")
                print(f"  Cached EnclaveInfo:  {'YES' if enclave_info_cache is not None else 'NO'}")
                print(f"  Verifier key pair:   {'YES' if verifier_key is not None else 'NO'}")
                print(f"  Device pk_d cached:  {'YES' if device_pk_d is not None else 'NO'}")
                print(f"  model_id:            0x{model_id:08X}")
                print(f"  cert_len:            {len(cert)}")
            
            else:
                print("Invalid choice, try again")
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        device.disconnect()


if __name__ == "__main__":
    main()
