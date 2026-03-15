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
from typing import Optional, Set, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
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
CMD_RUN_INFERENCE_NO_SAU = 0x0E
CMD_READ_PROTECTED_MEM = 0x0F
CMD_GET_ENCLAVE_STATE = 0x10

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
    print(" 18) Security tests (negative / tamper checks)")
    print(" 19) DANGER test: run inference without SAU open")
    print(" 20) DANGER test: direct read protected memory")
    print("\n  q) Quit")
    print()


def parse_ns_benchmark(data: bytes):
    if len(data) < 64:
        print(f"  ✗ NS benchmark payload too short: {len(data)} B")
        return
    # benchmark_metrics_t: 16 x uint32_t (64 bytes)
    # [0] enclave_create  [1] enclave_destroy  [2] aes_decrypt
    # [3] early_layers    [4] late_layers       [5] total_inference
    # [6] run_enclave     [7] heap_used         [8] heap_free
    # [9] stack_used      [10] ram_used         [11] ram_total
    # [12] flash_used     [13] flash_total      [14] inference_count
    # [15] enclave_recreations
    vals = struct.unpack('<16I', data[:64])
    print("  NS metrics:")
    print(f"    enclave_create_cycles:   {vals[0]}")
    print(f"    enclave_destroy_cycles:  {vals[1]}")
    print(f"    aes_decrypt_cycles:      {vals[2]}")
    print(f"    early_layers_cycles:     {vals[3]}")
    print(f"    late_layers_cycles:      {vals[4]}")
    print(f"    total_inference_cycles:  {vals[5]}")
    print(f"    run_enclave_cycles:      {vals[6]}")
    print(f"    inference_count:         {vals[14]}")
    print(f"    enclave_recreations:     {vals[15]}")
    print(f"    RAM used/total:          {vals[10]}/{vals[11]} B")
    print(f"    Flash used/total:        {vals[12]}/{vals[13]} B")


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


def get_device_pubkey(device: 'STM32Device') -> Optional[bytes]:
    if not device.send_command(CMD_GET_DEVICE_PUBKEY):
        return None
    resp = device.read_response()
    if not resp or resp[0] != RESP_OK or len(resp[1]) != 65:
        return None
    return resp[1]


def get_sau_state(device: 'STM32Device') -> Optional[Tuple[int, int, int]]:
    """Return SAU state tuple: (state, base, size)."""
    if not device.send_command(CMD_GET_SAU_STATE):
        return None
    resp = device.read_response()
    if not resp or resp[0] != RESP_OK or len(resp[1]) < 9:
        return None
    state = resp[1][0]
    base = struct.unpack('<I', resp[1][1:5])[0]
    size = struct.unpack('<I', resp[1][5:9])[0]
    return (state, base, size)


def get_enclave_state(device: 'STM32Device') -> Optional[bool]:
    """Return True if enclave is currently created on device."""
    if not device.send_command(CMD_GET_ENCLAVE_STATE):
        return None
    resp = device.read_response()
    if not resp or resp[0] != RESP_OK or len(resp[1]) < 1:
        return None
    return resp[1][0] != 0


def decode_maybe_encrypted(payload: bytes) -> Optional[bytes]:
    """Try encrypted decode first (when session exists), else return payload as-is."""
    if DYNAMIC_SESSION_KEY is not None:
        dec = decrypt_response(DYNAMIC_SESSION_KEY, payload)
        if dec is not None:
            return dec
    return payload


def verify_attested_enclave_info(device_pk_d: bytes, nonce: bytes, enclave_info: bytes, sig_raw: bytes) -> bool:
    if len(device_pk_d) != 65 or len(nonce) != 32 or len(enclave_info) != 32 or len(sig_raw) != 64:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pk_d)
        r = int.from_bytes(sig_raw[:32], 'big')
        s = int.from_bytes(sig_raw[32:], 'big')
        sig_der = encode_dss_signature(r, s)
        msg = nonce + enclave_info
        pub.verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def verify_pox_signature(device_pk_d: bytes, model_id: int, cert: bytes, nonce_inf: bytes, output_class: int, sig_raw: bytes) -> bool:
    """Verify PoX signature over: model_id(4 LE) || cert || nonce_inf(32) || output(1)."""
    if len(device_pk_d) != 65 or len(nonce_inf) != 32 or len(sig_raw) != 64:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pk_d)
        r = int.from_bytes(sig_raw[:32], 'big')
        s = int.from_bytes(sig_raw[32:], 'big')
        sig_der = encode_dss_signature(r, s)

        msg = struct.pack('<I', model_id) + cert + nonce_inf + bytes([output_class & 0xFF])
        pub.verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def request_enclave_info_attested(device: 'STM32Device', device_pk_d: Optional[bytes]) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Request EnclaveInfo using nonce attestation mode.
    Returns: (enclave_info, maybe_updated_device_pk_d)
    """
    nonce = os.urandom(32)
    if not device.send_command(CMD_COMPUTE_ENCLAVE_INFO, nonce):
        return None, device_pk_d

    resp = device.read_response()
    if not resp or resp[0] != RESP_OK:
        return None, device_pk_d

    plain = decode_maybe_encrypted(resp[1])
    if plain is None:
        return None, device_pk_d

    # New attested mode: enclave_info(32) || sig_d(64)
    if len(plain) >= 96:
        enclave_info = plain[:32]
        sig_d = plain[32:96]

        if device_pk_d is None:
            device_pk_d = get_device_pubkey(device)
        if device_pk_d is None:
            print("✗ Cannot verify EnclaveInfo attestation: pk_d unavailable")
            return None, None

        if not verify_attested_enclave_info(device_pk_d, nonce, enclave_info, sig_d):
            print("✗ EnclaveInfo attestation signature invalid")
            return None, device_pk_d

        print("✓ EnclaveInfo attestation verified with pk_d")
        return enclave_info, device_pk_d

    # Legacy fallback: plain enclave_info only
    if len(plain) == 32:
        print("! Legacy EnclaveInfo response (no attestation signature)")
        return plain, device_pk_d

    return None, device_pk_d


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


def run_security_tests(
    device: 'STM32Device',
    provider: 'ModelProvider',
    enclave_info_cache: Optional[bytes],
    device_pk_d: Optional[bytes],
    model_id: int,
    verifier_key,
    selected_tests: Optional[Set[str]] = None,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Run negative security tests against protocol checks.
    Returns possibly updated (enclave_info_cache, device_pk_d).
    """
    print("\n[18] Security tests (negative/tamper)...")

    if DYNAMIC_SESSION_KEY is None:
        print("  - No dynamic session key: running ECDH first")
        if not perform_ecdh_handshake(device):
            print("✗ Cannot run security tests without ECDH session")
            return enclave_info_cache, device_pk_d

    if enclave_info_cache is None:
        print("  - No cached EnclaveInfo: requesting attested EnclaveInfo")
        enclave_info_cache, device_pk_d = request_enclave_info_attested(device, device_pk_d)
        if enclave_info_cache is None:
            print("✗ Cannot run security tests without trusted EnclaveInfo")
            return enclave_info_cache, device_pk_d

    current_max = get_device_max_inferences(device)
    if current_max is None:
        print("✗ Cannot read current max_inferences")
        return enclave_info_cache, device_pk_d

    print(f"  Current max_inferences = {current_max}")
    print("  NOTE: some tests intentionally send malformed/replayed messages.")

    passed = 0
    total = 0

    def verdict(name: str, ok: bool):
        nonlocal passed, total
        total += 1
        if ok:
            passed += 1
            print(f"  ✓ {name}: PASS")
        else:
            print(f"  ✗ {name}: FAIL")

    def should_run(test_id: str) -> bool:
        return selected_tests is None or test_id in selected_tests

    # -------- Test 1: M_update with fake EnclaveInfo must be rejected --------
    if should_run('t1'):
        print("\n  [T1] M_update with fake EnclaveInfo should be rejected")
        c_limit_t1 = current_max + 1
        fake_enclave_info = bytearray(enclave_info_cache)
        fake_enclave_info[0] ^= 0x01

        nonce, ciphertext, tag = provider.generate_m_update(c_limit_t1, bytes(fake_enclave_info), struct.pack('<I', model_id) + bytes(range(16)))
        payload = nonce + ciphertext + tag
        rejected = False
        if device.send_command(CMD_VALIDATE_M_UPDATE, payload):
            resp = device.read_response()
            rejected = (resp is not None and resp[0] != RESP_OK)
        verdict("T1 fake EnclaveInfo rejection", rejected)

    # -------- Test 2: Valid M_update then replay same packet --------
    if should_run('t2'):
        print("\n  [T2] Replay protection should reject duplicated M_update")
        c_limit_t2 = current_max + 2
        nonce2, ciphertext2, tag2 = provider.generate_m_update(
            c_limit_t2,
            enclave_info_cache,
            struct.pack('<I', model_id) + bytes(range(16))
        )
        payload2 = nonce2 + ciphertext2 + tag2

        first_ok = False
        replay_rejected = False
        if device.send_command(CMD_VALIDATE_M_UPDATE, payload2):
            resp_first = device.read_response()
            first_ok = (resp_first is not None and resp_first[0] == RESP_OK)

        if device.send_command(CMD_VALIDATE_M_UPDATE, payload2):
            resp_replay = device.read_response()
            replay_rejected = (resp_replay is not None and resp_replay[0] != RESP_OK)

        verdict("T2 initial valid M_update accepted", first_ok)
        verdict("T2 replay rejected", replay_rejected)

    # -------- Test 3: Tamper GCM tag in M_update --------
    if should_run('t3'):
        print("\n  [T3] Tampered M_update tag should be rejected")
        refreshed_max = get_device_max_inferences(device)
        if refreshed_max is None:
            verdict("T3 tag tamper rejection", False)
        else:
            c_limit_t3 = refreshed_max + 1
            nonce3, ciphertext3, tag3 = provider.generate_m_update(
                c_limit_t3,
                enclave_info_cache,
                struct.pack('<I', model_id) + bytes(range(16))
            )
            bad_tag = bytearray(tag3)
            bad_tag[-1] ^= 0x80
            payload3 = nonce3 + ciphertext3 + bytes(bad_tag)

            tag_rejected = False
            if device.send_command(CMD_VALIDATE_M_UPDATE, payload3):
                resp3 = device.read_response()
                tag_rejected = (resp3 is not None and resp3[0] != RESP_OK)
            verdict("T3 tag tamper rejection", tag_rejected)

    # -------- Test 4: Invalid verifier signature in M_inf --------
    if should_run('t4'):
        print("\n  [T4] M_inf invalid verifier signature should be rejected")
        sig_rejected = False
        if DYNAMIC_SESSION_KEY is None:
            sig_rejected = False
        else:
            nonce_inf = os.urandom(32)
            model_id_bytes = struct.pack('<I', model_id)
            bad_sig = os.urandom(64)
            minf_plain = nonce_inf + model_id_bytes + bad_sig
            minf_enc = encrypt_command(DYNAMIC_SESSION_KEY, minf_plain)
            if device.send_command(CMD_RUN_INFERENCE, minf_enc):
                resp4 = device.read_response()
                sig_rejected = (resp4 is not None and resp4[0] != RESP_OK)
        verdict("T4 invalid M_inf signature rejection", sig_rejected)

    # -------- Test 5: Rejected inference must not open SAU window --------
    if should_run('t5'):
        print("\n  [T5] Rejected inference should keep SAU window closed")

        before = get_sau_state(device)
        if before is None:
            verdict("T5 SAU state readable before", False)
        else:
            state_before, base_before, size_before = before
            verdict("T5 SAU state readable before", True)

            nonce_inf = os.urandom(32)
            model_id_bytes = struct.pack('<I', model_id)
            bad_sig = os.urandom(64)
            minf_plain = nonce_inf + model_id_bytes + bad_sig
            minf_enc = encrypt_command(DYNAMIC_SESSION_KEY, minf_plain)

            rejected = False
            if device.send_command(CMD_RUN_INFERENCE, minf_enc):
                resp5 = device.read_response()
                rejected = (resp5 is not None and resp5[0] != RESP_OK)
            verdict("T5 malformed inference rejected", rejected)

            after = get_sau_state(device)
            if after is None:
                verdict("T5 SAU state readable after", False)
            else:
                state_after, base_after, size_after = after
                verdict("T5 SAU state readable after", True)

                # Main security property: rejected inference must not open SAU as a side effect.
                no_open_transition = not (state_before != 1 and state_after == 1)
                verdict("T5 no SAU open transition", no_open_transition)

                # Stronger property (nice-to-have): if already CLOSED, remain CLOSED.
                if state_before == 2:
                    verdict("T5 SAU remains CLOSED", state_after == 2)
                else:
                    print(f"  ! T5 info: SAU baseline state was {state_before}, not CLOSED; skipping strict CLOSED check")

                same_region = (base_before == base_after and size_before == size_after)
                verdict("T5 SAU region unchanged", same_region)

    # -------- Test 6: PoX negative verification must fail --------
    if should_run('t6'):
        print("\n  [T6] PoX negative test (verification must fail with wrong message)")

        if DYNAMIC_SESSION_KEY is None:
            verdict("T6 session key available", False)
        else:
            # Ensure we have pk_d for PoX verification.
            if device_pk_d is None:
                device_pk_d = get_device_pubkey(device)
            verdict("T6 device pk_d available", device_pk_d is not None)

            # Prepare a temporary verifier key and authorize it via M_update.
            cur2 = get_device_max_inferences(device)
            if cur2 is None:
                verdict("T6 read current max", False)
            else:
                temp_vk = ec.generate_private_key(ec.SECP256R1(), default_backend())
                vk_full = temp_vk.public_key().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                provider.verifier_pk = vk_full[1:]

                nonce_m, ct_m, tag_m = provider.generate_m_update(
                    cur2 + 1,
                    enclave_info_cache,
                    struct.pack('<I', model_id) + bytes(range(16))
                )
                m_ok = False
                if device.send_command(CMD_VALIDATE_M_UPDATE, nonce_m + ct_m + tag_m):
                    r_m = device.read_response()
                    m_ok = (r_m is not None and r_m[0] == RESP_OK)
                verdict("T6 temporary M_update accepted", m_ok)

                if m_ok and device_pk_d is not None:
                    # Run one valid verified inference to obtain a real PoX signature.
                    nonce_inf = os.urandom(32)
                    model_id_bytes = struct.pack('<I', model_id)
                    msg = nonce_inf + model_id_bytes
                    sig_der = temp_vk.sign(msg, ec.ECDSA(hashes.SHA256()))
                    r_v, s_v = decode_dss_signature(sig_der)
                    sig_v_raw = r_v.to_bytes(32, 'big') + s_v.to_bytes(32, 'big')
                    minf_plain = nonce_inf + model_id_bytes + sig_v_raw
                    minf_enc = encrypt_command(DYNAMIC_SESSION_KEY, minf_plain)

                    got_pox = False
                    pox_invalid_as_expected = False
                    pox_valid_sanity = False
                    pred_dbg = None
                    if device.send_command(CMD_RUN_INFERENCE, minf_enc):
                        r_inf = device.read_response()
                        if r_inf and r_inf[0] == RESP_OK and len(r_inf[1]) > 0:
                            dec = decrypt_response(DYNAMIC_SESSION_KEY, r_inf[1])
                            if dec and len(dec) >= 65:
                                got_pox = True
                                pred = dec[0]
                                pred_dbg = pred
                                pox_sig = dec[1:65]

                                # Intentionally verify with wrong model_id.
                                bad_ok = verify_pox_signature(
                                    device_pk_d=device_pk_d,
                                    model_id=(model_id + 1),
                                    cert=struct.pack('<I', model_id) + bytes(range(16)),
                                    nonce_inf=nonce_inf,
                                    output_class=pred,
                                    sig_raw=pox_sig,
                                )
                                pox_invalid_as_expected = (bad_ok is False)

                                # Sanity: verify with correct message must pass.
                                pox_valid_sanity = verify_pox_signature(
                                    device_pk_d=device_pk_d,
                                    model_id=model_id,
                                    cert=struct.pack('<I', model_id) + bytes(range(16)),
                                    nonce_inf=nonce_inf,
                                    output_class=pred,
                                    sig_raw=pox_sig,
                                )

                                print(f"  [T6 dbg] pred={pred_dbg}, pox_wrong_msg={bad_ok}, pox_correct_msg={pox_valid_sanity}")

                    verdict("T6 received PoX from valid inference", got_pox)
                    verdict("T6 wrong-message PoX verification fails", pox_invalid_as_expected)
                    verdict("T6 correct-message PoX verification passes", pox_valid_sanity)

    print(f"\n[18] Security tests summary: {passed}/{total} passed")
    if passed == total:
        print("✓ All negative security checks behaved as expected")
    else:
        print("! Some checks did not return expected behavior (inspect logs)")

    return enclave_info_cache, device_pk_d


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
    
    # model_id remains host-side for cert + M_inf binding
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
                dec, device_pk_d = request_enclave_info_attested(device, device_pk_d)
                if dec is not None:
                    enclave_info_cache = dec
                    print(f"✓ EnclaveInfo: {dec.hex()}")
                else:
                    print("✗ Failed to compute/verify EnclaveInfo attestation")

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
                    enclave_info_cache, device_pk_d = request_enclave_info_attested(device, device_pk_d)
                    if enclave_info_cache is None:
                        print("✗ Could not retrieve verified EnclaveInfo")
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
                                pox_sig = dec[1:65]

                                if device_pk_d is None:
                                    device_pk_d = get_device_pubkey(device)

                                if device_pk_d is not None and verify_pox_signature(
                                    device_pk_d=device_pk_d,
                                    model_id=model_id,
                                    cert=cert,
                                    nonce_inf=nonce_inf,
                                    output_class=pred,
                                    sig_raw=pox_sig,
                                ):
                                    print(f"✓ verified inference OK, pred={pred}, PoX=VALID")
                                else:
                                    print(f"! verified inference OK, pred={pred}, PoX=INVALID")
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
                enclave_created = get_enclave_state(device)
                print(f"  Dynamic session key: {'YES' if DYNAMIC_SESSION_KEY is not None else 'NO'}")
                print(f"  Cached EnclaveInfo:  {'YES' if enclave_info_cache is not None else 'NO'}")
                print(f"  Verifier key pair:   {'YES' if verifier_key is not None else 'NO'}")
                print(f"  Device pk_d cached:  {'YES' if device_pk_d is not None else 'NO'}")
                print(f"  Enclave created:     {('YES' if enclave_created else 'NO') if enclave_created is not None else 'UNKNOWN'}")
                print(f"  model_id:            0x{model_id:08X}")
                print(f"  cert_len:            {len(cert)}")

            elif choice == '18':
                print("\nSecurity test mode:")
                print("  a) Run all tests")
                print("  1) T1 fake EnclaveInfo")
                print("  2) T2 M_update replay")
                print("  3) T3 GCM tag tamper")
                print("  4) T4 invalid M_inf signature")
                print("  5) T5 inference blocked with SAU closed")
                print("  6) T6 PoX negative verification")
                print("\n  Tip: select unit tests individually or combine them (ex: 1,4,5)")
                sel = input("Select [a or list like 1,4,5,6] (default a): ").strip().lower()
                mapping = {
                    '1': {'t1'},
                    '2': {'t2'},
                    '3': {'t3'},
                    '4': {'t4'},
                    '5': {'t5'},
                    '6': {'t6'},
                }

                if sel in ('', 'a', 'all'):
                    selected = None
                else:
                    tokens = [t.strip() for t in sel.replace(';', ',').split(',') if t.strip()]
                    selected = set()
                    invalid = []
                    for tok in tokens:
                        if tok in mapping:
                            selected.update(mapping[tok])
                        else:
                            invalid.append(tok)

                    if invalid or not selected:
                        print(f"✗ Invalid selection: {', '.join(invalid) if invalid else sel}")
                        print("  Use: a  OR  one/many among 1,2,3,4,5,6")
                        continue

                enclave_info_cache, device_pk_d = run_security_tests(
                    device=device,
                    provider=provider,
                    enclave_info_cache=enclave_info_cache,
                    device_pk_d=device_pk_d,
                    model_id=model_id,
                    verifier_key=verifier_key,
                    selected_tests=selected,
                )

            elif choice == '19':
                print("\n[19] DANGER test: inference without SAU open")
                print("  This may trigger BusFault/HardFault reset if SAU is closed.")
                confirm = input("Type YES to continue: ").strip()
                if confirm != 'YES':
                    print("  cancelled")
                    continue

                before = get_sau_state(device)
                if before is not None:
                    st, base, size = before
                    print(f"  SAU before: state={st}, base=0x{base:08X}, size={size}")

                if not device.send_command(CMD_RUN_INFERENCE_NO_SAU):
                    print("✗ send failed")
                    continue

                resp = device.read_response(timeout=2.0)
                if resp is None:
                    print("! No response (possible fault/reset), reconnect then check logs")
                elif resp[0] == RESP_OK:
                    if len(resp[1]) >= 1:
                        print(f"✓ Command returned pred={resp[1][0]} (unexpected if SAU really closed)")
                    else:
                        print("✓ Command returned OK")
                else:
                    print("✓ Command rejected by device")

                after = get_sau_state(device)
                if after is not None:
                    st, base, size = after
                    print(f"  SAU after: state={st}, base=0x{base:08X}, size={size}")

            elif choice == '20':
                print("\n[20] DANGER test: direct read protected memory")
                print("  This can trigger BusFault/HardFault reset if SAU is active.")
                confirm = input("Type YES to continue: ").strip()
                if confirm != 'YES':
                    print("  cancelled")
                    continue

                before = get_sau_state(device)
                if before is not None:
                    st, base, size = before
                    print(f"  SAU before: state={st}, base=0x{base:08X}, size={size}")

                if not device.send_command(CMD_READ_PROTECTED_MEM):
                    print("✗ send failed")
                    continue

                resp = device.read_response(timeout=2.0)
                if resp is None:
                    print("! No response (possible HardFault/reset), reconnect and check logs")
                elif resp[0] == RESP_OK and len(resp[1]) >= 1:
                    print(f"! Direct protected read succeeded, value=0x{resp[1][0]:02X}")
                elif resp[0] == RESP_OK:
                    print("! Direct protected read command returned OK")
                else:
                    print("✓ Command rejected before direct read")

                after = get_sau_state(device)
                if after is not None:
                    st, base, size = after
                    print(f"  SAU after: state={st}, base=0x{base:08X}, size={size}")
            
            else:
                print("Invalid choice, try again")
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        device.disconnect()


if __name__ == "__main__":
    main()
