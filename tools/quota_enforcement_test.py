#!/usr/bin/env python3
"""
Quota Enforcement Test - Validates max_inferences policy on STM32L552
Tests scenario: set max_inferences=4, request 5 inferences
Verifies that 4 succeed and 5th is rejected with quota exhausted.
"""

import sys
import time
import struct
import serial
import os
import signal
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Protocol command codes (from uart_protocol.h)
CMD_COMPUTE_ENCLAVE_INFO = 0x01
CMD_VALIDATE_M_UPDATE = 0x02
CMD_GET_MAX_INFERENCES = 0x03
CMD_RUN_INFERENCE = 0x04
CMD_GET_INFERENCE_COUNT = 0x05
CMD_GET_REMAINING_INFERENCES = 0x06
CMD_GET_BENCHMARK = 0x08
CMD_GET_SECURE_BENCHMARK = 0x09
CMD_ECDH_HANDSHAKE = 0x07
CMD_SET_MAX_INFERENCES = 0x0B

RESP_OK = 0x00
RESP_ERROR = 0xFF

# ECDH & M_update parameters (must match firmware)
HKDF_SALT = b'uart_protocol_v1_salt'
HKDF_INFO = b'uart_protocol_v1_session_key'

# Verifier public key (from mac_provider.py)
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

# Test parameters
DEVICE_PORT = "/dev/tty.usbmodem1203"
BAUDRATE = 115200
MAX_QUOTA_LIMIT = 4
INFERENCE_ATTEMPTS = 5

class QuotaEnforcementTester:
    """Manages quota enforcement testing sequence."""
    
    def __init__(self, port: str, baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self.ser = None
        self.session_key = None
        self.results = {
            'ecdh_success': False,
            'enclave_info': None,
            'inference_runs': [],
            'ns_metrics': None,
            's_metrics': None,
            'test_verdict': None
        }
    
    def connect(self) -> bool:
        """Connect to device and initialize serial port."""
        self._release_port()
        
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=2)
            print(f"✓ Connected to {self.port} at {self.baudrate} baud\n")
            time.sleep(0.5)  # Device ready
            
            try:
                self.ser.reset_input_buffer()
                self.ser.reset_output_buffer()
            except Exception:
                pass
            
            return True
        except serial.SerialException as e:
            print(f"✗ Failed to open {self.port}: {e}")
            return False
    
    def _release_port(self):
        """Kill any process holding the device port."""
        try:
            pids = subprocess.check_output(
                ["lsof", "-t", self.port], text=True
            ).strip().splitlines()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except Exception:
                    pass
        except Exception:
            pass
    
    def send_command(self, cmd: int, data: bytes = b'') -> tuple:
        """
        Send command to device via UART protocol.
        Format: [CMD:1][LEN:4 LE][DATA:n]
        Response: [STATUS:1][LEN:4][DATA:n]
        
        Returns: (status, response_data)
        """
        try:
            self.ser.reset_input_buffer()
        except Exception:
            pass
        
        payload = struct.pack('<BI', cmd, len(data)) + data
        self.ser.write(payload)
        
        # Read response status, handling boot/debug noise
        status = None
        for _ in range(256):
            status_byte = self.ser.read(1)
            if not status_byte:
                break
            b = status_byte[0]
            if b in (RESP_OK, RESP_ERROR):
                status = b
                break
        
        if status is None:
            return None, None
        
        # Read response length (4 bytes LE)
        len_bytes = self.ser.read(4)
        if len(len_bytes) < 4:
            return status, None
        
        response_len = struct.unpack('<I', len_bytes)[0]
        
        # Read response data
        response_data = self.ser.read(response_len) if response_len > 0 else b''
        
        return status, response_data
    
    def perform_ecdh_handshake(self) -> bool:
        """Perform ECDH key exchange with device."""
        print("[1] ECDH Handshake...")
        
        # Generate Mac ephemeral key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # Export uncompressed public key (0x04 || x || y)
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Send ECDH handshake
        status, device_pubkey_data = self.send_command(CMD_ECDH_HANDSHAKE, public_bytes)
        
        if status == RESP_OK and device_pubkey_data and len(device_pubkey_data) == 65:
            # Load device public key and perform ECDH
            device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), device_pubkey_data
            )
            
            # Compute shared secret
            shared_secret = private_key.exchange(ec.ECDH(), device_public_key)
            
            # Derive session key via HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=HKDF_SALT,
                info=HKDF_INFO,
                backend=default_backend()
            )
            self.session_key = hkdf.derive(shared_secret)
            
            print(f"    ✓ Session key: {self.session_key.hex()[:32]}...")
            self.results['ecdh_success'] = True
            return True
        else:
            print(f"    ✗ ECDH failed (status={status})")
            self.results['ecdh_success'] = False
            return False
    
    def compute_enclave_info(self) -> bool:
        """Compute EnclaveInfo hash."""
        print("[2] Compute EnclaveInfo...")
        
        model_pub = bytes([0xC0 + i for i in range(32)])
        model_secret = bytes([0xE0 + i for i in range(32)])
        code_hash = bytes([0x01 + i for i in range(32)])
        model_id = 0x00000001
        test_data = model_pub + model_secret + code_hash + struct.pack('<I', model_id)
        
        status, enclave_info = self.send_command(CMD_COMPUTE_ENCLAVE_INFO, test_data)
        
        if status == RESP_OK and enclave_info:
            print(f"    ✓ EnclaveInfo: {enclave_info.hex()[:32]}...")
            self.results['enclave_info'] = enclave_info.hex()
            return True
        else:
            print(f"    ✗ Compute failed (status={status})")
            return False
    
    def send_m_update(self, c_limit: int = 10) -> bool:
        """Send M_update message with authorization."""
        print(f"[3] Validate M_update (quota={c_limit})...")
        
        # Query current counter for anti-replay
        status, counter_data = self.send_command(CMD_GET_INFERENCE_COUNT, b'')
        if status != RESP_OK or not counter_data:
            print(f"    ✗ Failed to get counter (status={status})")
            return False
        
        current_count = struct.unpack('<I', counter_data[:4])[0] if len(counter_data) >= 4 else 0
        
        # Anti-replay: c_limit must be strictly increasing
        safe_c_limit = max(current_count + 10, c_limit)
        
        print(f"    Current count: {current_count}, safe c_limit: {safe_c_limit}")
        
        # Build M_update message: [c_limit:4][reserved:4]
        m_update_plain = struct.pack('<II', safe_c_limit, 0)
        
        # Encrypt with AES-256-GCM
        nonce = b'\x00' * 12
        cipher = AESGCM(self.session_key)
        m_update_cipher = cipher.encrypt(nonce, m_update_plain, b'')
        
        # Message format: [nonce:12][ciphertext:8][tag:16]
        m_update_payload = nonce + m_update_cipher
        
        status, _ = self.send_command(CMD_VALIDATE_M_UPDATE, m_update_payload)
        
        if status == RESP_OK:
            print(f"    ✓ M_update validated")
            return True
        else:
            print(f"    ✗ M_update validation failed (status={status})")
            return False
    
    def set_max_inferences(self, max_val: int) -> bool:
        """Set maximum allowed inferences."""
        print(f"[4] Set max_inferences={max_val}...")
        
        data = struct.pack('<I', max_val)
        status, _ = self.send_command(CMD_SET_MAX_INFERENCES, data)
        
        if status == RESP_OK:
            print(f"    ✓ Max set to {max_val}")
            return True
        else:
            print(f"    ✗ Set max failed (status={status})")
            return False
    
    def get_max_inferences(self) -> int:
        """Get current max_inferences setting."""
        status, data = self.send_command(CMD_GET_MAX_INFERENCES, b'')
        
        if status == RESP_OK and data and len(data) >= 4:
            max_val = struct.unpack('<I', data[:4])[0]
            print(f"    Current max: {max_val}")
            return max_val
        return None
    
    def run_inference_sequence(self, num_attempts: int = 5) -> bool:
        """Run inference sequence and validate quota enforcement."""
        print(f"\n[5] Run {num_attempts} inferences (quota={MAX_QUOTA_LIMIT})...\n")
        
        for idx in range(1, num_attempts + 1):
            status, data = self.send_command(CMD_RUN_INFERENCE, b'')
            
            # Get current counter and remaining
            _, count_data = self.send_command(CMD_GET_INFERENCE_COUNT, b'')
            count = struct.unpack('<I', count_data[:4])[0] if count_data and len(count_data) >= 4 else 0
            
            _, rem_data = self.send_command(CMD_GET_REMAINING_INFERENCES, b'')
            remaining = struct.unpack('<I', rem_data[:4])[0] if rem_data and len(rem_data) >= 4 else 0
            
            result = {
                'idx': idx,
                'status': status,
                'count': count,
                'remaining': remaining,
                'success': status == RESP_OK
            }
            self.results['inference_runs'].append(result)
            
            status_label = "✓ OK" if status == RESP_OK else f"✗ ERR({status})"
            print(f"    Run {idx}: {status_label} | count={count}, remaining={remaining}")
        
        return True
    
    def retrieve_benchmarks(self) -> bool:
        """Retrieve NS and S benchmark metrics."""
        print("\n[6] Retrieve benchmark metrics...")
        
        # NS benchmark: 18 uint32
        status, ns_data = self.send_command(CMD_GET_BENCHMARK, b'')
        if status == RESP_OK and ns_data and len(ns_data) >= 72:
            ns_metrics = struct.unpack('<18I', ns_data[:72])
            self.results['ns_metrics'] = ns_metrics
            print(f"    ✓ NS metrics: {len(ns_metrics)} fields")
        else:
            print(f"    ✗ Failed to get NS metrics (status={status})")
        
        # S benchmark: 7 uint64 + 8 uint32 = 88 bytes
        status, s_data = self.send_command(CMD_GET_SECURE_BENCHMARK, b'')
        if status == RESP_OK and s_data and len(s_data) >= 88:
            s_metrics = struct.unpack('<7Q8I', s_data[:88])
            self.results['s_metrics'] = s_metrics
            print(f"    ✓ S metrics: {len(s_metrics)} fields")
        else:
            print(f"    ✗ Failed to get S metrics (status={status})")
        
        return True
    
    def validate_quota_policy(self) -> bool:
        """Validate that quota policy was enforced correctly."""
        print("\n[7] Validate quota policy...")
        
        runs = self.results['inference_runs']
        
        # Expected: runs 1-4 succeed, run 5 fails
        expected = [
            (1, RESP_OK),
            (2, RESP_OK),
            (3, RESP_OK),
            (4, RESP_OK),
            (5, RESP_ERROR),
        ]
        
        all_correct = True
        for (exp_idx, exp_status), run in zip(expected, runs):
            if run['idx'] != exp_idx or run['status'] != exp_status:
                all_correct = False
        
        if all_correct:
            print("    ✓ Quota policy validated!")
            print(f"      - Runs 1-4: SUCCESS")
            print(f"      - Run 5: REJECTED (quota exhausted)")
            self.results['test_verdict'] = 'PASS'
            return True
        else:
            print("    ✗ Quota policy check failed")
            self.results['test_verdict'] = 'FAIL'
            return False
    
    def generate_report(self, output_dir: Path = None) -> str:
        """Generate markdown report of test results."""
        if output_dir is None:
            output_dir = Path('build')
        
        output_dir.mkdir(exist_ok=True)
        report_path = output_dir / 'quota_enforcement_test_report.md'
        
        runs = self.results['inference_runs']
        ns_metrics = self.results['ns_metrics']
        s_metrics = self.results['s_metrics']
        
        # Build markdown report
        md = "# Quota Enforcement Test Report\n\n"
        md += "## Summary\n"
        md += f"- **Test Scenario**: Set max_inferences={MAX_QUOTA_LIMIT}, request {INFERENCE_ATTEMPTS} inferences\n"
        md += f"- **Expected**: Runs 1-{MAX_QUOTA_LIMIT} succeed, run {INFERENCE_ATTEMPTS} rejected\n"
        md += f"- **Verdict**: **{self.results['test_verdict']}**\n\n"
        
        # Inference runs table
        md += "## Inference Runs\n\n"
        md += "| Run | Status | Count | Remaining |\n"
        md += "|-----|--------|-------|----------|\n"
        for run in runs:
            status_label = "✓ OK" if run['success'] else "✗ ERR"
            md += f"| {run['idx']} | {status_label} | {run['count']} | {run['remaining']} |\n"
        
        # NS metrics
        if ns_metrics:
            md += "\n## Non-Secure (NS) Metrics\n\n"
            labels = [
                "total_inference_cycles", "run_enclave_cycles", "ns_copy_in_cycles",
                "ns_copy_out_cycles", "enclave_setup_cycles", "ns_to_s_ipc_cycles",
                "s_to_ns_ipc_cycles", "reserved1", "reserved2",
                "ns_ram_used", "ns_ram_total", "ns_flash_used", "ns_flash_total",
                "s_ram_used", "s_ram_total", "s_flash_used", "s_flash_total", "reserved3"
            ]
            
            md += "### Performance\n\n"
            md += f"- Total inference cycles: **{ns_metrics[0]:,}**\n"
            md += f"- Run enclave cycles: **{ns_metrics[1]:,}**\n"
            md += f"- NS copy-in cycles: **{ns_metrics[2]:,}**\n"
            md += f"- NS copy-out cycles: **{ns_metrics[3]:,}**\n"
            
            md += "\n### Memory Usage\n\n"
            md += "| Resource | Used | Total | Utilization |\n"
            md += "|----------|------|-------|-------------|\n"
            ns_ram_pct = (ns_metrics[9] / ns_metrics[10] * 100) if ns_metrics[10] > 0 else 0
            ns_flash_pct = (ns_metrics[11] / ns_metrics[12] * 100) if ns_metrics[12] > 0 else 0
            md += f"| NS RAM | {ns_metrics[9]:,} | {ns_metrics[10]:,} | {ns_ram_pct:.2f}% |\n"
            md += f"| NS Flash | {ns_metrics[11]:,} | {ns_metrics[12]:,} | {ns_flash_pct:.2f}% |\n"
        
        # S metrics
        if s_metrics:
            md += "\n## Secure (S) Metrics\n\n"
            md += "### Performance\n\n"
            md += f"- AES-256-GCM decrypt cycles: **{s_metrics[0]:,}**\n"
            md += f"- Quota validation cycles: **{s_metrics[1]:,}**\n"
            md += f"- SHA-256 compute cycles: **{s_metrics[2]:,}**\n"
            md += f"- Counter increment cycles: **{s_metrics[3]:,}**\n"
            
            md += "\n### Memory Usage\n\n"
            md += "| Resource | Used | Total | Utilization |\n"
            md += "|----------|------|-------|-------------|\n"
            s_ram_pct = (s_metrics[4] / s_metrics[5] * 100) if s_metrics[5] > 0 else 0
            s_flash_pct = (s_metrics[6] / s_metrics[7] * 100) if s_metrics[7] > 0 else 0
            md += f"| S RAM | {s_metrics[4]:,} | {s_metrics[5]:,} | {s_ram_pct:.2f}% |\n"
            md += f"| S Flash | {s_metrics[6]:,} | {s_metrics[7]:,} | {s_flash_pct:.2f}% |\n"
        
        md += "\n## Conclusion\n\n"
        if self.results['test_verdict'] == 'PASS':
            md += "✅ **Quota enforcement policy is working correctly.**\n"
            md += f"- Device correctly enforced max {MAX_QUOTA_LIMIT} inferences\n"
            md += f"- Inference #{INFERENCE_ATTEMPTS} was properly rejected when quota exhausted\n"
        else:
            md += "❌ **Quota enforcement policy validation failed.**\n"
        
        # Write report
        with open(report_path, 'w') as f:
            f.write(md)
        
        print(f"\n✓ Report generated: {report_path}\n")
        
        return str(report_path)
    
    def run_full_test(self) -> bool:
        """Execute full test sequence."""
        print("=" * 60)
        print("QUOTA ENFORCEMENT TEST - STM32L552")
        print("=" * 60 + "\n")
        
        if not self.connect():
            return False
        
        try:
            # Perform setup
            if not self.perform_ecdh_handshake():
                return False
            
            if not self.compute_enclave_info():
                return False
            
            if not self.send_m_update():
                return False
            
            # Run main test
            if not self.set_max_inferences(MAX_QUOTA_LIMIT):
                return False
            
            self.get_max_inferences()
            
            if not self.run_inference_sequence(INFERENCE_ATTEMPTS):
                return False
            
            if not self.retrieve_benchmarks():
                return False
            
            if not self.validate_quota_policy():
                return False
            
            # Generate report
            self.generate_report()
            
            print("=" * 60)
            print("TEST COMPLETED")
            print("=" * 60)
            
            return True
        
        finally:
            if self.ser:
                self.ser.close()

def main():
    """Main entry point."""
    tester = QuotaEnforcementTester(DEVICE_PORT, BAUDRATE)
    success = tester.run_full_test()
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
