#!/usr/bin/env python3
"""
Device Benchmark Tool - Retrieves performance metrics from STM32L552
Runs inference on device and captures memory/timing measurements via UART protocol.
"""

import sys
import time
import struct
import subprocess
import serial
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
import os


def analyze_elf_sections() -> dict:
    """Extract ELF sections and top symbols from build/zephyr/zephyr.elf."""
    elf_file = Path("build/zephyr/zephyr.elf")
    if not elf_file.exists():
        return None

    sdk_bin = Path("/Users/user/zephyr-sdk-0.17.4/arm-zephyr-eabi/bin")
    readelf_candidates = [
        sdk_bin / "arm-zephyr-eabi-readelf",
        Path("arm-zephyr-eabi-readelf"),
    ]
    nm_candidates = [
        sdk_bin / "arm-zephyr-eabi-nm",
        Path("arm-zephyr-eabi-nm"),
    ]

    def first_available(candidates):
        for c in candidates:
            if c.is_absolute() and c.exists():
                return str(c)
            if not c.is_absolute():
                return str(c)
        return None

    readelf_cmd = first_available(readelf_candidates)
    nm_cmd = first_available(nm_candidates)
    if not readelf_cmd or not nm_cmd:
        return None

    try:
        sections_proc = subprocess.run(
            [readelf_cmd, "-S", str(elf_file)],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if sections_proc.returncode != 0:
            return None

        sections = {}
        for line in sections_proc.stdout.splitlines():
            parts = line.split()
            # Expected format includes: [Nr] Name Type Addr Off Size ...
            if len(parts) >= 7 and parts[0].startswith("[") and parts[0] != "[Nr]":
                try:
                    name = parts[2] if parts[1].endswith("]") else parts[1]
                    size_hex = parts[6] if parts[1].endswith("]") else parts[5]
                    size = int(size_hex, 16)
                    if size > 0:
                        sections[name] = size
                except (ValueError, IndexError):
                    continue

        nm_proc = subprocess.run(
            [nm_cmd, "-S", str(elf_file)],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )

        symbols = []
        if nm_proc.returncode == 0:
            for line in nm_proc.stdout.splitlines():
                parts = line.split()
                # Typical: address size type name
                if len(parts) >= 4:
                    try:
                        size = int(parts[1], 16)
                        if size > 0:
                            symbols.append((parts[-1], size))
                    except ValueError:
                        continue

        symbols.sort(key=lambda x: x[1], reverse=True)
        return {
            "sections": sections,
            "top_symbols": symbols[:20],
        }
    except Exception:
        return None

# Protocol command codes (from uart_protocol.h)
CMD_COMPUTE_ENCLAVE_INFO = 0x01
CMD_VALIDATE_M_UPDATE = 0x02
CMD_GET_MAX_INFERENCES = 0x03
CMD_RUN_INFERENCE = 0x04
CMD_GET_INFERENCE_COUNT = 0x05
CMD_GET_REMAINING_INFERENCES = 0x06
CMD_GET_BENCHMARK = 0x08
CMD_GET_SECURE_BENCHMARK = 0x09
CMD_GET_INFERENCE_RESULT = 0x0A
CMD_ECDH_HANDSHAKE = 0x07
CMD_SET_MAX_INFERENCES = 0x0B
CMD_GET_DEVICE_PUBKEY   = 0x0C  # Return pk_d (65 B) for PoX verification

RESP_OK = 0x00
RESP_ERROR = 0xFF

# ECDH & M_update parameters (must match firmware)
HKDF_SALT = b'uart_protocol_v1_salt'
HKDF_INFO = b'uart_protocol_v1_session_key'

# Verifier key pair (sk_v, pk_v) is now generated dynamically inside run_benchmark_on_device()
# so that the private key sk_v is available to sign M_inf messages.

CIFAR10_LABELS = [
    'airplane', 'automobile', 'bird', 'cat', 'deer',
    'dog', 'frog', 'horse', 'ship', 'truck'
]

def decrypt_response(session_key: bytes, enc_data: bytes):
    """AES-256-GCM decrypt a device response: nonce(12) || ciphertext+tag."""
    if len(enc_data) < 28:
        return None
    nonce  = enc_data[:12]
    ct_tag = enc_data[12:]
    try:
        return AESGCM(session_key).decrypt(nonce, ct_tag, None)
    except Exception:
        return None

def encrypt_command(session_key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt a command payload: returns nonce(12) || ciphertext+tag."""
    nonce  = os.urandom(12)
    ct_tag = AESGCM(session_key).encrypt(nonce, plaintext, None)
    return nonce + ct_tag

def find_device_port(device_pattern: str = None) -> str:
    """Find the STM32 device port."""
    import glob
    
    if device_pattern:
        ports = glob.glob(device_pattern)
        if ports:
            return ports[0]
    
    # Try common patterns
    patterns = [
        "/dev/tty.usbmodem*",
        "/dev/ttyACM*",
        "/dev/ttyUSB*",
    ]
    
    for pattern in patterns:
        ports = glob.glob(pattern)
        if ports:
            return ports[0]
    
    return None

CMD_NAMES = {
    0x01: 'CMD_COMPUTE_ENCLAVE_INFO',
    0x02: 'CMD_VALIDATE_M_UPDATE',
    0x03: 'CMD_GET_MAX_INFERENCES',
    0x04: 'CMD_RUN_INFERENCE',
    0x05: 'CMD_GET_INFERENCE_COUNT',
    0x06: 'CMD_GET_REMAINING_INFERENCES',
    0x07: 'CMD_ECDH_HANDSHAKE',
    0x08: 'CMD_GET_BENCHMARK',
    0x09: 'CMD_GET_SECURE_BENCHMARK',
    0x0A: 'CMD_GET_INFERENCE_RESULT',
    0x0B: 'CMD_SET_MAX_INFERENCES',
    0x0C: 'CMD_GET_DEVICE_PUBKEY',
}

VERBOSE = True

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def send_command(ser: serial.Serial, cmd: int, data: bytes = b'') -> tuple:
    """
    Send command to device via UART protocol.
    Format: [CMD:1][LEN:4 LE][DATA:n]
    Response: [STATUS:1][DATA:n]
    """
    cmd_name = CMD_NAMES.get(cmd, f'CMD_0x{cmd:02X}')
    vprint(f"      → TX  {cmd_name} (0x{cmd:02X})  data={len(data)}B"
           + (f"  [{data[:8].hex()}{'...' if len(data)>8 else ''}]" if data else ""))

    # Drop any pending debug/boot bytes before command transaction
    try:
        ser.reset_input_buffer()
    except Exception:
        pass

    payload = struct.pack('<BI', cmd, len(data)) + data
    ser.write(payload)

    # Read response status, skipping non-protocol bytes if logs are interleaved.
    status = None
    skipped = 0
    for _ in range(256):
        status_byte = ser.read(1)
        if not status_byte:
            break
        b = status_byte[0]
        if b in (RESP_OK, RESP_ERROR):
            status = b
            break
        skipped += 1

    if skipped:
        vprint(f"      ⚠ skipped {skipped} non-protocol byte(s) before status")

    if status is None:
        vprint(f"      ✗ no response (timeout)")
        return None, None

    # Read response length (4 bytes LE)
    len_bytes = ser.read(4)
    if len(len_bytes) < 4:
        vprint(f"      ✗ incomplete length field ({len(len_bytes)} B)")
        return status, None

    response_len = struct.unpack('<I', len_bytes)[0]

    # Read response data
    response_data = ser.read(response_len) if response_len > 0 else b''

    status_str = 'OK' if status == RESP_OK else f'ERROR(0x{status:02X})'
    vprint(f"      ← RX  {status_str}  data={response_len}B"
           + (f"  [{response_data[:8].hex()}{'...' if len(response_data)>8 else ''}]" if response_data else ""))

    return status, response_data

def run_benchmark_on_device(port: str, baudrate: int = 115200) -> dict:
    """
    Run full benchmark sequence on device:
    1. ECDH handshake
    2. Compute enclave info
    3. Send M_update (authorization)
    4. Run inference
    5. Retrieve benchmark metrics
    """
    
    try:
        ser = serial.Serial(port, baudrate, timeout=2)
        print(f"✓ Connected to {port} at {baudrate} baud\n")
    except serial.SerialException as e:
        print(f"✗ Failed to open {port}: {e}")
        return None
    
    time.sleep(0.5)  # Wait for device to be ready
    try:
        ser.reset_input_buffer()
        ser.reset_output_buffer()
    except Exception:
        pass
    
    metrics = {}
    session_key = None
    
    try:
        # Step 1: ECDH Handshake
        print("[1] Performing ECDH handshake...")
        
        # Generate Mac ephemeral key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        # Export uncompressed public key (0x04 || x || y)
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Send ECDH handshake
        status, device_pubkey_data = send_command(ser, CMD_ECDH_HANDSHAKE, public_bytes)
        
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
            session_key = hkdf.derive(shared_secret)
            
            print(f"    ✓ Session key established: {session_key.hex()[:32]}...")
            metrics['ecdh_success'] = True
        else:
            print(f"    ✗ ECDH failed")
            metrics['ecdh_success'] = False
            return metrics

        # Step 1b: Get device signing public key pk_d (for PoX verification)
        print("\n" + "─"*60)
        print("[1b] Device signing key pk_d  (for PoX verification)")
        print("─"*60)
        pk_d_ec = None
        status_pkd, device_pk_d_bytes = send_command(ser, CMD_GET_DEVICE_PUBKEY)
        if status_pkd == RESP_OK and device_pk_d_bytes and len(device_pk_d_bytes) == 65:
            try:
                pk_d_ec = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), device_pk_d_bytes
                )
                vprint(f"    pk_d (full 65B):  {device_pk_d_bytes.hex()}")
                print(f"    ✓ pk_d received and parsed  (P-256 uncompressed, {len(device_pk_d_bytes)}B)")
                metrics['device_pk_d'] = device_pk_d_bytes.hex()
            except Exception as e:
                print(f"    ✗ pk_d parse failed: {e}")
        else:
            print(f"    ⚠ CMD_GET_DEVICE_PUBKEY not available (status={status_pkd})")

        # Generate Verifier key pair (sk_v, pk_v) for M_inf signing
        print("\n" + "─"*60)
        print("[1c] Verifier key pair  (sk_v, pk_v)")
        print("─"*60)
        verifier_key    = ec.generate_private_key(ec.SECP256R1(), default_backend())
        verifier_pubkey = verifier_key.public_key()
        vk_full  = verifier_pubkey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )  # 65 bytes: 0x04 || x(32) || y(32)
        pk_v_raw = vk_full[1:]  # 64 bytes raw x||y (no 0x04 prefix)
        vprint(f"    pk_v (raw 64B):   {pk_v_raw.hex()}")
        print(f"    ✓ Verifier key pair generated  (pk_v={len(pk_v_raw)}B raw x||y)")        
        # Step 2: Compute enclave info
        print("\n" + "─"*60)
        print("[2] EnclaveInfo = SHA256(Model_pub || Model_secret || code || model_id)")
        print("─"*60)
        model_pub    = bytes([0xC0 + i for i in range(32)])
        model_secret = bytes([0xE0 + i for i in range(32)])
        code_hash    = bytes([0x01 + i for i in range(32)])
        model_id     = 0x00000001
        test_data    = model_pub + model_secret + code_hash + struct.pack('<I', model_id)
        vprint(f"    model_pub:    {model_pub.hex()}")
        vprint(f"    model_secret: {model_secret.hex()}")
        vprint(f"    code_hash:    {code_hash.hex()}")
        vprint(f"    model_id:     0x{model_id:08X}")
        vprint(f"    input total:  {len(test_data)}B sent to device")

        status, enc_data = send_command(ser, CMD_COMPUTE_ENCLAVE_INFO, test_data)
        enclave_info = None
        if status == RESP_OK and enc_data:
            vprint(f"    encrypted resp: {len(enc_data)}B  [{enc_data[:16].hex()}...]")
            enclave_info = decrypt_response(session_key, enc_data) if session_key else enc_data

        if enclave_info:
            vprint(f"    EnclaveInfo (decrypted 32B): {enclave_info.hex()}")
            print(f"    ✓ EnclaveInfo computed  ({len(enclave_info)}B): {enclave_info.hex()[:32]}...")
            metrics['enclave_info'] = enclave_info.hex()
        else:
            print(f"    ✗ Failed to compute EnclaveInfo  (status={status}, enc_data={enc_data})")
            return metrics
        
        # Step 3: Send M_update with strictly increasing quota (anti-replay safe)
        status_cur, data_cur = send_command(ser, CMD_GET_MAX_INFERENCES)
        current_limit = 0
        if status_cur == RESP_OK and data_cur and len(data_cur) >= 4:
            current_limit = struct.unpack('<I', data_cur[:4])[0]

        c_limit = max(10, current_limit + 10)
        print(f"[3] Sending M_update (quota={c_limit})...")
        
        if session_key:
            # Create M_update plaintext
            # Layout: c_limit(4) || pk_v(64) || enclave_info(32) || cert_len(4) || cert(n)
            # cert[0..3] = model_id (LE uint32) — used by device for M_inf model_id check
            cert = struct.pack('<I', model_id) + bytes(range(16))  # 20 bytes total

            plaintext  = struct.pack('<I', c_limit)      # c_limit  (4 bytes)
            plaintext += pk_v_raw                        # pk_v     (64 bytes raw x||y)
            plaintext += enclave_info                    # EnclaveInfo (32 bytes)
            plaintext += struct.pack('<I', len(cert))    # cert_len (4 bytes)
            plaintext += cert                            # cert     (20 bytes)
            # Total plaintext: 4+64+32+4+20 = 124 bytes
            
            # Encrypt with AES-256-GCM
            nonce = os.urandom(12)
            cipher = AESGCM(session_key)
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext, None)
            
            # Split: nonce(12) + ciphertext(120) + tag(16)
            m_update_packet = nonce + ciphertext_with_tag
            
            status, _ = send_command(ser, CMD_VALIDATE_M_UPDATE, m_update_packet)
            
            if status == RESP_OK:
                print(f"    ✓ M_update validated (quota set to {c_limit})")
                metrics['m_update_success'] = True
                metrics['m_update_quota'] = c_limit
            else:
                print(f"    ✗ M_update failed with status {status}")
                metrics['m_update_success'] = False
                return metrics
        
        # Step 4: Get max inferences after M_update
        print("\n" + "─"*60)
        print("[4] Quota check after M_update")
        print("─"*60)
        status, data = send_command(ser, CMD_GET_MAX_INFERENCES)
        if status == RESP_OK and data:
            max_inf = struct.unpack('<I', data[:4])[0]
            print(f"    ✓ max_inferences = {max_inf}")
            metrics['quota_after_m_update'] = max_inf
        
        # Step 5: Run 5 inferences and capture prediction/expected each time
        num_inferences = 5
        print(f"[5] Running {num_inferences} inferences...")
        metrics['inference_runs'] = []
        host_times_ms = []

        for i in range(num_inferences):
            # Build M_inf: nonce_inf(32) || model_id(4) || Sign(sk_v, SHA256(nonce_inf||model_id))(64)
            nonce_inf      = os.urandom(32)
            model_id_bytes = struct.pack('<I', model_id)
            msg_to_sign    = nonce_inf + model_id_bytes           # 36 bytes
            sig_der        = verifier_key.sign(msg_to_sign, ec.ECDSA(hashes.SHA256()))
            r_v, s_v       = decode_dss_signature(sig_der)
            sig_v_raw      = r_v.to_bytes(32, 'big') + s_v.to_bytes(32, 'big')  # 64 bytes raw r||s
            minf_plain     = nonce_inf + model_id_bytes + sig_v_raw              # 100 bytes
            minf_enc       = encrypt_command(session_key, minf_plain)            # 128 bytes encrypted

            start_time = time.time()
            status, inf_response_enc = send_command(ser, CMD_RUN_INFERENCE, minf_enc)
            elapsed_host_ms = (time.time() - start_time) * 1000

            run_item = {
                'index': i + 1,
                'status': status,
                'host_time_ms': elapsed_host_ms,
            }

            if status == RESP_OK:
                pred      = None
                pox_valid = False

                # Decrypt inference response: output_class(1) || pox_sig(64)
                if inf_response_enc:
                    vprint(f"    response encrypted ({len(inf_response_enc)}B): [{inf_response_enc[:16].hex()}...]")
                    inf_plain = decrypt_response(session_key, inf_response_enc)
                    if inf_plain and len(inf_plain) >= 65:
                        pred        = inf_plain[0]
                        pox_sig_raw = inf_plain[1:65]  # 64 bytes raw r||s
                        vprint(f"    response decrypted ({len(inf_plain)}B): output={pred}  pox_r={pox_sig_raw[:8].hex()}...")

                        # Verify PoX = Sign(sk_d, SHA256(model_id||cert||nonce_inf||output))
                        if pk_d_ec is not None:
                            try:
                                pox_msg = model_id_bytes + cert + nonce_inf + bytes([pred])
                                vprint(f"    PoX msg ({len(pox_msg)}B): model_id(4)+cert({len(cert)})+nonce_inf(32)+output(1)")
                                r_d = int.from_bytes(pox_sig_raw[:32], 'big')
                                s_d = int.from_bytes(pox_sig_raw[32:], 'big')
                                pk_d_ec.verify(encode_dss_signature(r_d, s_d),
                                               pox_msg, ec.ECDSA(hashes.SHA256()))
                                pox_valid = True
                                vprint(f"    PoX signature: VALID ✓")
                            except Exception as e:
                                pox_valid = False
                                vprint(f"    PoX signature: INVALID ✗  ({e})")
                        else:
                            vprint(f"    PoX skipped (pk_d not available)")
                    else:
                        vprint(f"    ✗ decrypt failed or too short ({len(inf_plain) if inf_plain else 0}B)")

                # Get expected label via CMD_GET_INFERENCE_RESULT
                st_res, data_res = send_command(ser, CMD_GET_INFERENCE_RESULT)
                exp = None
                if st_res == RESP_OK and data_res and len(data_res) >= 2:
                    if pred is None:
                        pred = data_res[0]   # fallback if encrypted response unavailable
                    exp = data_res[1]
                    vprint(f"    GET_INFERENCE_RESULT: raw pred={data_res[0]}  exp={data_res[1]}")

                run_item['prediction']       = pred
                run_item['expected']         = exp
                run_item['pox_valid']        = pox_valid
                run_item['prediction_label'] = CIFAR10_LABELS[pred] if pred is not None and pred < len(CIFAR10_LABELS) else f"unknown({pred})"
                run_item['expected_label']   = CIFAR10_LABELS[exp]  if exp  is not None and exp  < len(CIFAR10_LABELS) else f"unknown({exp})"
                run_item['match'] = (pred == exp) if pred is not None and exp is not None else False

                host_times_ms.append(elapsed_host_ms)
                ok_mark  = "✓" if run_item.get('match') else "✗"
                pox_mark = "✓PoX" if pox_valid else "✗PoX"
                print(
                    f"    ✓ {elapsed_host_ms:.1f} ms | "
                    f"pred={run_item['prediction']} ({run_item['prediction_label']}) | "
                    f"expected={run_item['expected']} ({run_item['expected_label']}) {ok_mark} | {pox_mark}"
                )
            else:
                print(f"    ✗ CMD_RUN_INFERENCE failed — status=0x{status:02X}")

            metrics['inference_runs'].append(run_item)

        # Aggregate inference status
        success_runs = [r for r in metrics['inference_runs'] if r.get('status') == RESP_OK]
        metrics['inference_success'] = len(success_runs) == num_inferences
        metrics['inference_count_requested'] = num_inferences
        metrics['inference_count_success'] = len(success_runs)
        if host_times_ms:
            metrics['inference_time_host_ms_avg'] = sum(host_times_ms) / len(host_times_ms)
            metrics['inference_time_host_ms_total'] = sum(host_times_ms)
            # Keep backward-compatible single key
            metrics['inference_time_host_ms'] = metrics['inference_time_host_ms_avg']

        # Step 6: Get inference count
        print("\n" + "─"*60)
        print("[6] Post-run telemetry")
        print("─"*60)
        status, data = send_command(ser, CMD_GET_INFERENCE_COUNT)
        if status == RESP_OK and data:
            count = struct.unpack('<I', data[:4])[0]
            print(f"    inference_count:     {count}")
            metrics['inference_count'] = count

        # Step 7: Remaining quota
        print("\n" + "─"*60)
        print("[7] Post-run Quota Check")
        print("─"*60)
        status, data = send_command(ser, CMD_GET_REMAINING_INFERENCES)
        if status == RESP_OK and data:
            remaining = struct.unpack('<I', data[:4])[0]
            print(f"    remaining_quota:     {remaining}")
            metrics['remaining_quota'] = remaining
        
        # Step 8: NS benchmark
        print("\n" + "─"*60)
        print("[8] NS Benchmark Metrics")
        print("─"*60)
        status, data = send_command(ser, CMD_GET_BENCHMARK)
        _cy2ms = lambda c: c / 110_000.0  # 110 MHz → ms

        if status == RESP_OK and data and len(data) >= 72:  # 18 x uint32_t = 72 bytes
            vprint(f"    raw ({len(data)}B): [{data[:16].hex()}...]")

            # Parse benchmark_metrics_t structure (18 x uint32_t)
            values = struct.unpack('<18I', data[:72])

            metrics['enclave_create_cycles']  = values[0]
            metrics['enclave_destroy_cycles'] = values[1]
            metrics['aes_decrypt_cycles']     = values[2]
            metrics['late_hash_cycles']       = values[3]
            metrics['inference_hash_cycles']  = values[4]
            metrics['early_layers_cycles']    = values[5]
            metrics['late_layers_cycles']     = values[6]
            metrics['total_inference_cycles'] = values[7]
            metrics['run_enclave_cycles']     = values[8]
            metrics['heap_used_bytes']        = values[9]
            metrics['heap_free_bytes']        = values[10]
            metrics['stack_used_bytes']       = values[11]
            metrics['ram_used_bytes']         = values[12]
            metrics['ram_total_bytes']        = values[13]
            metrics['flash_used_bytes']       = values[14]
            metrics['flash_total_bytes']      = values[15]
            metrics['inference_count']        = values[16]
            metrics['enclave_recreations']    = values[17]

            # Convert cycles to ms @ 110 MHz
            cpu_freq_mhz = 110
            for k in ('enclave_create', 'early_layers', 'late_layers', 'total_inference'):
                cyc = metrics.get(f'{k}_cycles', 0)
                if cyc > 0:
                    metrics[f'{k}_ms'] = cyc / (cpu_freq_mhz * 1000)

            vprint(f"    enclave_create:    {values[0]:>12,} cy  ({_cy2ms(values[0]):.2f} ms)")
            vprint(f"    enclave_destroy:   {values[1]:>12,} cy  ({_cy2ms(values[1]):.2f} ms)")
            vprint(f"    aes_decrypt:       {values[2]:>12,} cy  ({_cy2ms(values[2]):.2f} ms)")
            vprint(f"    late_hash:         {values[3]:>12,} cy  ({_cy2ms(values[3]):.2f} ms)")
            vprint(f"    inference_hash:    {values[4]:>12,} cy  ({_cy2ms(values[4]):.2f} ms)")
            vprint(f"    early_layers:      {values[5]:>12,} cy  ({_cy2ms(values[5]):.2f} ms)")
            vprint(f"    late_layers:       {values[6]:>12,} cy  ({_cy2ms(values[6]):.2f} ms)")
            vprint(f"    total_inference:   {values[7]:>12,} cy  ({_cy2ms(values[7]):.2f} ms)")
            vprint(f"    run_enclave:       {values[8]:>12,} cy  ({_cy2ms(values[8]):.2f} ms)")
            vprint(f"    heap_used:         {values[9]:>12,} B")
            vprint(f"    heap_free:         {values[10]:>12,} B")
            vprint(f"    stack_used:        {values[11]:>12,} B")
            vprint(f"    ram_used:          {values[12]:>12,} / {values[13]:,} B  ({values[12]/values[13]*100:.1f}%)")
            vprint(f"    flash_used:        {values[14]:>12,} / {values[15]:,} B  ({values[14]/values[15]*100:.1f}%)")
            vprint(f"    inference_count:   {values[16]:>12,}")
            vprint(f"    enclave_recr:      {values[17]:>12,}")
            print(f"    ✓ early={metrics['early_layers_cycles']:,} cy ({metrics.get('early_layers_ms',0):.1f} ms) | "
                  f"late={metrics['late_layers_cycles']:,} cy ({metrics.get('late_layers_ms',0):.1f} ms) | "
                  f"total={metrics['total_inference_cycles']:,} cy ({metrics.get('total_inference_ms',0):.1f} ms)")
            print(f"    ✓ RAM {metrics['ram_used_bytes']:,}/{metrics['ram_total_bytes']:,} B "
                  f"({metrics['ram_used_bytes']/metrics['ram_total_bytes']*100:.1f}%)  "
                  f"Flash {metrics['flash_used_bytes']:,}/{metrics['flash_total_bytes']:,} B "
                  f"({metrics['flash_used_bytes']/metrics['flash_total_bytes']*100:.1f}%)")
        else:
            print(f"    ✗ NS benchmark not available (status={status}, data={len(data) if data else 0}B)")
        
        # Step 9: Secure benchmark
        print("\n" + "─"*60)
        print("[9] Secure Benchmark Metrics")
        print("─"*60)
        status, s_data = send_command(ser, CMD_GET_SECURE_BENCHMARK)

        if status == RESP_OK and s_data and len(s_data) >= 88:
            vprint(f"    raw ({len(s_data)}B): [{s_data[:16].hex()}...]")
            # 7 x uint64_t + 8 x uint32_t = 88 bytes
            s_values = struct.unpack('<7Q8I', s_data[:88])

            # Cycle counts (7 x uint64_t)
            metrics['s_aes_decrypt_cycles']       = s_values[0]
            metrics['s_late_hash_cycles']         = s_values[1]
            metrics['s_digest_compute_cycles']    = s_values[2]
            metrics['s_get_max_cycles']           = s_values[3]
            metrics['s_check_allowed_cycles']     = s_values[4]
            metrics['s_counter_increment_cycles'] = s_values[5]
            metrics['s_reset_cycles']             = s_values[6]

            # Operation counts and memory (8 x uint32_t)
            metrics['s_aes_operations']   = s_values[7]
            metrics['s_hash_operations']  = s_values[8]
            metrics['s_digest_operations']= s_values[9]
            metrics['s_counter_operations']= s_values[10]
            metrics['s_ram_used']         = s_values[11]
            metrics['s_ram_total']        = s_values[12]
            metrics['s_flash_used']       = s_values[13]
            metrics['s_flash_total']      = s_values[14]

            vprint(f"    aes_decrypt:       {s_values[0]:>14,} cy  ({_cy2ms(s_values[0]):.2f} ms) x{s_values[7]}")
            vprint(f"    late_hash:         {s_values[1]:>14,} cy  ({_cy2ms(s_values[1]):.2f} ms) x{s_values[8]}")
            vprint(f"    digest_compute:    {s_values[2]:>14,} cy  ({_cy2ms(s_values[2]):.2f} ms) x{s_values[9]}")
            vprint(f"    get_max:           {s_values[3]:>14,} cy  ({_cy2ms(s_values[3]):.2f} ms)")
            vprint(f"    check_allowed:     {s_values[4]:>14,} cy  ({_cy2ms(s_values[4]):.2f} ms)")
            vprint(f"    counter_incr:      {s_values[5]:>14,} cy  ({_cy2ms(s_values[5]):.2f} ms)")
            vprint(f"    reset:             {s_values[6]:>14,} cy  ({_cy2ms(s_values[6]):.2f} ms)")
            vprint(f"    counter_ops total: {s_values[10]:>14,}")
            vprint(f"    S RAM:  {s_values[11]:,} / {s_values[12]:,} B  ({s_values[11]/s_values[12]*100:.1f}%)")
            vprint(f"    S Flash:{s_values[13]:,} / {s_values[14]:,} B  ({s_values[13]/s_values[14]*100:.1f}%)")
            print(f"    ✓ aes_decrypt={metrics['s_aes_decrypt_cycles']:,} cy ({_cy2ms(metrics['s_aes_decrypt_cycles']):.1f} ms) x{metrics['s_aes_operations']}")
            print(f"    ✓ S RAM {metrics['s_ram_used']:,}/{metrics['s_ram_total']:,} B "
                  f"({metrics['s_ram_used']/metrics['s_ram_total']*100:.1f}%)  "
                  f"S Flash {metrics['s_flash_used']:,}/{metrics['s_flash_total']:,} B "
                  f"({metrics['s_flash_used']/metrics['s_flash_total']*100:.1f}%)")
        else:
            print(f"    ✗ Secure benchmark not available (status={status}, data={len(s_data) if s_data else 0}B)")

        print("\n" + "─"*60)
        
    finally:
        ser.close()
    
    return metrics

def format_report(metrics: dict) -> str:
    """Format benchmark metrics into detailed report (BENCHMARK_RESULTS.md style)."""
    
    CPU_FREQ_MHZ = 110.0
    
    def cycles_to_ms(cycles):
        return cycles / (CPU_FREQ_MHZ * 1000)
    
    from datetime import datetime
    date_str = datetime.now().strftime("%d %B %Y")
    
    report = f"""# Performance Benchmark Results

**Date:** {date_str}  
**Platform:** STM32L552ZE-Q (Cortex-M33 @ 110 MHz)  
**Configuration:** TrustZone-M, TF-M Secure partition, CMSIS-NN optimized  
**Test:** Single inference with ECDH handshake and M_update (quota={metrics.get('m_update_quota', 'N/A')})

## Complete Results

```
╔══════════════════════════════════════════════════════════════╗
║        NON-SECURE (NS) BENCHMARK RESULTS                    ║
╠══════════════════════════════════════════════════════════════╣
║ ENCLAVE LIFECYCLE                                            ║
╟──────────────────────────────────────────────────────────────╢
"""
    
    # NS Lifecycle
    if 'enclave_create_cycles' in metrics:
        cyc = metrics['enclave_create_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ Create:    {cyc:>10,} cycles  ({ms:>8.1f} ms)               ║\n"
    if 'enclave_destroy_cycles' in metrics:
        cyc = metrics['enclave_destroy_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ Destroy:   {cyc:>10,} cycles  ({ms:>8.1f} ms)               ║\n"
    
    # NS Crypto
    report += """╟──────────────────────────────────────────────────────────────╢
║ CRYPTOGRAPHIC OPERATIONS                                     ║
╟──────────────────────────────────────────────────────────────╢
"""
    
    if 'aes_decrypt_cycles' in metrics:
        cyc = metrics['aes_decrypt_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ AES Decrypt: {cyc:>10,} cycles  ({ms:>8.1f} ms)               ║\n"
    if 'late_hash_cycles' in metrics:
        cyc = metrics['late_hash_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ Late Hash:   {cyc:>10,} cycles  ({ms:>8.1f} ms)               ║\n"
    if 'inference_hash_cycles' in metrics:
        cyc = metrics['inference_hash_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ Inference Hash: {cyc:>7,} cycles  ({ms:>8.1f} ms)               ║\n"
    
    # NS Inference
    report += """╟──────────────────────────────────────────────────────────────╢
║ INFERENCE PERFORMANCE                                        ║
╟──────────────────────────────────────────────────────────────╢
"""
    
    if 'early_layers_cycles' in metrics:
        cyc = metrics['early_layers_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ Early Layers: {cyc:>9,} cycles  ({ms:>7.1f} ms)              ║\n"
    if 'late_layers_cycles' in metrics:
        cyc = metrics['late_layers_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ Late Layers: {cyc:>10,} cycles  ({ms:>8.1f} ms)              ║\n"
    if 'total_inference_cycles' in metrics:
        cyc = metrics['total_inference_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ Total Inf:   {cyc:>10,} cycles  ({ms:>8.1f} ms)              ║\n"
    
    # NS End-to-end
    report += """╟──────────────────────────────────────────────────────────────╢
║ END-TO-END METRICS                                           ║
╟──────────────────────────────────────────────────────────────╢
"""
    
    if 'run_enclave_cycles' in metrics:
        cyc = metrics['run_enclave_cycles']
        ms = cycles_to_ms(cyc)
        report += f"║ run_enclave(): {cyc:>8,} cycles  ({ms:>7.1f} ms)             ║\n"
    if 'inference_count' in metrics:
        count = metrics['inference_count']
        report += f"║ Inferences:    {count:>10,} total                              ║\n"
    
    # NS Memory
    report += """╟──────────────────────────────────────────────────────────────╢
║ MEMORY USAGE (NS World)                                      ║
╟──────────────────────────────────────────────────────────────╢
"""
    
    if 'heap_used_bytes' in metrics:
        heap = metrics['heap_used_bytes']
        report += f"║ Heap Used:   {heap:>10,} bytes  ({heap/1024:>8.0f} KB)                   ║\n"
    if 'stack_used_bytes' in metrics:
        stack = metrics['stack_used_bytes']
        report += f"║ Stack Used:  {stack:>10,} bytes  ({stack/1024:>8.0f} KB)                   ║\n"
    if 'ram_used_bytes' in metrics and 'ram_total_bytes' in metrics:
        used = metrics['ram_used_bytes']
        total = metrics['ram_total_bytes']
        pct = (used / total * 100) if total > 0 else 0
        report += f"║ RAM Used:    {used:>10,} / {total:,} bytes ({pct:.1f}%)              ║\n"
    if 'flash_used_bytes' in metrics and 'flash_total_bytes' in metrics:
        used = metrics['flash_used_bytes']
        total = metrics['flash_total_bytes']
        pct = (used / total * 100) if total > 0 else 0
        report += f"║ Flash Used:  {used:>10,} / {total:,} bytes ({pct:.1f}%)              ║\n"
    
    report += "╚══════════════════════════════════════════════════════════════╝\n\n"
    
    # Secure World
    if 's_aes_decrypt_cycles' in metrics:
        report += """╔══════════════════════════════════════════════════════════════╗
║        SECURE (S) BENCHMARK RESULTS                         ║
╠══════════════════════════════════════════════════════════════╣
║ CRYPTOGRAPHIC OPERATIONS                                     ║
╟──────────────────────────────────────────────────────────────╢
"""
        
        cyc = metrics['s_aes_decrypt_cycles']
        ms = cycles_to_ms(cyc)
        ops = metrics.get('s_aes_operations', 0)
        report += f"║ AES Decrypt: {cyc:>10,} cycles  ({ms:>8.1f} ms) [{ops} ops]       ║\n"
        
        if 's_late_hash_cycles' in metrics:
            cyc = metrics['s_late_hash_cycles']
            ms = cycles_to_ms(cyc)
            ops = metrics.get('s_hash_operations', 0)
            report += f"║ Late Hash:   {cyc:>10,} cycles  ({ms:>8.1f} ms) [{ops} ops]       ║\n"
        
        if 's_digest_compute_cycles' in metrics:
            cyc = metrics['s_digest_compute_cycles']
            ms = cycles_to_ms(cyc)
            ops = metrics.get('s_digest_operations', 0)
            report += f"║ Digest Compute: {cyc:>7,} cycles  ({ms:>8.1f} ms) [{ops} ops]       ║\n"
        
        # Counter Management
        report += """╟──────────────────────────────────────────────────────────────╢
║ COUNTER MANAGEMENT                                           ║
╟──────────────────────────────────────────────────────────────╢
"""
        
        if 's_get_max_cycles' in metrics:
            cyc = metrics['s_get_max_cycles']
            ms = cycles_to_ms(cyc)
            report += f"║ Get Max:     {cyc:>10,} cycles  ({ms:>8.1f} ms)               ║\n"
        
        if 's_check_allowed_cycles' in metrics:
            cyc = metrics['s_check_allowed_cycles']
            ms = cycles_to_ms(cyc)
            report += f"║ Check Allowed: {cyc:>8,} cycles  ({ms:>8.1f} ms)               ║\n"
        
        if 's_counter_increment_cycles' in metrics:
            cyc = metrics['s_counter_increment_cycles']
            ms = cycles_to_ms(cyc)
            report += f"║ Increment:   {cyc:>10,} cycles  ({ms:>8.1f} ms)               ║\n"
        
        if 's_reset_cycles' in metrics:
            cyc = metrics['s_reset_cycles']
            ms = cycles_to_ms(cyc)
            report += f"║ Reset:       {cyc:>10,} cycles  ({ms:>8.1f} ms)               ║\n"
        
        if 's_counter_operations' in metrics:
            ops = metrics['s_counter_operations']
            report += f"║ Total Ops:   {ops:>10,} operations                    ║\n"
        
        # S Memory
        report += """╟──────────────────────────────────────────────────────────────╢
║ MEMORY USAGE (Secure World)                                 ║
╟──────────────────────────────────────────────────────────────╢
"""
        
        if 's_ram_used' in metrics and 's_ram_total' in metrics:
            used = metrics['s_ram_used']
            total = metrics['s_ram_total']
            pct = (used / total * 100) if total > 0 else 0
            report += f"║ RAM Used:    {used:>10,} / {total:,} bytes ({pct:.1f}%)               ║\n"
        
        if 's_flash_used' in metrics and 's_flash_total' in metrics:
            used = metrics['s_flash_used']
            total = metrics['s_flash_total']
            pct = (used / total * 100) if total > 0 else 0
            report += f"║ Flash Used:  {used:>10,} / {total:,} bytes ({pct:.1f}%)              ║\n"
        
        report += "╚══════════════════════════════════════════════════════════════╝\n\n"
    
    # Combined metrics
    if 'ram_used_bytes' in metrics and 's_ram_used' in metrics:
        report += """╔══════════════════════════════════════════════════════════════╗
║        COMBINED SYSTEM METRICS                              ║
╠══════════════════════════════════════════════════════════════╣
"""
        
        ns_ram = metrics['ram_used_bytes']
        s_ram = metrics['s_ram_used']
        ns_ram_total = metrics['ram_total_bytes']
        s_ram_total = metrics['s_ram_total']
        total_ram_used = ns_ram + s_ram
        total_ram = ns_ram_total + s_ram_total
        ram_pct = (total_ram_used / total_ram * 100) if total_ram > 0 else 0
        
        report += f"║ Total RAM:   {total_ram_used:>10,} / {total_ram:,} bytes ({ram_pct:.1f}%)             ║\n"
        
        if 'flash_used_bytes' in metrics and 's_flash_used' in metrics:
            ns_flash = metrics['flash_used_bytes']
            s_flash = metrics['s_flash_used']
            ns_flash_total = metrics['flash_total_bytes']
            s_flash_total = metrics['s_flash_total']
            total_flash_used = ns_flash + s_flash
            total_flash = ns_flash_total + s_flash_total
            flash_pct = (total_flash_used / total_flash * 100) if total_flash > 0 else 0
            
            report += f"║ Total Flash: {total_flash_used:>10,} / {total_flash:,} bytes ({flash_pct:.1f}%)             ║\n"
        
        report += "╚══════════════════════════════════════════════════════════════╝\n"
    
    report += "```\n\n"
    
    # Summary section
    report += "## Summary\n\n"
    
    if 'inference_time_host_ms' in metrics:
        report += f"- **Host-measured inference time (avg)**: {metrics['inference_time_host_ms']:.1f} ms\n"

    if 'inference_time_host_ms_total' in metrics:
        report += f"- **Host-measured inference time (total)**: {metrics['inference_time_host_ms_total']:.1f} ms\n"
    
    if 'total_inference_cycles' in metrics:
        cyc = metrics['total_inference_cycles']
        ms = cycles_to_ms(cyc)
        report += f"- **Device total inference cycles**: {cyc:,} ({ms:.1f} ms @ 110 MHz)\n"
    
    if 'ecdh_success' in metrics:
        report += f"- **ECDH handshake**: {'✓ SUCCESS' if metrics['ecdh_success'] else '✗ FAILED'}\n"
    
    if 'm_update_success' in metrics:
        report += f"- **M_update validation**: {'✓ SUCCESS' if metrics['m_update_success'] else '✗ FAILED'}\n"
    
    if 'inference_success' in metrics:
        report += f"- **Inference execution**: {'✓ SUCCESS' if metrics['inference_success'] else '✗ FAILED'}\n"
    
    report += "\n"

    # Detailed per-inference results
    if 'inference_runs' in metrics and metrics['inference_runs']:
        report += "## Inference Results (5 runs)\n\n"
        report += "| Run | Status | Prediction | Expected | Match | Host time (ms) |\n"
        report += "|---|---|---|---|---|---:|\n"
        for run in metrics['inference_runs']:
            if run.get('status') == RESP_OK:
                pred = f"{run.get('prediction')} ({run.get('prediction_label')})"
                exp = f"{run.get('expected')} ({run.get('expected_label')})"
                match = "✓" if run.get('match') else "✗"
                status_txt = "OK"
            else:
                pred = "N/A"
                exp = "N/A"
                match = "-"
                status_txt = f"ERR({run.get('status')})"

            report += (
                f"| {run.get('index')} | {status_txt} | {pred} | {exp} | "
                f"{match} | {run.get('host_time_ms', 0):.1f} |\n"
            )
        report += "\n"

    # NS vs Secure footprint share
    report += "## Memory Footprint Share (NS vs Secure)\n\n"
    if all(k in metrics for k in [
        'ram_used_bytes', 'ram_total_bytes', 'flash_used_bytes', 'flash_total_bytes',
        's_ram_used', 's_ram_total', 's_flash_used', 's_flash_total'
    ]):
        ns_ram_used = metrics['ram_used_bytes']
        s_ram_used = metrics['s_ram_used']
        total_ram_used = ns_ram_used + s_ram_used

        ns_flash_used = metrics['flash_used_bytes']
        s_flash_used = metrics['s_flash_used']
        total_flash_used = ns_flash_used + s_flash_used

        ns_ram_total = metrics['ram_total_bytes']
        s_ram_total = metrics['s_ram_total']
        total_ram_cap = ns_ram_total + s_ram_total

        ns_flash_total = metrics['flash_total_bytes']
        s_flash_total = metrics['s_flash_total']
        total_flash_cap = ns_flash_total + s_flash_total

        ns_ram_share_used = (ns_ram_used / total_ram_used * 100) if total_ram_used else 0
        s_ram_share_used = (s_ram_used / total_ram_used * 100) if total_ram_used else 0
        ns_flash_share_used = (ns_flash_used / total_flash_used * 100) if total_flash_used else 0
        s_flash_share_used = (s_flash_used / total_flash_used * 100) if total_flash_used else 0

        ns_ram_share_cap = (ns_ram_total / total_ram_cap * 100) if total_ram_cap else 0
        s_ram_share_cap = (s_ram_total / total_ram_cap * 100) if total_ram_cap else 0
        ns_flash_share_cap = (ns_flash_total / total_flash_cap * 100) if total_flash_cap else 0
        s_flash_share_cap = (s_flash_total / total_flash_cap * 100) if total_flash_cap else 0

        report += "### Used footprint share\n\n"
        report += "| Resource | NS used | Secure used | Total used | NS share | Secure share |\n"
        report += "|---|---:|---:|---:|---:|---:|\n"
        report += f"| RAM | {ns_ram_used:,} | {s_ram_used:,} | {total_ram_used:,} | {ns_ram_share_used:.1f}% | {s_ram_share_used:.1f}% |\n"
        report += f"| Flash | {ns_flash_used:,} | {s_flash_used:,} | {total_flash_used:,} | {ns_flash_share_used:.1f}% | {s_flash_share_used:.1f}% |\n\n"

        report += "### Capacity split\n\n"
        report += "| Resource | NS capacity | Secure capacity | Total capacity | NS share | Secure share |\n"
        report += "|---|---:|---:|---:|---:|---:|\n"
        report += f"| RAM | {ns_ram_total:,} | {s_ram_total:,} | {total_ram_cap:,} | {ns_ram_share_cap:.1f}% | {s_ram_share_cap:.1f}% |\n"
        report += f"| Flash | {ns_flash_total:,} | {s_flash_total:,} | {total_flash_cap:,} | {ns_flash_share_cap:.1f}% | {s_flash_share_cap:.1f}% |\n\n"
    else:
        report += "- Not enough metrics to compute NS/Secure share.\n\n"

    # ELF extraction section
    elf = analyze_elf_sections()
    report += "## Memory Footprint Analysis (ELF Extracted)\n\n"
    if elf:
        sections = elf.get("sections", {})
        symbols = elf.get("top_symbols", [])

        text_size = sections.get("text", 0)
        rodata_size = sections.get("rodata", 0)
        data_size = sections.get("datas", 0) or sections.get("data", 0)
        bss_size = sections.get("bss", 0)

        report += "### ELF Sections\n\n"
        report += f"- .text: {text_size:,} bytes ({text_size / 1024:.1f} KB)\n"
        report += f"- .rodata: {rodata_size:,} bytes ({rodata_size / 1024:.1f} KB)\n"
        report += f"- .data: {data_size:,} bytes ({data_size / 1024:.1f} KB)\n"
        report += f"- .bss: {bss_size:,} bytes ({bss_size / 1024:.1f} KB)\n"
        report += f"- Flash subtotal (.text + .rodata): {text_size + rodata_size:,} bytes ({(text_size + rodata_size) / 1024:.1f} KB)\n"
        report += f"- RAM subtotal (.data + .bss): {data_size + bss_size:,} bytes ({(data_size + bss_size) / 1024:.1f} KB)\n\n"

        report += "### Largest Symbols (Top 20)\n\n"
        report += "| # | Symbol | Size (bytes) | Size (KB) |\n"
        report += "|---|---|---:|---:|\n"
        for idx, (name, size) in enumerate(symbols, 1):
            clean_name = name.replace("|", "\\|")
            if len(clean_name) > 80:
                clean_name = clean_name[:77] + "..."
            report += f"| {idx} | {clean_name} | {size:,} | {size / 1024:.1f} |\n"
        report += "\n"
    else:
        report += "- ELF extraction unavailable (missing build/zephyr/zephyr.elf or toolchain binaries).\n\n"
    
    return report

def main():
    port = None
    
    if len(sys.argv) > 1:
        port = sys.argv[1]
    else:
        port = find_device_port()
        if not port:
            print("Error: Could not find device port")
            print("Usage: python3 get_device_benchmark.py [/dev/ttyXXX]")
            sys.exit(1)
    
    print(f"Using port: {port}\n")
    
    metrics = run_benchmark_on_device(port)
    
    if metrics:
        report = format_report(metrics)
        print(report)
        
        # Save report as markdown
        report_file = Path("build") / "DEVICE_BENCHMARK_RESULTS.md"
        report_file.parent.mkdir(exist_ok=True)
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\n{'='*80}")
        print(f"Report saved to: {report_file}")
        print(f"{'='*80}")
    else:
        print("Failed to collect metrics")
        sys.exit(1)

if __name__ == "__main__":
    main()
