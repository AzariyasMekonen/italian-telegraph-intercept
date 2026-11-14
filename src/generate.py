#!/usr/bin/env python3
"""
On-Demand Dynamic Challenge File Generator for Italian Telegraph Intercept (AdwaCTF).

Environment variables:
  - FLAG: Dynamic participant-specific flag (e.g. 'AdwaCTF{...}')
  - USER_ID: Optional participant or team identifier
  - OUTPUT_FILENAME: Output file name (default: 'intercept.pcap')
  - OUTPUT_DIR: Target directory to write to (default: 'output' or '/output')
"""

import os
import sys
import base64
import struct
import secrets
from pathlib import Path

def get_flag():
    flag = os.environ.get("FLAG", "").strip()
    if flag:
        return flag

    candidates = ["flag.txt", "/app/flag.txt", "../flag.txt"]
    for c in candidates:
        if os.path.isfile(c):
            try:
                with open(c, "r", encoding="utf-8") as f:
                    val = f.read().strip()
                    if val:
                        return val
            except OSError:
                pass

    return "AdwaCTF{73l36r4ph_w1r35_t4pp3d_47_54ur14}"

def build_pcap_bytes(flag: str, user_id: str) -> bytes:
    # Global PCAP Header (24 bytes)
    # magic=0xa1b2c3d4, v_maj=2, v_min=4, tz=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets = []

    def make_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        dst_mac = b"\x00\x1a\x2b\x3c\x4d\x5e"
        src_mac = b"\x52\x54\x00\x12\x34\x56"
        eth_hdr = dst_mac + src_mac + struct.pack(">H", 0x0800)

        ip_total_len = 20 + 20 + len(payload)
        src_ip_bytes = bytes(map(int, src_ip.split('.')))
        dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
        ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x1896, 0x4000, 64, 6, 0, src_ip_bytes, dst_ip_bytes)

        tcp_hdr = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 8192, 0, 0)
        return eth_hdr + ip_hdr + tcp_hdr + payload

    t0 = 825652800  # Historic timestamp base: night before Adwa battle (Feb 29, 1896)

    def add_packet(t_offset, src, dst, sport, dport, seq, ack, flags, data):
        raw = make_eth_ip_tcp(src, dst, sport, dport, seq, ack, flags, data)
        p_len = len(raw)
        hdr = struct.pack("<IIII", int(t0 + t_offset), 0, p_len, p_len)
        packets.append(hdr + raw)

    wire_id = f"1896{secrets.randbelow(9000) + 1000}"

    # 1. Routine status traffic
    add_packet(0, "192.168.18.10", "192.168.18.96", 1896, 5000, 100, 1, 0x18, b"IMTP/1.0 STATUS_REQUEST SAURIA_HQ\n")
    add_packet(1, "192.168.18.96", "192.168.18.10", 5000, 1896, 1, 135, 0x18, b"IMTP/1.0 STATUS_OK HOST=SAURIA_RELAY COLUMNS=4_ACTIVE\n")

    # 2. General Albertone dispatch
    add_packet(5, "192.168.18.10", "192.168.18.96", 1896, 5000, 135, 55, 0x18, b"DISPATCH_FROM_BARATIERI: ALBERTONE ADVANCE LEFT FLANK TO KIDANE MEHRET PASS.\n")
    add_packet(7, "192.168.18.96", "192.168.18.10", 5000, 1896, 55, 211, 0x18, b"DISPATCH_ACK ALBERTONE: MARCHING THROUGH REBBI ARIENNI GORGE.\n")

    # 3. Confidential Italian Ministry Telegram with dynamic flag
    secret_payload = (
        f"CONFIDENTIAL TELEGRAPH DISPATCH:\n"
        f"FROM: COMMISSARIO CIVILE FERDINANDO MARTINI\n"
        f"TO: GENERALE ORESTE BARATIERI\n"
        f"OPERATIVE IDENTIFIER: {user_id}\n"
        f"SUBJECT: IMPERIAL ETHIOPIAN ARMY NUMERICAL SUPERIORITY\n\n"
        f"Reports from scouts indicate Emperor Menelik has mobilized over 100,000 men.\n"
        f"Do not engage in open defiles without artillery consolidation.\n"
        f"AUTHENTICATION_FLAG: {flag}\n"
    )
    b64_msg = base64.b64encode(secret_payload.encode()).decode()
    encoded_wire = f"IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID={wire_id} DATA={b64_msg}\n".encode()

    add_packet(12, "192.168.18.10", "192.168.18.96", 1896, 5000, 211, 115, 0x18, encoded_wire)
    add_packet(14, "192.168.18.96", "192.168.18.10", 5000, 1896, 115, 211 + len(encoded_wire), 0x18, f"IMTP/1.0 ACK WIRE_ID={wire_id} STATUS=RECEIVED\n".encode())

    return global_hdr + b"".join(packets)

def main():
    flag = get_flag()
    user_id = os.environ.get("USER_ID", "tigray_wiretap_scout").strip()
    here = Path(__file__).resolve().parent.parent

    # Determine primary output target directory
    output_path = os.environ.get("OUTPUT_PATH", "").strip()
    if output_path:
        target_file = Path(output_path).resolve()
        target_dir = target_file.parent
        target_pcap_name = target_file.name
    elif len(sys.argv) > 1 and sys.argv[1].strip():
        arg_path = Path(sys.argv[1].strip()).resolve()
        if arg_path.is_dir() or sys.argv[1].endswith("/"):
            target_dir = arg_path
            target_pcap_name = "intercept.pcap"
        else:
            target_dir = arg_path.parent
            target_pcap_name = arg_path.name
    else:
        env_dir = os.environ.get("OUTPUT_DIR", "").strip()
        if env_dir:
            target_dir = Path(env_dir).resolve()
        elif Path("/output").is_dir():
            target_dir = Path("/output")
        else:
            target_dir = here / "output"
        target_pcap_name = os.environ.get("OUTPUT_FILENAME", "intercept.pcap").strip()

    target_dir.mkdir(parents=True, exist_ok=True)

    # Generate PCAP bytes
    pcap_data = build_pcap_bytes(flag, user_id)

    # Companion wiretap briefing log
    log_content = (
        "===============================================================================\n"
        "IMPERIAL TELEGRAPH WIRETAP LOG - SAURIA RELAY\n"
        "TIGRAYAN RECONNAISSANCE DETACHMENT\n"
        "COORDINATED WITH RAS ALULA ENGIDA\n"
        "NIGHT OF 29 YEKATIT 1888 (29 FEBRUARY 1896)\n"
        f"SESSION IDENTIFIER: {user_id}\n"
        "===============================================================================\n\n"
        "WIRETAP OVERVIEW:\n"
        "Our scout wiremen tapped into the Italian military telegraph copper wire strung\n"
        "between Sauria forward headquarters and the coastal garrison at Massawa.\n\n"
        "TECHNICAL CAPTURE SPECIFICATIONS:\n"
        f"- Target File: {target_pcap_name}\n"
        "- Target Relay Port: TCP 1896 (Italian Military Telegraph Protocol / IMTP/1.0)\n"
        "- Source IP: 192.168.18.10 (Baratieri Forward HQ)\n"
        "- Destination IP: 192.168.18.96 (Sauria Telegraph Station)\n\n"
        "MISSION INSTRUCTIONS:\n"
        "Inspect the captured pcap traffic, reassemble the TCP streams on port 1896,\n"
        "decode the encrypted telegram payload, and extract the Italian military clearance flag!\n"
        "===============================================================================\n"
    )

    env_dir = os.environ.get("OUTPUT_DIR", "").strip()

    dirs_to_write = {target_dir}
    if Path("/output").is_dir():
        dirs_to_write.add(Path("/output"))

    # Only write to local output/ if no custom output directory was set via env or args
    if (here / "output").is_dir() and not env_dir and not output_path and len(sys.argv) <= 1:
        dirs_to_write.add(here / "output")

    for d in dirs_to_write:
        try:
            d.mkdir(parents=True, exist_ok=True)
            pcap_file = d / target_pcap_name
            with open(pcap_file, "wb") as f:
                f.write(pcap_data)
            try:
                os.chmod(pcap_file, 0o666)
            except OSError:
                pass

            wiretap_file = d / "wiretap_log.txt"
            with open(wiretap_file, "w", encoding="utf-8") as f:
                f.write(log_content)
            try:
                os.chmod(wiretap_file, 0o666)
            except OSError:
                pass
        except OSError:
            pass

    # Also keep dist/ updated if present and no custom target was forced
    if (here / "dist").is_dir() and not env_dir and not output_path and len(sys.argv) <= 1:
        try:
            with open(here / "dist" / "intercept.pcap", "wb") as f:
                f.write(pcap_data)
            with open(here / "dist" / "wiretap_log.txt", "w", encoding="utf-8") as f:
                f.write(log_content)
        except OSError:
            pass

    print(f"[generator] user_id={user_id}")
    print(f"[generator] target_dir={target_dir}")
    print(f"[generator] generated output files: {target_pcap_name}, wiretap_log.txt")
    print(f"[generator] total size={len(pcap_data)} bytes")

if __name__ == "__main__":
    main()
