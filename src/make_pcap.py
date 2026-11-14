#!/usr/bin/env python3
import base64
import struct
import time
from pathlib import Path

def build_pcap():
    base_dir = Path(__file__).resolve().parent.parent
    dist_dir = base_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    flag = "AdwaCTF{73l36r4ph_w1r35_t4pp3d_47_54ur14}"
    (base_dir / "flag.txt").write_text(flag + "\n", encoding="utf-8")

    # Global PCAP Header (24 bytes)
    # magic=0xa1b2c3d4, v_maj=2, v_min=4, tz=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets = []

    def make_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        # Ethernet Header: 14 bytes (dst_mac 6B, src_mac 6B, ethertype 0x0800 2B)
        dst_mac = b"\x00\x1a\x2b\x3c\x4d\x5e"
        src_mac = b"\x52\x54\x00\x12\x34\x56"
        eth_hdr = dst_mac + src_mac + struct.pack(">H", 0x0800)

        # IPv4 Header: 20 bytes
        # Version 4, IHL 5 (0x45), DSCP/ECN 0, total_len, id 0x1234, flags/offset 0x4000, ttl 64, proto 6 (TCP), cksum 0
        ip_total_len = 20 + 20 + len(payload)
        src_ip_bytes = bytes(map(int, src_ip.split('.')))
        dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
        ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x1896, 0x4000, 64, 6, 0, src_ip_bytes, dst_ip_bytes)

        # TCP Header: 20 bytes (offset=5 -> 0x50)
        tcp_hdr = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 8192, 0, 0)

        return eth_hdr + ip_hdr + tcp_hdr + payload

    # Conversations
    # Base timestamp: 1896-03-01 04:00:00 UTC -> 1709265600 (or epoch simulation)
    t0 = 825652800  # 1896 timestamp representation in epoch or unix
    seq_a = 1000
    seq_b = 5000

    def add_packet(t_offset, src, dst, sport, dport, seq, ack, flags, data):
        raw = make_eth_ip_tcp(src, dst, sport, dport, seq, ack, flags, data)
        p_len = len(raw)
        hdr = struct.pack("<IIII", int(t0 + t_offset), 0, p_len, p_len)
        packets.append(hdr + raw)

    # 1. Routine status traffic
    add_packet(0, "192.168.18.10", "192.168.18.96", 1896, 5000, 100, 1, 0x18, b"IMTP/1.0 STATUS_REQUEST SAURIA_HQ\n")
    add_packet(1, "192.168.18.96", "192.168.18.10", 5000, 1896, 1, 135, 0x18, b"IMTP/1.0 STATUS_OK HOST=SAURIA_RELAY COLUMNS=4_ACTIVE\n")

    # 2. General Albertone dispatch
    add_packet(5, "192.168.18.10", "192.168.18.96", 1896, 5000, 135, 55, 0x18, b"DISPATCH_FROM_BARATIERI: ALBERTONE ADVANCE LEFT FLANK TO KIDANE MEHRET PASS.\n")
    add_packet(7, "192.168.18.96", "192.168.18.10", 5000, 1896, 55, 211, 0x18, b"DISPATCH_ACK ALBERTONE: MARCHING THROUGH REBBI ARIENNI GORGE.\n")

    # 3. Confidential Italian Ministry Telegram with Flag
    secret_payload = (
        f"CONFIDENTIAL TELEGRAPH DISPATCH:\n"
        f"FROM: COMMISSARIO CIVILE FERDINANDO MARTINI\n"
        f"TO: GENERALE ORESTE BARATIERI\n"
        f"SUBJECT: IMPERIAL ETHIOPIAN ARMY NUMERICAL SUPERIORITY\n\n"
        f"Reports from scouts indicate Emperor Menelik has mobilized over 100,000 men.\n"
        f"Do not engage in open defiles without artillery consolidation.\n"
        f"AUTHENTICATION_FLAG: {flag}\n"
    )
    b64_msg = base64.b64encode(secret_payload.encode()).decode()
    encoded_wire = f"IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=18960301 DATA={b64_msg}\n".encode()

    add_packet(12, "192.168.18.10", "192.168.18.96", 1896, 5000, 211, 115, 0x18, encoded_wire)
    add_packet(14, "192.168.18.96", "192.168.18.10", 5000, 1896, 115, 211 + len(encoded_wire), 0x18, b"IMTP/1.0 ACK WIRE_ID=18960301 STATUS=RECEIVED\n")

    pcap_data = global_hdr + b"".join(packets)
    out_file = dist_dir / "intercept.pcap"
    out_file.write_bytes(pcap_data)
    print(f"[+] Written {out_file} ({len(pcap_data)} bytes, {len(packets)} packets)")

if __name__ == "__main__":
    build_pcap()
