#!/usr/bin/env python3
"""
On-Demand Dynamic Challenge File Generator — Italian Telegraph Intercept (AdwaCTF).
HARDENED: 200+ noise packets, flag split across 3 encrypted IMTP sessions,
XOR(key=ADWA) + base64 encoding, cipher key discoverable in routine traffic.

Environment variables:
  - FLAG       : participant-specific flag
  - USER_ID    : participant / team identifier
  - OUTPUT_DIR : target directory (default: 'output' or '/output')
  - OUTPUT_FILENAME : pcap filename (default: intercept.pcap)
"""

import os
import sys
import base64
import struct
import secrets
import random
from pathlib import Path

# ─── flag helpers ─────────────────────────────────────────────────────────────

def get_flag() -> str:
    flag = os.environ.get("FLAG", "").strip()
    if flag:
        return flag
    for c in ["flag.txt", "/app/flag.txt", "../flag.txt"]:
        if os.path.isfile(c):
            try:
                val = open(c, encoding="utf-8").read().strip()
                if val:
                    return val
            except OSError:
                pass
    return "AdwaCTF{73l36r4ph_w1r35_t4pp3d_47_54ur14}"

# ─── XOR cipher ───────────────────────────────────────────────────────────────

XOR_KEY = b"ADWA"

def xor_cipher(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))

def encode_fragment(text: str) -> str:
    """XOR-encrypt then base64-encode a flag fragment."""
    return base64.b64encode(xor_cipher(text.encode())).decode()

# ─── PCAP packet builder ───────────────────────────────────────────────────────

def eth_ip_tcp(src_ip: str, dst_ip: str,
               sport: int, dport: int,
               seq: int, ack: int,
               flags: int, payload: bytes) -> bytes:
    dst_mac = b"\x00\x1a\x2b\x3c\x4d\x5e"
    src_mac = b"\x52\x54\x00\x12\x34\x56"
    eth_hdr = dst_mac + src_mac + struct.pack(">H", 0x0800)

    ip_len = 20 + 20 + len(payload)
    src_b = bytes(map(int, src_ip.split(".")))
    dst_b = bytes(map(int, dst_ip.split(".")))
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
                         0x45, 0, ip_len, 0x1896, 0x4000, 64, 6, 0, src_b, dst_b)

    tcp_hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 8192, 0, 0)
    return eth_hdr + ip_hdr + tcp_hdr + payload


def build_pcap(flag: str, user_id: str) -> bytes:
    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Base timestamp — night before Adwa, 29 Feb 1896
    T0 = 825652800

    packets: list[bytes] = []
    rng = random.Random(42)   # deterministic so the pcap is reproducible per flag

    def pkt(t_off: float, src: str, dst: str,
            sport: int, dport: int,
            seq: int, ack: int, flags: int, data: bytes):
        raw = eth_ip_tcp(src, dst, sport, dport, seq, ack, flags, data)
        n = len(raw)
        hdr = struct.pack("<IIII", int(T0 + t_off), 0, n, n)
        packets.append(hdr + raw)

    # ── helpers for compact call sites ────────────────────────────────────────
    HQ    = "192.168.18.10"   # Baratieri Forward HQ
    SAU   = "192.168.18.96"   # Sauria Telegraph Relay
    MAS   = "192.168.18.4"    # Massawa Coastal HQ
    ASM   = "192.168.18.1"    # Asmara Command Post
    ALB   = "192.168.18.20"   # Albertone column radio node
    DAB   = "192.168.18.21"   # Dabormida column radio node
    ELL   = "192.168.18.22"   # Ellena column radio node

    PSH_ACK = 0x18

    # ── PHASE 0: initial handshakes / noise  (t = 0 .. 15) ───────────────────
    pkt(0.1,  HQ,  SAU, 1896, 5000, 100,  0,    0x02, b"")           # SYN
    pkt(0.2,  SAU, HQ,  5000, 1896, 500,  101,  0x12, b"")           # SYN-ACK
    pkt(0.3,  HQ,  SAU, 1896, 5000, 101,  501,  0x10, b"")           # ACK

    pkt(1.0,  HQ,  SAU, 1896, 5000, 101, 501,  PSH_ACK,
        b"IMTP/1.0 STATUS_REQUEST SAURIA_HQ UNIT=BARATIERI_FWD\n")
    pkt(1.3,  SAU, HQ,  5000, 1896, 501, 155,  PSH_ACK,
        b"IMTP/1.0 STATUS_OK HOST=SAURIA_RELAY COLUMNS=4_ACTIVE LINE_CLEAR\n")

    pkt(2.0,  ASM, MAS, 2200, 80,   10,  0,    PSH_ACK,
        b"GET /status HTTP/1.1\r\nHost: massawa.mil.it\r\n\r\n")
    pkt(2.3,  MAS, ASM, 80,   2200, 1,   100,  PSH_ACK,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    pkt(3.0,  HQ,  MAS, 1896, 1896, 200, 0,    PSH_ACK,
        b"IMTP/1.0 DISPATCH_FROM_BARATIERI: ALL COLUMNS ADVANCE AT 03:00 YEKATIT 29.\n")
    pkt(3.4,  MAS, HQ,  1896, 1896, 300, 290,  PSH_ACK,
        b"IMTP/1.0 DISPATCH_ACK: MASSAWA CONFIRMS.\n")

    # Albertone brigade status
    pkt(4.0,  ALB, SAU, 3001, 1896, 50,  0,    PSH_ACK,
        b"IMTP/1.0 STATUS UNIT=ALBERTONE_BRIGADE POS=KIDANE_MEHRET TROOPS=4100\n")
    pkt(4.1,  SAU, ALB, 1896, 3001, 90,  120,  PSH_ACK,
        b"IMTP/1.0 STATUS_ACK UNIT=ALBERTONE_BRIGADE\n")

    # Dabormida brigade status
    pkt(5.0,  DAB, SAU, 3002, 1896, 70,  0,    PSH_ACK,
        b"IMTP/1.0 STATUS UNIT=DABORMIDA_BRIGADE POS=MARIAM_SHAVITU TROOPS=3800\n")
    pkt(5.1,  SAU, DAB, 1896, 3002, 80,  140,  PSH_ACK,
        b"IMTP/1.0 STATUS_ACK UNIT=DABORMIDA_BRIGADE\n")

    # Ellena reserve brigade status
    pkt(6.0,  ELL, SAU, 3003, 1896, 60,  0,    PSH_ACK,
        b"IMTP/1.0 STATUS UNIT=ELLENA_RESERVE POS=REBBI_ARIENNI TROOPS=4200\n")
    pkt(6.1,  SAU, ELL, 1896, 3003, 85,  130,  PSH_ACK,
        b"IMTP/1.0 STATUS_ACK UNIT=ELLENA_RESERVE\n")

    # HTTP noise between ASM-MAS
    for i in range(10):
        pkt(7.0 + i*0.4, ASM, MAS, 2300+i, 80, 10+i*5, 0, PSH_ACK,
            f"GET /telemetry/{i} HTTP/1.1\r\nHost: massawa.mil.it\r\n\r\n".encode())
        pkt(7.2 + i*0.4, MAS, ASM, 80, 2300+i, 1+i*3, 50+i*5, PSH_ACK,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    # ── KEY DISCLOSURE: cipher key buried in routine traffic ──────────────────
    # Discoverable at t≈11 — a system broadcast about key rotation
    pkt(11.0, ASM, SAU, 4000, 1896, 400, 0, PSH_ACK,
        b"IMTP/1.0 SYSTEM_KEY_ROTATION UNIT=CIPHER_BUREAU KEY_ID=ADWA EPOCH=18960229\n")
    pkt(11.2, SAU, ASM, 1896, 4000, 420, 490, PSH_ACK,
        b"IMTP/1.0 SYSTEM_ACK KEY_ROTATION_CONFIRMED\n")

    # ── Noise burst 1 (t = 12 .. 29) ─────────────────────────────────────────
    smtp_lines = [
        b"220 massawa.mil.it ESMTP\r\n",
        b"EHLO asmara.mil.it\r\n",
        b"250-massawa.mil.it\r\n",
        b"MAIL FROM:<martini@coloniale.it>\r\n",
        b"250 OK\r\n",
        b"RCPT TO:<baratieri@fwd.mil.it>\r\n",
        b"250 OK\r\n",
        b"DATA\r\n",
        b"354 Start input\r\n",
        b"Subject: Reinforcements delayed - Ancona supply ship grounded.\r\n.\r\n",
        b"250 OK\r\n",
        b"QUIT\r\n",
        b"221 Bye\r\n",
    ]
    for i, line in enumerate(smtp_lines):
        src, dst, sp, dp = (ASM, MAS, 2500, 25) if i % 2 == 0 else (MAS, ASM, 25, 2500)
        pkt(12.0 + i*0.5, src, dst, sp, dp, 1000+i, 1+i, PSH_ACK, line)

    for i in range(20):
        pkt(19.0 + i*0.4, ALB, HQ, 4100+i, 1896, 500+i*3, 0, PSH_ACK,
            f"IMTP/1.0 PING SEQ={i} UNIT=ALBERTONE\n".encode())
        pkt(19.2 + i*0.4, HQ, ALB, 1896, 4100+i, 1+i, 503+i*3, PSH_ACK,
            f"IMTP/1.0 PONG SEQ={i}\n".encode())

    # Decoy — looks like ENCRYPTED_TELEGRAM but with garbled format (wrong field)
    pkt(28.0, MAS, SAU, 1896, 5001, 300, 0, PSH_ACK,
        b"IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=DECOY_A PAYLOAD=INVALIDBASE64!!!\n")
    pkt(28.5, SAU, MAS, 5001, 1896, 400, 350, PSH_ACK,
        b"IMTP/1.0 NAK WIRE_ID=DECOY_A REASON=DECODE_FAIL\n")

    # ── ENCRYPTED FRAGMENT 1 (t = 30) ─────────────────────────────────────────
    # Flag split into 3 equal-ish parts
    third = len(flag) // 3
    part1 = flag[:third]
    part2 = flag[third:2*third]
    part3 = flag[2*third:]

    wire_base = f"{secrets.randbelow(9000)+1000}"

    frag1 = (
        f"CONFIDENTIAL TELEGRAPH DISPATCH:\n"
        f"FROM: COMMISSARIO CIVILE FERDINANDO MARTINI\n"
        f"TO: GENERALE ORESTE BARATIERI\n"
        f"OPERATIVE_ID: {user_id}\n"
        f"FRAGMENT: 1/3\n"
        f"BODY: {part1}\n"
    )
    wire1 = f"IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=WIRE_{wire_base}_A DATA={encode_fragment(frag1)}\n".encode()

    pkt(30.0, HQ,  SAU, 1896, 5000, 2000, 2500, PSH_ACK, wire1)
    pkt(30.3, SAU, HQ,  5000, 1896, 2500, 2000+len(wire1), PSH_ACK,
        f"IMTP/1.0 ACK WIRE_ID=WIRE_{wire_base}_A STATUS=RECEIVED\n".encode())

    # ── Noise burst 2 (t = 31 .. 49) ──────────────────────────────────────────
    for i in range(25):
        pkt(31.0 + i*0.5, DAB, SAU, 5000+i, 1896, 700+i*4, 0, PSH_ACK,
            f"IMTP/1.0 POSITION_REPORT UNIT=DABORMIDA LON=38.{i:02d} LAT=14.{i:02d}\n".encode())
        pkt(31.2 + i*0.5, SAU, DAB, 1896, 5000+i, 1+i, 704+i*4, PSH_ACK,
            b"IMTP/1.0 POSITION_ACK\n")

    # Second decoy — correct format but wrong DATA (scrambled base64, can't decode)
    pkt(42.0, ALB, HQ, 1896, 5000, 3000, 0, PSH_ACK,
        b"IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=DECOY_B DATA=aGVsbG8gd29ybGQ=\n")
    pkt(42.3, HQ, ALB, 5000, 1896, 400, 3050, PSH_ACK,
        b"IMTP/1.0 NAK WIRE_ID=DECOY_B REASON=AUTH_FAIL\n")

    pkt(44.0, MAS, ASM, 2600, 80, 1500, 0, PSH_ACK,
        b"POST /report HTTP/1.1\r\nHost: asmara.mil.it\r\nContent-Length: 20\r\n\r\n{\"status\":\"nominal\"}")
    pkt(44.4, ASM, MAS, 80, 2600, 1, 1540, PSH_ACK,
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nCreated")

    # ── ENCRYPTED FRAGMENT 2 (t = 50) ─────────────────────────────────────────
    frag2 = (
        f"CONFIDENTIAL TELEGRAPH DISPATCH:\n"
        f"FROM: COMMISSARIO CIVILE FERDINANDO MARTINI\n"
        f"TO: GENERALE ORESTE BARATIERI\n"
        f"FRAGMENT: 2/3\n"
        f"BODY: {part2}\n"
    )
    wire2 = f"IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=WIRE_{wire_base}_B DATA={encode_fragment(frag2)}\n".encode()

    pkt(50.0, MAS, SAU, 1896, 5000, 4000, 4500, PSH_ACK, wire2)
    pkt(50.3, SAU, MAS, 5000, 1896, 4500, 4000+len(wire2), PSH_ACK,
        f"IMTP/1.0 ACK WIRE_ID=WIRE_{wire_base}_B STATUS=RECEIVED\n".encode())

    # ── Noise burst 3 (t = 51 .. 69) ──────────────────────────────────────────
    for i in range(20):
        pkt(51.0 + i*0.6, ELL, MAS, 6000+i, 1896, 900+i*3, 0, PSH_ACK,
            f"IMTP/1.0 LOGISTICS_REPORT UNIT=ELLENA AMMO={rng.randint(1000,9999)} RATIONS={rng.randint(500,2000)}\n".encode())
        pkt(51.3 + i*0.6, MAS, ELL, 1896, 6000+i, 1+i, 903+i*3, PSH_ACK,
            b"IMTP/1.0 LOGISTICS_ACK\n")

    # ARP-like traffic (broadcast style)
    for i in range(15):
        pkt(60.0 + i*0.3, f"192.168.18.{10+i}", "192.168.18.255",
            rng.randint(1024,65000), 1896, rng.randint(100,999), 0, PSH_ACK,
            f"IMTP/1.0 BROADCAST UNIT=UNKNOWN_{i} STATUS=ALIVE\n".encode())

    # Third decoy — correct wrapper but DATA decodes to something that is not a flag
    pkt(67.0, ASM, HQ, 1896, 5000, 5000, 0, PSH_ACK,
        ("IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=DECOY_C DATA=" +
         base64.b64encode(b"THIS_IS_NOT_THE_FLAG_YOU_ARE_LOOKING_FOR").decode() +
         "\n").encode())
    pkt(67.5, HQ, ASM, 5000, 1896, 500, 5050, PSH_ACK,
        b"IMTP/1.0 ACK WIRE_ID=DECOY_C STATUS=RECEIVED\n")

    # ── ENCRYPTED FRAGMENT 3 (t = 70) ─────────────────────────────────────────
    frag3 = (
        f"CONFIDENTIAL TELEGRAPH DISPATCH:\n"
        f"FROM: COMMISSARIO CIVILE FERDINANDO MARTINI\n"
        f"TO: GENERALE ORESTE BARATIERI\n"
        f"FRAGMENT: 3/3\n"
        f"BODY: {part3}\n"
        f"AUTH: DO_NOT_ENGAGE_WITHOUT_CONSOLIDATION\n"
    )
    wire3 = f"IMTP/1.0 ENCRYPTED_TELEGRAM WIRE_ID=WIRE_{wire_base}_C DATA={encode_fragment(frag3)}\n".encode()

    pkt(70.0, ASM, SAU, 1896, 5000, 6000, 6500, PSH_ACK, wire3)
    pkt(70.3, SAU, ASM, 5000, 1896, 6500, 6000+len(wire3), PSH_ACK,
        f"IMTP/1.0 ACK WIRE_ID=WIRE_{wire_base}_C STATUS=RECEIVED\n".encode())

    # ── Noise burst 4 — final wind-down (t = 71 .. 90) ────────────────────────
    for i in range(30):
        pkt(71.0 + i*0.5, SAU, HQ, 5100+i, 1896, 1000+i*5, 0, PSH_ACK,
            f"IMTP/1.0 RELAY_HEARTBEAT SEQ={i} SAURIA_ACTIVE\n".encode())
        pkt(71.2 + i*0.5, HQ, SAU, 1896, 5100+i, 1+i, 1005+i*5, PSH_ACK,
            b"IMTP/1.0 HB_ACK\n")

    pkt(87.0, HQ, SAU, 1896, 5000, 9000, 9100, PSH_ACK,
        b"IMTP/1.0 SESSION_CLOSE SAURIA_HQ REASON=DAWN_ADVANCE\n")
    pkt(87.3, SAU, HQ, 5000, 1896, 9100, 9050, PSH_ACK,
        b"IMTP/1.0 SESSION_CLOSE_ACK\n")
    pkt(87.5, HQ, SAU, 1896, 5000, 9050, 9150, 0x11, b"")   # FIN-ACK

    return global_hdr + b"".join(packets)


def main():
    flag    = get_flag()
    user_id = os.environ.get("USER_ID", "tigray_wiretap_scout").strip()
    here    = Path(__file__).resolve().parent.parent

    output_path = os.environ.get("OUTPUT_PATH", "").strip()
    if output_path:
        target_file  = Path(output_path).resolve()
        target_dir   = target_file.parent
        target_name  = target_file.name
    elif len(sys.argv) > 1 and sys.argv[1].strip():
        arg_path = Path(sys.argv[1].strip()).resolve()
        if arg_path.is_dir() or sys.argv[1].endswith("/"):
            target_dir  = arg_path
            target_name = "intercept.pcap"
        else:
            target_dir  = arg_path.parent
            target_name = arg_path.name
    else:
        env_dir = os.environ.get("OUTPUT_DIR", "").strip()
        if env_dir:
            target_dir = Path(env_dir).resolve()
        elif Path("/output").is_dir():
            target_dir = Path("/output")
        else:
            target_dir = here / "output"
        target_name = os.environ.get("OUTPUT_FILENAME", "intercept.pcap").strip()

    target_dir.mkdir(parents=True, exist_ok=True)

    pcap_data = build_pcap(flag, user_id)

    log_content = (
        "===============================================================================\n"
        "IMPERIAL TELEGRAPH WIRETAP LOG - SAURIA RELAY\n"
        "TIGRAYAN RECONNAISSANCE DETACHMENT\n"
        "COORDINATED WITH RAS ALULA ENGIDA\n"
        "NIGHT OF 29 YEKATIT 1888 (29 FEBRUARY 1896)\n"
        f"SESSION IDENTIFIER: {user_id}\n"
        "===============================================================================\n\n"
        "WIRETAP OVERVIEW:\n"
        "Scout wiremen tapped the Italian military telegraph copper wire between\n"
        "Sauria forward headquarters and the coastal garrison at Massawa.\n\n"
        "TECHNICAL CAPTURE:\n"
        f"- Target File   : {target_name}\n"
        "- Protocol      : IMTP/1.0 on TCP port 1896\n"
        "- Source IPs    : Multiple Italian military nodes\n"
        "- Key IPs       :\n"
        "    192.168.18.10  Baratieri Forward HQ\n"
        "    192.168.18.96  Sauria Telegraph Relay\n"
        "    192.168.18.4   Massawa Coastal HQ\n"
        "    192.168.18.1   Asmara Command Post\n\n"
        "MISSION INSTRUCTIONS:\n"
        "Multiple IMTP sessions were recorded over the wire. Among the routine\n"
        "brigade dispatches, heartbeats, and logistics reports, three encrypted\n"
        "telegrams were intercepted from the Italian Cipher Bureau.\n\n"
        "Find all IMTP/1.0 ENCRYPTED_TELEGRAM packets.\n"
        "Sort by WIRE_ID suffix (A, B, C).\n"
        "Decode each DATA field and XOR-decrypt using the key broadcast by the Cipher Bureau.\n"
        "Reassemble the three BODY fragments in order to recover the flag.\n"
        "===============================================================================\n"
    )

    env_dir = os.environ.get("OUTPUT_DIR", "").strip()

    dirs_to_write = {target_dir}
    if Path("/output").is_dir():
        dirs_to_write.add(Path("/output"))
    if (here / "output").is_dir() and not env_dir and not output_path and len(sys.argv) <= 1:
        dirs_to_write.add(here / "output")

    for d in dirs_to_write:
        try:
            d.mkdir(parents=True, exist_ok=True)
            with open(d / target_name, "wb") as f:
                f.write(pcap_data)
            os.chmod(d / target_name, 0o666)
            with open(d / "wiretap_log.txt", "w", encoding="utf-8") as f:
                f.write(log_content)
            os.chmod(d / "wiretap_log.txt", 0o666)
        except OSError:
            pass

    if (here / "dist").is_dir() and not env_dir and not output_path and len(sys.argv) <= 1:
        try:
            with open(here / "dist" / "intercept.pcap", "wb") as f:
                f.write(pcap_data)
            with open(here / "dist" / "wiretap_log.txt", "w", encoding="utf-8") as f:
                f.write(log_content)
        except OSError:
            pass

    total_pkts = pcap_data.count(b"IMTP/1.0")
    print(f"[generator] user_id={user_id}")
    print(f"[generator] target_dir={target_dir}")
    print(f"[generator] pcap_size={len(pcap_data)} bytes  flag_fragments=3  xor_key=ADWA")
    print(f"[generator] generated: {target_name}, wiretap_log.txt")


if __name__ == "__main__":
    main()
