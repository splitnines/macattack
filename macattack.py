#!/usr/bin/env python3
"""
macattack.py

Send UDP packets as raw Ethernet frames with a different source MAC per frame,
recycling the same mac list continuously.  It is intended to be used in a lab
setting to load test a layer 2 switch by poplulating the MAC address table.

Linux only (uses AF_PACKET raw sockets). Must be run as root (or CAP_NET_RAW).
 -- sudo setcap cap_net_raw+ep $(which python3)

Usage:
  sudo python3 macattack.py --iface eth0 --dst-mac aa:bb:cc:dd:ee:ff --count
  1000 --rate 100
"""

from __future__ import annotations

import argparse
import os
import random
import re
import socket
import struct
import sys
import time
from typing import Iterator, List


def mac_str_to_bytes(mac: str) -> bytes:
    s = re.sub(r"[^0-9A-Fa-f]", "", str(mac))
    if len(s) == 12:
        return bytes(int(s[i:i + 2], 16) for i in range(0, 12, 2))
    if len(s) == 6:
        return bytes(int(s[i:i + 2], 16) for i in range(0, 6, 2))
    raise ValueError(
        f"Error: mac must be 6 or 12 hex digits (received {mac!r})")


def bytes_to_mac_str(b: bytes) -> str:
    return ":".join(f"{i:02x}" for i in b)


def int_to_mac_bytes(n: int, base_oui: str = "02:00:00") -> bytes:
    base = mac_str_to_bytes(base_oui)
    if len(base) == 6:
        base = base[:3]
    if len(base) != 3:
        raise ValueError(
            "base_oui must decode to exactly 3 bytes (3-octet OUI)")
    if not (0 <= n < (1 << 24)):
        raise ValueError("n out of range for 3-octet suffix")
    suffix = bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    return base + suffix


def gen_macs_sequential(count: int,
                        start: int = 0,
                        base_oui: str = "02:00:00") -> Iterator[bytes]:
    for i in range(start, start + count):
        yield int_to_mac_bytes(i & 0xFFFFFF, base_oui)


def gen_macs_random(count: int, base_oui: str = "02:00:00") -> Iterator[bytes]:
    seen = set()
    while len(seen) < count:
        n = random.getrandbits(24)
        if n in seen:
            continue
        seen.add(n)
        yield int_to_mac_bytes(n, base_oui)


def checksum_ipv4(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) + header[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def udp_checksum(src_ip: bytes, dst_ip: bytes, udp_header: bytes,
                 payload: bytes) -> int:
    pseudo = (src_ip + dst_ip + struct.pack("!BBH", 0, socket.IPPROTO_UDP,
                                            len(udp_header) + len(payload)))
    sdata = pseudo + udp_header + payload
    if len(sdata) % 2:
        sdata += b"\x00"
    s = 0
    for i in range(0, len(sdata), 2):
        s += (sdata[i] << 8) + sdata[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ipv4_header(
    src_ip: str,
    dst_ip: str,
    payload_len: int,
    identification: int = 0,
    ttl: int = 64,
) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0
    proto = socket.IPPROTO_UDP
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header_wo_cksum = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        proto,
        checksum,
        src,
        dst,
    )
    ck = checksum_ipv4(header_wo_cksum)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        proto,
        ck,
        src,
        dst,
    )
    return header


def build_udp_header(src_port: int, dst_port: int, payload: bytes, src_ip: str,
                     dst_ip: str) -> bytes:
    length = 8 + len(payload)
    header_wo_cksum = struct.pack("!HHHH", src_port, dst_port, length, 0)
    src_ip_b = socket.inet_aton(src_ip)
    dst_ip_b = socket.inet_aton(dst_ip)
    chksum = udp_checksum(src_ip_b, dst_ip_b, header_wo_cksum, payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, chksum)
    return header


def build_eth_frame(dst_mac: bytes, src_mac: bytes, ethertype: int,
                    payload: bytes) -> bytes:
    eth_hdr = dst_mac + src_mac + struct.pack("!H", ethertype)
    return eth_hdr + payload


def qbf() -> str:
    return "The quick brown fox jumped over the lazy dog 0123456789"


def send_spoofed_udp(
    iface: str,
    dst_mac_str: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    count: int,
    rate: float,
    mode: str,
    base_oui: str,
):
    s = None
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    except PermissionError:
        print("ERROR: must be run as root.")
        sys.exit(1)

    try:
        s.bind((iface, 0))
        dst_mac = mac_str_to_bytes(dst_mac_str)

        if mode == "sequential":
            macs: List[bytes] = list(
                gen_macs_sequential(count, start=0, base_oui=base_oui))
        else:
            macs: List[bytes] = list(gen_macs_random(count, base_oui=base_oui))

        if not macs:
            print("Error: no macs generated.")
            return

        print(
            f"Generated {len(macs)} source MACs. First: "
            f"{bytes_to_mac_str(macs[0])} Last: {bytes_to_mac_str(macs[-1])}")

        ident = random.randrange(0, 0xFFFF)
        sent_total = 0
        interval = 1.0 / rate if rate > 0 else 0
        start_time = time.time()
        next_report = start_time + 1.0

        print(f"Starting continuous send on {iface}: dst_mac={dst_mac_str}, "
              f"src_ip={src_ip}, dst_ip={dst_ip}, rate={rate} pkt/s")

        try:
            cycle = 0
            while True:
                cycle += 1
                for idx, src_mac in enumerate(macs, start=1):
                    i = (cycle - 1) * len(macs) + idx
                    payload = f"{qbf()} - pkt {i}".encode("ascii")

                    ident = (ident + 1) & 0xFFFF

                    udp_hdr = build_udp_header(src_port, dst_port, payload,
                                               src_ip, dst_ip)
                    ip_hdr = build_ipv4_header(
                        src_ip,
                        dst_ip,
                        len(udp_hdr) + len(payload),
                        identification=ident,
                    )
                    frame = build_eth_frame(dst_mac, src_mac, 0x0800,
                                            ip_hdr + udp_hdr + payload)

                    try:
                        s.send(frame)
                        sent_total += 1
                    except BrokenPipeError:
                        print("Socket send error (BrokenPipe). The NIC/driver "
                              "may have rejected frame.")
                        raise
                    except OSError as e:
                        print(f"Socket send OSError: {e}")
                        raise

                    if interval > 0:
                        time.sleep(interval)

                    now = time.time()
                    if now >= next_report:
                        elapsed = now - start_time
                        rate_obs = sent_total / elapsed if elapsed > 0 else 0
                        print(f"Sent {sent_total} frames (avg {rate_obs:.1f} "
                              "pkt/s). Current src_mac="
                              f"{bytes_to_mac_str(src_mac)}")
                        next_report = now + 1.0

        except KeyboardInterrupt:
            elapsed = time.time() - start_time
            avg_rate = sent_total / elapsed if elapsed > 0 else 0
            print(f"\n\nKeyboardInterrupt received — stopping. Sent "
                  f"{sent_total} frames in {elapsed:.2f}s (avg {avg_rate:.1f} "
                  "pkt/s).")

    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def parse_args():
    p = argparse.ArgumentParser(
        description="Send UDP frames with spoofed source MAC per frame "
        "(Linux, root).")
    p.add_argument("--iface",
                   required=True,
                   help="Interface to send on (e.g. eth0)")
    p.add_argument("--dst-mac",
                   required=True,
                   help="Destination MAC (aa:bb:cc:dd:ee:ff)")
    p.add_argument(
        "--src-ip",
        default="10.254.1.1",
        help="Source IP address used in IPv4 header",
    )
    p.add_argument(
        "--dst-ip",
        default="10.255.1.1",
        help="Destination IP address used in IPv4 header",
    )
    p.add_argument("--src-port",
                   type=int,
                   default=12345,
                   help="UDP source port")
    p.add_argument("--dst-port",
                   type=int,
                   default=12345,
                   help="UDP destination port")
    p.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of source MAC addresses to generate and cycle",
    )
    p.add_argument(
        "--rate",
        type=float,
        default=10.0,
        help="Packets per second (0 means as fast as possible)",
    )
    p.add_argument(
        "--mode",
        choices=("sequential", "random"),
        default="sequential",
        help="MAC generation mode",
    )
    p.add_argument(
        "--base-oui",
        default="02:00:00",
        help="Base OUI for generated source MACs",
    )
    return p.parse_args()


def main():
    args = parse_args()
    if ":" not in args.dst_mac or len(args.dst_mac.split(":")) != 6:
        print("Invalid --dst-mac format; expected aa:bb:cc:dd:ee:ff")
        sys.exit(2)
    if args.count <= 0:
        print("--count must be > 0")
        sys.exit(2)
    if not os.geteuid() == 0:
        print("Error: Must be run as root.")
    send_spoofed_udp(
        iface=args.iface,
        dst_mac_str=args.dst_mac,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        count=args.count,
        rate=args.rate,
        mode=args.mode,
        base_oui=args.base_oui,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nKeyboardInterrupt received — exiting.")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
