# macattack

**macattack** is a small Linux-only Python utility for lab testing of Layer-2 switches. It crafts raw Ethernet frames containing IPv4/UDP payloads and sends them on a specified interface while rotating the source MAC address for each frame. Use it to exercise a switch MAC address table (filling / aging) in a controlled lab environment.

> **Important safety note:** this tool sends forged Ethernet frames on your network. **Do not** run it on production or third-party networks. Only use macattack in isolated lab/test environments where you have permission.

---

# Requirements

- Linux (uses `AF_PACKET` raw sockets)
- Python 3.8+ (uses only standard library modules)
- Root privileges (or the `CAP_NET_RAW` capability)

To grant capability without running as root:

```bash
sudo setcap cap_net_raw+ep $(which python3)
```

If you don't set that capability you must run the script with `sudo`.

---

# Installation

Add `macattack.py` to your repository (or clone this repo) and make it executable:

```bash
chmod +x macattack.py
```

No additional packages are required.

---

# Usage

```
sudo python3 macattack.py --iface eth0 --dst-mac aa:bb:cc:dd:ee:ff --count 1000 --rate 100
```

Or, if you granted `CAP_NET_RAW` to your python binary:

```
python3 macattack.py --iface eth0 --dst-mac aa:bb:cc:dd:ee:ff --count 1000 --rate 100
```

## Options

- `--iface` (required) — Interface to send on (e.g. `eth0`, `enp3s0`).
- `--dst-mac` (required) — Destination MAC address in `aa:bb:cc:dd:ee:ff` format.
- `--src-ip` — Source IPv4 address used in the IP header. Default: `10.254.1.1`.
- `--dst-ip` — Destination IPv4 address used in the IP header. Default: `10.255.1.1`.
- `--src-port` — UDP source port. Default: `12345`.
- `--dst-port` — UDP destination port. Default: `12345`.
- `--count` — Number of source MAC addresses to generate and cycle. Default: `1000`.
- `--rate` — Packets per second. Use `0` for as-fast-as-possible. Default: `10.0`.
- `--mode` — MAC generation mode: `sequential` or `random`. Default: `sequential`.
- `--base-oui` — Base OUI for generated source MACs. Default: `02:00:00`.

---

# Behaviour & Notes

- The script generates a list of source MAC addresses (either sequential suffixes or random 3-octet suffixes appended to `--base-oui`) and continuously cycles through them, sending a UDP packet per frame with a short ASCII payload.
- IPv4 and UDP checksums are calculated and inserted into packets.
- The script prints progress once per second with total packets sent and the current source MAC.
- `--rate` controls the send interval as `1.0 / rate` seconds between frames. If `--rate 0` is provided, the script will send as fast as the OS and NIC allow.
- If the NIC/driver rejects the frame you may see `BrokenPipe` or `OSError` messages. That indicates the driver or hardware refused the raw frame — reduce rate or check NIC support.

---

# Example

Start a run with 10,000 MACs at 50 packets/sec:

```bash
sudo python3 macattack.py --iface enp5s0 --dst-mac aa:bb:cc:dd:ee:ff --count 10000 --rate 50 --mode sequential
```

Typical console output:

```
Generated 10000 source MACs. First: 02:00:00:00:00:00 Last: 02:00:00:00:27:0f
Starting continuous send on enp5s0: dst_mac=aa:bb:cc:dd:ee:ff, src_ip=10.254.1.1, dst_ip=10.255.1.1, rate=50.0 pkt/s
Sent 500 frames (avg 50.0 pkt/s). Current src_mac=02:00:00:00:00:0f
...
^C

KeyboardInterrupt received — stopping. Sent 10000 frames in 200.00s (avg 50.0 pkt/s).
```

---


# License

```
MIT License
Copyright (c) 2025 Rickey Ingrassia
```
