def mac_str_to_bytes(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError("MAC must be 6 octets separated by ':'")
    return bytes(int(p, 16) for p in parts)


mac = mac_str_to_bytes("52:54:00:06:a7:0f")
print(mac)
