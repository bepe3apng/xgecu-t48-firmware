"""Decode a local T48 update for static analysis; never accesses USB.
Algorithm/key source: https://github.com/JohnDMcMaster/libxgecu
libxgecu/t48/t48crypto.py and t48decrypt.py (main).
"""
import binascii
import hashlib
import json
import struct
import argparse
from pathlib import Path


def decode(source, key):
    version, expected_crc, pad, count = struct.unpack_from("<4I", source)
    if version >> 16 != 0xF048 or len(source) != 16 + count * 276:
        raise ValueError("Unexpected T48 update format")
    if binascii.crc32(source[16:]) ^ 0xFFFFFFFF != expected_crc:
        raise ValueError("File CRC mismatch")
    if len(key) != 516:
        raise ValueError("Unexpected key length")
    blocks = []
    addresses = set()
    for i in range(count):
        crc, seed, unknown, block_pad, data = struct.unpack_from("<4I260s", source, 16 + i * 276)
        start = ((seed >> 8) + (seed & 255)) & 255
        swizzled = ((seed & 0x07070707) << 5) | ((seed & 0xF8F8F8F8) >> 3)
        fixed_key = struct.pack("<I", swizzled)
        raw = bytes(v ^ key[(j + start) % len(key)] ^ fixed_key[j % 4]
                    for j, v in enumerate(data))
        plain = bytes(((v & 0xE0) >> 5) | ((v & 0x1F) << 3) for v in raw)
        if binascii.crc32(plain) ^ 0xFFFFFFFF != crc:
            raise ValueError(f"Block {i} CRC mismatch")
        address = struct.unpack_from("<I", plain)[0]
        if not 0x08000000 <= address <= 0x080FFFFF or address % 256 or address in addresses:
            raise ValueError(f"Unexpected/duplicate block address {address:#x}")
        addresses.add(address)
        blocks.append((address, plain[4:]))
    base = min(addresses)
    image = bytearray(b"\xff" * (max(addresses) + 256 - base))
    for address, data in blocks:
        image[address-base:address-base+256] = data
    return bytes(image), dict(version=hex(version), blocks=count, base=hex(base),
                             end=hex(base+len(image)), all_block_crcs_valid=True,
                             source_sha256=hashlib.sha256(source).hexdigest())


def main():
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", type=Path, default=root / "t48_key.dat",
                        help="Local 516-byte libxgecu key.dat (no network or USB access)")
    args = parser.parse_args()
    if not args.key.is_file():
        parser.error(f"Key file not found: {args.key}. Obtain libxgecu/t48/key.dat "
                     "from https://github.com/JohnDMcMaster/libxgecu and pass --key PATH.")
    key = args.key.read_bytes()
    image, report = decode((root.parent / "OR/UpdateT48.dat").read_bytes(), key)
    report["key_sha256"] = hashlib.sha256(key).hexdigest()
    report["image_sha256"] = hashlib.sha256(image).hexdigest()
    output = root / "t48_firmware_decoded.bin"
    output.write_bytes(image)
    (root / "t48_firmware_decoded.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("Saved:", output)


if __name__ == "__main__":
    main()
