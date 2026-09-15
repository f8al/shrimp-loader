"""
Payload encryptor — prepares a .NET assembly for encrypted delivery.
Outputs XOR-encrypted or AES-encrypted byte arrays as C# source, raw binary, or hex.

Usage:
  python encrypt_payload.py xor <assembly_path> [--key <hex_key>] [--format cs|bin|hex]
  python encrypt_payload.py aes <assembly_path> [--key <hex_key>] [--iv <hex_iv>] [--format cs|bin|hex]
"""

import argparse
import os
import sys
from hashlib import sha256


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def format_csharp_array(name: str, data: bytes) -> str:
    lines = []
    lines.append(f"byte[] {name} = new byte[{len(data)}] {{")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f"    {hex_str},")
    lines.append("};")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Encrypt .NET assembly for in-memory delivery")
    parser.add_argument("mode", choices=["xor", "aes"])
    parser.add_argument("assembly", help="Path to .NET assembly")
    parser.add_argument("--key", help="Encryption key (hex string). Auto-generated if omitted.")
    parser.add_argument("--iv", help="AES IV (hex string, 32 hex chars). Auto-generated if omitted.")
    parser.add_argument("--format", choices=["cs", "bin", "hex"], default="cs",
                        help="Output format: cs (C# byte array), bin (raw binary), hex (hex dump)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout for cs/hex, required for bin)")
    args = parser.parse_args()

    with open(args.assembly, "rb") as f:
        assembly_bytes = f.read()

    print(f"[*] Assembly size: {len(assembly_bytes)} bytes", file=sys.stderr)

    if args.mode == "xor":
        if args.key:
            key = bytes.fromhex(args.key)
        else:
            key = os.urandom(16)
            print(f"[*] Generated XOR key: {key.hex()}", file=sys.stderr)

        encrypted = xor_encrypt(assembly_bytes, key)

        if args.format == "cs":
            output = format_csharp_array("encryptedAssembly", encrypted) + "\n\n"
            output += format_csharp_array("xorKey", key)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
            else:
                print(output)

        elif args.format == "bin":
            outpath = args.output or args.assembly + ".enc"
            with open(outpath, "wb") as f:
                f.write(encrypted)
            print(f"[+] Written to {outpath}", file=sys.stderr)
            print(f"[*] Decrypt with key: {key.hex()}", file=sys.stderr)

        elif args.format == "hex":
            output = encrypted.hex()
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
            else:
                print(output)

    elif args.mode == "aes":
        if args.key:
            key = bytes.fromhex(args.key)
        else:
            key = os.urandom(32)
            print(f"[*] Generated AES-256 key: {key.hex()}", file=sys.stderr)

        if args.iv:
            iv = bytes.fromhex(args.iv)
        else:
            iv = os.urandom(16)
            print(f"[*] Generated IV: {iv.hex()}", file=sys.stderr)

        encrypted = aes_encrypt(assembly_bytes, key, iv)
        print(f"[*] Encrypted size: {len(encrypted)} bytes", file=sys.stderr)

        if args.format == "cs":
            output = format_csharp_array("encryptedAssembly", encrypted) + "\n\n"
            output += format_csharp_array("aesKey", key) + "\n\n"
            output += format_csharp_array("aesIV", iv)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
            else:
                print(output)

        elif args.format == "bin":
            outpath = args.output or args.assembly + ".aes"
            with open(outpath, "wb") as f:
                f.write(encrypted)
            print(f"[+] Written to {outpath}", file=sys.stderr)

        elif args.format == "hex":
            output = encrypted.hex()
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
            else:
                print(output)


if __name__ == "__main__":
    main()
