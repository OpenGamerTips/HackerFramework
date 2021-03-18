using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using static HackerFramework.WinAPI;

namespace HackerFramework
{
    /// <summary>
    /// The main controller of HackerFramework's dependencies and introduction to applications.
    /// </summary>
    public class Interface
    {
        internal static Process Proc;
        internal static int Handle;
        internal static int ModuleAddress;
        internal static int ModuleSize;

        /// <summary>
        /// Attach to the given process.
        /// </summary>
        public static void Attach(Process P)
        {
            Proc = P;
            Handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, P.Id);
            ModuleAddress = P.MainModule.BaseAddress.ToInt32();
            ModuleSize = P.MainModule.ModuleMemorySize;
        }

        /// <summary>
        /// Attach to the given process ID.
        /// </summary>
        public static void Attach(int PID)
        {
            Proc = Process.GetProcessById(PID);
            Handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, PID);
            ModuleAddress = Proc.MainModule.BaseAddress.ToInt32();
            ModuleSize = Proc.MainModule.ModuleMemorySize;
        }

        /// <summary>
        /// Attach to the given process ID.
        /// </summary>
        /// <param name="Index">This is the index to find. -1 means to find the last one avaliable.</param>
        public static void Attach(string Name, int Index = -1)
        {
            if (Index == -1)
            {
                Proc = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(Name)).Last();
            }
            else
            {
                Proc = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(Name))[Index];
            }
            Handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, Proc.Id);
            ModuleAddress = Proc.MainModule.BaseAddress.ToInt32(); // IntPtr is a pain
            ModuleSize = Proc.MainModule.ModuleMemorySize;
        }

        internal static string GetDedicatedFolder() // Don't touch the god dang folder you idiot
        {
            bool DirExists = Directory.Exists("hacker_framework");
            if (!DirExists) Directory.CreateDirectory("hacker_framework");
            DirExists = Directory.Exists("hacker_framework/temp");
            if (!DirExists) Directory.CreateDirectory("hacker_framework/temp");
            DirExists = Directory.Exists("hacker_framework/dependencies");
            if (!DirExists) Directory.CreateDirectory("hacker_framework/dependencies");
            return "hacker_framework";
        }

        internal static int RunDependency(string FileName, string Args = "") // TODO: File downloads for dependencies
        {
            string Folder = GetDedicatedFolder();
            if (!File.Exists(Folder + "/dependencies/" + FileName))
            {
                using (WebClient Client = new WebClient())
                {
                    Client.DownloadFile("https://github.com/OpenGamerTips/HackerFramework/raw/main/dependencies/" + FileName, Folder + "/dependencies/" + FileName);
                }
            }

            // Start process and get stdout.
            string Command = $".\\..\\dependencies\\{FileName} {Args}";
            Debug.WriteLine(Command);
            ProcessStartInfo NewStartInfo = new ProcessStartInfo("cmd", $"/c {Command}");
            NewStartInfo.WorkingDirectory = Folder + "/temp";
            NewStartInfo.CreateNoWindow = true;

            Process NewProc = new Process();
            NewProc.StartInfo = NewStartInfo;
            NewProc.Start();
            NewProc.WaitForExit();

            return NewProc.ExitCode;
        }

        /// <summary>
        /// Release memory that you allocated when attaching.
        /// </summary>
        public static void Exit()
        {
            CloseHandle(Handle);
        }

        /// <summary>
        /// Downloads and opens COPYING.md for HackerFramework. Contains copyright/license notices for HackerFramework.
        /// </summary>
        public static void DisplayCredits()
        {
            string Folder = GetDedicatedFolder();
            using (WebClient Client = new WebClient())
            {
                File.WriteAllText(Folder + "/COPYING.txt", Client.DownloadString("https://raw.githubusercontent.com/OpenGamerTips/HackerFramework/main/COPYING.md"));
                Process.Start(Path.GetFullPath(Folder + "/COPYING.txt"));
            }
        }
    }
}
