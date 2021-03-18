using System.Runtime.InteropServices;
namespace HackerFramework
{
    internal class WinAPI
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(int hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetProcAddress(int hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualAllocEx(int hProcess, int lpAddress, int size, uint allocation_type, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(int hProcess, int lpAddress, int dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int CreateRemoteThread(int hProcess, int lpThreadAttributes, uint dwStackSize, int lpStartAddress, int lpParameter, uint dwCreationFlags, int lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(int hProcess, int lpBaseAddress, int dwSize, uint new_protect, ref uint lpOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(int hProcess, int lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        public const int PROCESS_CREATE_THREAD = 0x02;
        public const int PROCESS_QUERY_INFORMATION = 0x400;
        public const int PROCESS_VM_OPERATION = 0x08;
        public const int PROCESS_VM_READ = 0x10;
        public const int PROCESS_VM_WRITE = 0x20;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;

        public const uint PAGE_NOACCESS = 0x1;
        public const uint PAGE_READONLY = 0x2;
        public const uint PAGE_READWRITE = 0x4;
        public const uint PAGE_WRITECOPY = 0x8;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOCACHE = 0x200;
        public const uint PAGE_WRITECOMBINE = 0x400;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public uint AllocationProtect;
            public int RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
    }
}
