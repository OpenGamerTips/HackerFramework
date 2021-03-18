using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using static HackerFramework.WinAPI;

namespace HackerFramework
{
    #region Exceptions Used in this Section
    [Serializable]
    public class AOBNotFoundException : Exception
    {
        public AOBNotFoundException() : base("The array of bytes specified does not exist.") { }
    }

    [Serializable]
    public class EmptyShellcodeException : Exception
    {
        public EmptyShellcodeException() : base("You cannot pass empty shellcode to this function.") { }
    }
    #endregion

    /// <summary>
    /// A line of a full assembly dump
    /// </summary>
    public class AsmLine // A line in dumped assembly.
    {
        public string Code;         // The instruction in nasm (Edited to look a little more like intel) format. i.e: 'push ebp'
        public int Size;        // The size of the instruction (Alias for AsmLine.Bytes.Length)
        public byte[] Bytes;        // The instruction, in bytes.
        public string BytesStr;     // The same thing as Bytes but it's a string.
    }

    /// <summary>
    /// A full dump of an assembly source.
    /// </summary>
    public class AsmDump
    {
        public string Code;
        public int Size;
        public byte[] Bytes;
        public string BytesStr;
        public List<AsmLine> Lines;
    }

    internal class NasmParser // Parses the output of ndisasm.exe
    {
        internal static string Format(string Code)
        {
            Code = Code.Replace(",", ", "); // make commas neat
            Code = Code.Replace("byte +", ""); // what.
            Code = Code.Replace("byte -", "-");
            Code = Code.Replace("0x", "");
            Code = Code.Replace("+", " + "); // neato the addition

            return Code;
        }

        internal static AsmDump Parse(string Dump, bool DoFormat = true) // moving from objdump to ndisam to avoid GPL licensing.
        {
            List<AsmLine> Lines = new List<AsmLine>();
            Regex IdxRegex = new Regex(@"^[a-f-A-F-0-9]+  ");
            Regex HexRegex = new Regex(@"^([a-f-A-F-0-9]{2})+");
            Regex WhiteRegex = new Regex(@"^\s+");

            string FullCode = "";
            string FullByteStr = "";
            List<byte> FullByteList = new List<byte>();
            foreach (string Line in Dump.Split('\n'))
            {
                string LineIdxStripped = IdxRegex.Replace(Line, ""); // To remove the beginning index (i.e: 00000000)
                string HexStripped;
                Match Bytes = HexRegex.Match(LineIdxStripped); // Get the bytes (i.e: 83EC10)
                if (Bytes.Success) // Bytes found; there's obviously code too
                {
                    //string[] SplitBytes = Regex.Split(Bytes.Value, "(?<=^(.{2})+)"); // bug patch where the first byte would repeat for some reason?? idk but i just inserted and split instead
                    string InsBytes = Regex.Replace(Bytes.Value, ".{2}", "$0 ");
                    string[] SplitBytes = InsBytes.Split(' ');
                    HexStripped = HexRegex.Replace(LineIdxStripped, "");

                    string ByteStr = "";
                    List<byte> ByteList = new List<byte>();
                    foreach (string Hexadecimal in SplitBytes)
                    {
                        if (Hexadecimal.Length > 1)
                        {
                            FullByteStr += Hexadecimal + " ";
                            ByteStr += Hexadecimal + " ";

                            byte Hex2Byte = byte.Parse(Hexadecimal, NumberStyles.HexNumber);
                            ByteList.Add(Hex2Byte);
                            FullByteList.Add(Hex2Byte);
                        }
                    }

                    string Code = WhiteRegex.Replace(HexStripped, "");
                    Code = DoFormat ? Format(Code) : Code; // a little formatting won't hurt
                    FullCode += Code;
                    FullCode += '\n';

                    AsmLine AsmData = new AsmLine();
                    AsmData.Bytes = ByteList.ToArray();
                    AsmData.BytesStr = ByteStr.Substring(0, ByteStr.Length - 1);
                    AsmData.Size = ByteList.Count;
                    AsmData.Code = Code;
                    Lines.Add(AsmData);
                }
            }

            AsmDump ReturnDump = new AsmDump();
            ReturnDump.Bytes = FullByteList.ToArray();
            ReturnDump.BytesStr = FullByteStr.Substring(0, FullByteStr.Length - 1);
            ReturnDump.Size = FullByteList.Count;
            ReturnDump.Code = FullCode;
            ReturnDump.Lines = Lines;

            return ReturnDump;
        }
    }

    /// <summary>
    /// A class providing information about the trampoline that was created. This contains a function that allows for you to revert the trampoline.
    /// </summary>
    /// <seealso cref="Remove"/>
    public class Trampoline
    {
        public int Address;
        public byte[] Old;
        public int Air;
        public int AirSize;

        /// <summary>
        /// Reverts the trampoline.
        /// </summary>
        public void Remove()
        {
            Memory.WriteBytes(Address, Old);
            Memory.DeallocateShared(Air);
        }
    }

    /// <summary>
    /// A class providing information about the hook. This contains a function that allows you to unhook.
    /// </summary>
    public class Hook
    {
        public Trampoline Boing;
        public int ExecutedAddress;
        public void Remove()
        {
            x86.Hooks.Remove(this);
            Boing.Remove();
            Memory.DeallocateShared(ExecutedAddress);
        }
        public void Unhook() { Remove(); }
    }

    /// <summary>
    /// Contains x86 registers.
    /// </summary>
    public class R32
    {
        public const byte EAX = 0;
        public const byte ECX = 1;
        public const byte EDX = 2;
        public const byte EBX = 3;
        public const byte ESP = 4;
        public const byte EBP = 5;
        public const byte ESI = 6;
        public const byte EDI = 7;
    }

    /// <summary>
    /// Contains the functions for screwing around with x86 assembly.
    /// </summary>
    public class x86
    {
        #region Assembly
        /// <summary>
        /// Disassembles assembly shellcode.
        /// </summary>
        /// <returns>An AsmDump class. This class provides useful things about the bytes of your code.</returns>
        public static AsmDump Disassemble(byte[] Shellcode)
        {
            File.WriteAllBytes(Interface.GetDedicatedFolder() + "/temp/dump.bin", Shellcode);
            return DisassembleDumpFile();
        }

        internal static AsmDump DisassembleDumpFile()
        {
            string Temp = Interface.GetDedicatedFolder() + "/temp";
            int DisamExit = Interface.RunDependency("ndisasm.exe", "-p intel -b32 dump.bin > disassembly.txt 2>&1");
            if (DisamExit == 0)
            {
                string Dump = File.ReadAllText(Temp + "/disassembly.txt");
                return NasmParser.Parse(Dump);
            }
            else
            {
                string Error = File.ReadAllText(Temp + "/disassembly.txt");
                throw new Exception("Disassembly failed:\n" + Error.Substring(0, Error.Length - 1));
            }
        }

        /// <summary>
        /// Assembles the given code then disassembles it.
        /// </summary>
        /// <returns>An AsmDump class. This class provides useful things about the bytes of your code.</returns>
        public static AsmDump Assemble(string Asm)
        {
            string Temp = Interface.GetDedicatedFolder() + "/temp";
            File.WriteAllText(Temp + "/source.s", $"_main:\n{Asm}\n");

            int CompileOut = Interface.RunDependency("nasm.exe", "-f elf32 -o out.elf32 source.s > compile.log 2>&1"); // compile it
            if (CompileOut == 0)
            {
                // Get the .text segment of the elf file (lol tiny elf parser)
                Stream ElfStream = File.OpenRead(Temp + "/out.elf32");
                BinaryReader Reader = new BinaryReader(ElfStream);
                try
                {
                    byte[] Header = Reader.ReadBytes(6);
                    if (!(Header[0] == 0x7F && Header[1] == 0x45 && Header[2] == 0x4C && Header[3] == 0x46 && Header[4] == 1 && Header[5] == 1)) // 32 bit, little endian
                    {
                        throw new Exception("ELF parsing failed.");
                    }
                    ElfStream.Position += 26;
                    ElfStream.Position = Reader.ReadInt64(); // Section header

                    int Revolutions = 0;
                    int TextOffset;
                    int TextSize;
                    bool IsProg = false;
                    while (true)
                    {
                        if (Revolutions > 100) // yeah we aren't gonna find anything
                        {
                            throw new Exception("ELF parsing failed.");
                        }

                        Reader.ReadInt32(); // ShName but its not needed
                        int ShType = Reader.ReadInt32();
                        if (ShType == 0x1) // PROGBITS
                        {
                            IsProg = true;
                        }

                        Reader.ReadInt32(); // ShFlags
                        Reader.ReadInt32(); // ShAddr
                        int ShOffset = Reader.ReadInt32();
                        int ShSize = Reader.ReadInt32();
                        if (IsProg) // is .text
                        {
                            TextOffset = ShOffset;
                            TextSize = ShSize;
                            break;
                        }
                        Reader.ReadInt32(); // ShLink
                        Reader.ReadInt32(); // ShInfo
                        Reader.ReadInt32(); // ShAddralign
                        Reader.ReadInt32(); // ShEntsize
                        Revolutions++;
                    }

                    ElfStream.Position = TextOffset;
                    File.WriteAllBytes(Temp + "/dump.bin", Reader.ReadBytes(TextSize));
                    Reader.Dispose();
                    ElfStream.Dispose();
                }
                catch (IndexOutOfRangeException)
                {
                    Reader.Dispose();
                    ElfStream.Dispose();
                    throw new Exception("ELF parsing failed. (No .text segment found)");
                }

                return DisassembleDumpFile();
            }
            else
            {
                throw new Exception("There was a problem compiling:\n" + File.ReadAllText(Temp + "/compile.log"));
            }
        }
        #endregion

        #region Pro/Epilogues
        /// <summary>
        /// Checks if there is an prologue at the given address.
        /// </summary>
        /// <returns>A boolean telling you if there is an prologue at the address.</returns>
        public static bool IsPrologue(int Address)
        {
            byte[] Bytes = Memory.ReadBytes(Address, 3);
            if ((Bytes[0] == 0x55 && Bytes[1] == 0x8B && Bytes[2] == 0xEC) || (Bytes[0] == 0x53 && Bytes[1] == 0x8B && Bytes[2] == 0xDC) || (Bytes[0] == 0x56 && Bytes[1] == 0x8B && Bytes[2] == 0xF4))
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Checks if there is an epilogue at the given address.
        /// </summary>
        /// <returns>A boolean telling you if there is an epilogue at the address.</returns>
        public static bool IsEpilogue(int Address)
        {
            byte[] Bytes = Memory.ReadBytes(Address - 1, 2);
            ushort Retn = Memory.ReadUShort(Address + 2);
            if (((Bytes[0] == 0x5D || Bytes[0] == 0xC9) && ((Bytes[1] == 0xC2) || Bytes[1] == 0xC3))) // pop ebp ? leave; retn ? ret;
            {
                return true;
            }

            return false;
        }
        #endregion

        #region Misc
        /// <summary>
        /// Gets the size of the function at the given address.
        /// </summary>
        /// <returns>An integer representing the size of the function.</returns>
        public static int GetFunctionSize(int Address)
        {
            return GetEpilogue(Address) - GetPrologue(Address) + 1;
        }

        /// <summary>
        /// Gets the size of the full instruction (with its operands) at the given address.
        /// </summary>
        /// <returns>An integer representing the size of the instruction.</returns>
        public static int GetInstructionSize(int Address) // Return the size, in bytes, of the instruction at the address.
        {
            byte[] Bytes = Memory.ReadBytes(Address, 16); // 16 bytes will guarantee that I get at least one instruction out of the buffer.
            return Disassemble(Bytes).Lines.First().Size;
        }

        /// <summary>
        /// Gets the point where a rel32 instruction would point to. This is used for following calls and jmps.
        /// </summary>
        /// <returns>In integer representing the address when followed.</returns>
        public static int GetRel32(int Address)
        {
            return Address + 5 + Memory.ReadInt32(Address + 1); // We are going past the instruction then going to the area it points to.
        }

        /// <summary>
        /// Determines whether the instruction at the given address is a call instruction.
        /// </summary>
        /// <returns>A boolean telling you if the instruction at the given address is a call instruction.</returns>
        public static bool IsCall(int Address)
        {
            int Rel = GetRel32(Address);
            return (Rel % 16 == 0 && Rel > Interface.ModuleAddress && Rel < Interface.ModuleAddress + Interface.ModuleSize);
        }

        /// <summary>
        /// Gets the point where a rel16 instruction would point to. This is used for following calls and jmps.
        /// </summary>
        /// <returns>In integer representing the address when followed.</returns>
        public static int GetRel16(int Address)
        {
            return Address + 5 + Memory.ReadShort(Address + 1); // We are going past the instruction then going to the area it points to.
        }
        #endregion

        #region Scanning
        /// <summary>
        /// Gets the function after the function at the given address.
        /// </summary>
        /// <returns>An integer representing the prologue of the next function.</returns>
        public static int GetNextFunc(int Address)
        {
            if (IsPrologue(Address)) Address++;
            while (!IsPrologue(Address))
            {
                Address++;
            }

            return Address;
        }

        /// <summary>
        /// Gets the function before the function at the given address.
        /// </summary>
        /// <returns>An integer representing the prologue of the last function.</returns>
        public static int GetLastFunc(int Address)
        {
            if (IsPrologue(Address)) Address--;
            while (!IsPrologue(Address))
            {
                Address--;
            }

            return Address;
        }

        /// <summary>
        /// Gets the prologue of the function at the given address.
        /// </summary>
        /// <returns>An integer representing the prologue of the function.</returns>
        public static int GetPrologue(int Address)
        {
            if (IsPrologue(Address)) return Address;
            return GetLastFunc(Address);
        }

        /// <summary>
        /// Gets the epilogue of the function at the given address.
        /// </summary>
        /// <returns>An integer representing the epilogue of the function.</returns>
        public static int GetEpilogue(int Address)
        {
            if (IsEpilogue(Address)) return Address;
            while (!IsEpilogue(Address))
            {
                //Console.WriteLine("{0:X2}", Memory.ReadByte(Address));
                Address++;
            }
            return Address;
        }

        /// <summary>
        /// Gets the next call from the given address.
        /// </summary>
        /// <returns>An integer representing the call.</returns>
        public static int GetNextCall(int Address)
        {
            byte Check = Memory.ReadByte(Address);
            if (Check == 0xE8) Address++;
            while (Address < 0x7FFFFFFF)
            {
                if (Memory.ReadByte(Address) == 0xE8 && IsCall(Address))
                {
                    return Address;
                }
                Address++;
            }
            return 0;
        }

        /// <summary>
        /// Gets the next call from the given address then follows it.
        /// </summary>
        /// <returns>An integer representing the call's rel32.</returns>
        public static int GetNextCallFunc(int Address)
        {
            int Next = GetNextCall(Address);
            if (Next != 0)
            {
                return GetRel32(Next);
            }
            return 0;
        }

        /// <summary>
        /// Gets the last call from the given address.
        /// </summary>
        /// <returns>An integer representing the call.</returns>
        public static int GetLastCall(int Address)
        {
            byte Check = Memory.ReadByte(Address);
            if (Check == 0xE8) Address++;
            while (Address < 0x7FFFFFFF)
            {
                if (Memory.ReadByte(Address) == 0xE8 && IsCall(Address))
                {
                    return Address;
                }
                Address--;
            }
            return 0;
        }

        /// <summary>
        /// Gets the last call from the given address then follows it.
        /// </summary>
        /// <returns>An integer representing the call's rel32.</returns>
        public static int GetLastCallFunc(int Address)
        {
            int Next = GetLastCall(Address);
            if (Next != 0)
            {
                return GetRel32(Next);
            }
            return 0;
        }

        /// <summary>
        /// Gets a list of call instructions from the address to your size. If the size is -1 then it will get the function's calls.
        /// </summary>
        /// <returns>A list showing the calls from the given address down.</returns>
        public static List<int> GetCalls(int Address, int Size = -1)
        {
            List<int> Calls = new List<int>();
            if (Size == -1)
            {
                int FuncStart = GetPrologue(Address);
                int FuncEnd = GetEpilogue(Address);
                Address = FuncStart;
                while (Address <= FuncEnd)
                {
                    int Next = GetNextCall(Address);
                    Calls.Add(Next);
                    Address = Next;
                }
                Calls.Remove(Calls.Last());
            }
            return Calls;
        }

        /// <summary>
        /// Gets a list of followed call instructions from the address to your size. If the size is -1 then it will get the function's calls.
        /// </summary>
        /// <returns>A list showing the followed addresses from the given address down.</returns>
        public static List<int> GetCallFuncs(int Address, int Size = -1)
        {
            List<int> Calls = new List<int>();
            if (Size == -1)
            {
                int FuncStart = GetPrologue(Address);
                int FuncEnd = GetEpilogue(Address);
                Address = FuncStart;
                while (Address <= FuncEnd)
                {
                    int Next = GetNextCall(Address);
                    Calls.Add(GetRel32(Next));
                    Address = Next;
                }
                Calls.Remove(Calls.Last());
            }
            return Calls;
        }
        #endregion

        #region Hacking
        /// <summary>
        /// Replaces the assembly at the given address with the given payload. This is a wrapper for WriteBytes.
        /// </summary>
        /// <exception cref="EmptyShellcodeException"></exception>
        public static void ReplaceAssembly(int Address, byte[] Shellcode)
        {
            if (Shellcode.Length < 1)
            {
                throw new EmptyShellcodeException();
            }

            uint Old = Memory.SetMemoryProtection(Address, Shellcode.Length, PAGE_EXECUTE_READWRITE);
            Memory.WriteBytes(Address, Shellcode);
            Memory.SetMemoryProtection(Address, Shellcode.Length, Old);
        }

        /// <summary>
        /// Uses code caves to inject an assembly payload to the given address.
        /// </summary>
        /// <returns>A Trampoline class. The class has a function that allows for you to revert the trampoline.</returns>
        /// <exception cref="EmptyShellcodeException"></exception>
        public static Trampoline InjectAssembly(int Address, byte[] Shellcode)
        {
            if (Shellcode.Length < 1)
            {
                throw new EmptyShellcodeException();
            }

            AsmDump Disassembled = Disassemble(Memory.ReadBytes(Address, 16));
            List<byte> TrampolineAddon = new List<byte>();
            foreach (AsmLine Line in Disassembled.Lines)
            {
                if (TrampolineAddon.Count > 4) break;
                TrampolineAddon.AddRange(Line.Bytes);
            }

            byte[] TrampolineAddonArray = TrampolineAddon.ToArray();
            int AddonLen = TrampolineAddon.Count;
            int PayloadSize = Shellcode.Length + AddonLen + 5; // Enough room for the shellcode, the trampoline addon, and the jump back
            int Cave = Memory.AllocateShared(PayloadSize); // Let's allocate that code cave

            int AsmInjectionPoint = Cave + AddonLen;
            int JmpBackPoint = AsmInjectionPoint + Shellcode.Length;

            int JmpTo = (Cave - Address) - 5;
            int JmpBack = (Address - Cave) - PayloadSize + 5;

            Memory.WriteBytes(Cave, TrampolineAddonArray);
            Memory.WriteBytes(AsmInjectionPoint, Shellcode);
            Memory.WriteByte(JmpBackPoint, 0xE9); // jmp ?? ?? ?? ??
            Memory.WriteInt32(JmpBackPoint + 1, JmpBack);
            //Console.WriteLine("Free Bytes: {0}, Air: 0x{1:X8}", AddonLen, Air);

            uint OldProt = Memory.SetMemoryProtection(Address, AddonLen, PAGE_EXECUTE_READWRITE);
            Memory.Set(Address, 0x90, AddonLen); // Fill with nopsw
            Memory.WriteByte(Address, 0xE9); // jmp ?? ?? ?? ??
            Memory.WriteInt32(Address + 1, JmpTo);
            Memory.SetMemoryProtection(Address, AddonLen, OldProt);

            Trampoline Data = new Trampoline();
            Data.Address = Address;
            Data.Air = Cave; // Air and AirSize for deallocating
            Data.AirSize = PayloadSize;
            Data.Old = TrampolineAddonArray;
            return Data;
        }

        /// <summary>
        /// Uses code caves to inject an assembly payload to the given AOB. This is a wrapper for InjectAssembly.
        /// </summary>
        /// <returns>A Trampoline class. The class has a function that allows for you to revert the trampoline.</returns>
        /// <exception cref="AOBNotFoundException"></exception>
        /// <exception cref="EmptyShellcodeException"></exception>
        public static Trampoline InjectAssemblyAtAOB(string AOB, byte[] Shellcode) // Wraps for InjectAssembly
        {
            if (Shellcode.Length < 1)
            {
                throw new EmptyShellcodeException();
            }

            List<int> ScanResults = Scanner.AOBScan(AOB);
            if (ScanResults.Count > 0)
            {
                return InjectAssembly(ScanResults.Last(), Shellcode);
            }
            else
            {
                throw new AOBNotFoundException(); // young me realizing i need to update aobs every time the game updates or sigs every once in a while
            }
        }

        /// <summary>
        /// Interrupts a function by inserting a return at the given address.
        /// </summary>
        public static void DisableFunction(int Address)
        {
            uint Old = Memory.SetMemoryProtection(Address, 0x3FF, PAGE_EXECUTE_READWRITE);
            if (IsPrologue(Address)) // Make sure you return correctly
            {
                ushort Retn = Memory.ReadUShort(GetEpilogue(Address) + 1);
                Memory.WriteByte(Address + 3, 0xC2);
                Memory.WriteUShort(Address + 4, Retn);
            }
            else
            {
                Memory.WriteByte(Address, 0xC3); // Return at the address.
            }
            Memory.SetMemoryProtection(Address, 0x3FF, Old);
        }

        internal static byte[] CreateDebugRoutine(byte Register, int Offset, (int, int) Addresses)
        {
            List<byte> Payload = new List<byte>();
            // Open eax so we can use it
            Payload.Add(0x60); // pushad
            Payload.Add(0x50); // push eax

            // Move the value in the register at index Offset to eax
            if (Offset >= 128) // Determine if the mov operand should be an integer or a byte
            {
                byte[] OffsetBytes = BitConverter.GetBytes(Offset);
                Payload.Add(0x8B); // mov eax, [Reg + Off32]
                Payload.Add((byte)(0x80 + Register));
                Payload.Add(OffsetBytes[0]);
                Payload.Add(OffsetBytes[1]);
                Payload.Add(OffsetBytes[2]);
                Payload.Add(OffsetBytes[3]);
            }
            else
            {
                Payload.Add(0x8B); // mov eax, [Reg + Off8]
                Payload.Add((byte)(0x40 + Register));
                Payload.Add((byte)Offset);
            }

            // Move the contents of eax into the Variables
            byte[] VarMovAddr = BitConverter.GetBytes(Addresses.Item1);
            Payload.Add(0xA3); // mov [Variables + Off], eax
            Payload.Add(VarMovAddr[0]);
            Payload.Add(VarMovAddr[1]);
            Payload.Add(VarMovAddr[2]);
            Payload.Add(VarMovAddr[3]);

            // Write to the "notification box" to tell us when it's ready and stop halting the application
            byte[] ReadyMovAddr = BitConverter.GetBytes(Addresses.Item2);
            Payload.Add(0xC7); // mov [ReadyAddr], 0x01
            Payload.Add(0x05);
            Payload.Add(ReadyMovAddr[0]);
            Payload.Add(ReadyMovAddr[1]);
            Payload.Add(ReadyMovAddr[2]);
            Payload.Add(ReadyMovAddr[3]);
            Payload.Add(0x01);
            Payload.Add(0x00);
            Payload.Add(0x00);
            Payload.Add(0x00);

            // Clean up the registers and get ready for the jmp back
            Payload.Add(0x58); // pop eax
            Payload.Add(0x61); // popad
            return Payload.ToArray();
        }

        internal static List<Hook> Hooks = new List<Hook>();
        /// <summary>
        /// Hooks the given address without giving it direct access to assembly. This allows for use of native C# functions. If your application has sanity checks on memory, this is not for you.
        /// </summary>
        /// <returns>A Hook class. The class has assets for dealing with unhooking.</returns>
        public static Hook HookIndirect(int Address, Func<bool> Function)
        {
            int Executed = Memory.AllocateShared(4); // Allocate an integer so we can tell when the assembly was executed.

            List<byte> Payload = new List<byte>();
            byte[] ExecMovAddr = BitConverter.GetBytes(Executed);
            Payload.Add(0xC7); // mov [ExecutedAddr], 0x01
            Payload.Add(0x05);
            Payload.Add(ExecMovAddr[0]);
            Payload.Add(ExecMovAddr[1]);
            Payload.Add(ExecMovAddr[2]);
            Payload.Add(ExecMovAddr[3]);
            Payload.Add(0x01);
            Payload.Add(0x00);
            Payload.Add(0x00);
            Payload.Add(0x00);

            Trampoline Boing = InjectAssembly(Address, Payload.ToArray()); // Hook the address
            Hook Hk = new Hook();
            Hk.Boing = Boing;
            Hk.ExecutedAddress = Executed;
            Hooks.Add(Hk);

            Task.Factory.StartNew(delegate
            {
                while (true)
                {
                    while (Memory.ReadInt32(Executed) == 0)
                    {
                        if (!Hooks.Contains(Hk)) return; // Feels like bad practice but idk
                        Thread.Sleep(10);
                    }
                    Function();
                    Memory.WriteInt32(Executed, 0);
                }
            });

            return Hk;
        }

        /// <summary>
        /// Debugs a register. Allows for you to steal values that can be essential to exploitation.
        /// </summary>
        public static int Debug(int Address, byte Register, int Offset = 0)
        {
            // Allocate the memory we will use when debugging
            int Var = Memory.AllocateShared(8);
            int Ready = Var + 5;

            byte[] Routine = CreateDebugRoutine(Register, Offset, (Var, Ready)); // Construct our routine
            Trampoline Boing = InjectAssembly(Address, Routine); // Hook the address

            int RegisterValue;
            while (Memory.ReadInt32(Ready) == 0) Thread.Sleep(10);
            Boing.Remove(); // Revert the trampoline
            RegisterValue = Memory.ReadInt32(Var); // Get the stolen register
            Memory.DeallocateShared(Var); // Clean up

            //Console.WriteLine("Debugging finished! Register Value: 0x{0:X8}", RegisterValue);
            return RegisterValue;
        }

        internal static void DebugInfThread(int Address, byte Register, int Offset, Func<int, bool> Callback)
        {
            // Allocate the memory we will use when debugging
            int Var = Memory.AllocateShared(8);
            int Ready = Var + 5;

            byte[] Routine = CreateDebugRoutine(Register, Offset, (Var, Ready)); // Construct our routine
            InjectAssembly(Address, Routine); // Hook the address

            while (true)
            {
                while (Memory.ReadInt32(Ready) == 0) Thread.Sleep(10);
                Callback(Memory.ReadInt32(Var));
                Memory.WriteInt32(Ready, 0); // Clear out the memory we used so we can start over.
            }
        }

        /// <summary>
        /// Debugs a register indefinetely. This allows a callback. If your application has sanity checks on memory, this is not for you.
        /// </summary>
        public static Task DebugInf(int Address, byte Register, Func<int, bool> Callback, int Offset = 0)
        {
            return Task.Factory.StartNew(() => DebugInfThread(Address, Register, Offset, Callback));
        }

        /// <summary>
        /// Waits for execution of assembly. If your application has sanity checks on memory, this is not for you.
        /// </summary>
        public static void WaitForExecution(int Address)
        {
            int Executed = Memory.AllocateShared(4); // Allocate an integer so we can tell when the assembly was executed.

            List<byte> Payload = new List<byte>();
            byte[] ExecMovAddr = BitConverter.GetBytes(Executed);
            Payload.Add(0xC7); // mov [ExecutedAddr], 0x01
            Payload.Add(0x05);
            Payload.Add(ExecMovAddr[0]);
            Payload.Add(ExecMovAddr[1]);
            Payload.Add(ExecMovAddr[2]);
            Payload.Add(ExecMovAddr[3]);
            Payload.Add(0x01);
            Payload.Add(0x00);
            Payload.Add(0x00);
            Payload.Add(0x00);

            Trampoline Boing = InjectAssembly(Address, Payload.ToArray()); // Hook the address
            while (Memory.ReadInt32(Executed) == 0) Thread.Sleep(10);
            Boing.Remove(); // Revert the trampoline
            Memory.DeallocateShared(Executed); // Clean up allocated memory
        }
        #endregion
    }
}