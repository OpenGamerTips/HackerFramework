using System;
using System.Runtime.CompilerServices;
using static HackerFramework.WinAPI;

namespace HackerFramework
{
    /// <summary>
    /// Controls the all-memory baseline of HackerFramework.
    /// </summary>
    public class Memory
    {
        private static int int_ = 0;
        private static uint uint_ = 0;

        /// <summary>
        /// Rebases the given address by the module address.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Rebase(int Address)
        {
            return (Address + Interface.ModuleAddress);
        }

        /// <summary>
        /// Rebases the given address by 0x400000 with the module address.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ASLR(int Address)
        {
            return (Address - 0x400000 + Interface.ModuleAddress);
        }

        // I don't know a good name for this
        /// <summary>
        /// Rebases the given address by 0x400000 without the module address for use in cheats that rebase it again.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ASLRBase(int Address)
        {
            return (Address + 0x400000 - Interface.ModuleAddress);
        }

        /// <summary>
        /// Makes the memory area completely accessible.
        /// </summary>
        public static void UnprotectMemory(int Address, int Size)
        {
            VirtualProtectEx(Interface.Handle, Address, Size, PAGE_EXECUTE_READWRITE, ref uint_);
        }

        /// <summary>
        /// Sets the protection of a memory area.
        /// </summary>
        /// <returns>The old protection.</returns>
        public static uint SetMemoryProtection(int Address, int Size, uint Type)
        {
            uint Old = 0;
            VirtualProtectEx(Interface.Handle, Address, Size, Type, ref Old);
            return Old;
        }

        /// <summary>
        /// Allocates memory to the attached application.
        /// </summary>
        public static int AllocateShared(int Size)
        {
            return VirtualAllocEx(Interface.Handle, 0, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }

        /// <summary>
        /// Deallocates the shared memory.
        /// </summary>
        /// <param name="Address">The address returned by AllocateShared.</param>
        public static bool DeallocateShared(int Address)
        {
            return VirtualFreeEx(Interface.Handle, Address, 0, MEM_RELEASE);
        }

        // not even gonna write summaries for these because they are self-explainatory
        public static byte[] ReadBytes(int Address, int Offset)
        {
            byte[] Buffer = new byte[Offset];
            ReadProcessMemory(Interface.Handle, Address, Buffer, Offset, ref int_);
            return Buffer;
        }

        public static byte ReadByte(int Address)
        {
            return ReadBytes(Address, 1)[0];
        }

        public static ushort ReadUShort(int Address)
        {
            return BitConverter.ToUInt16(ReadBytes(Address, sizeof(ushort)), 0);
        }

        public static short ReadShort(int Address)
        {
            return BitConverter.ToInt16(ReadBytes(Address, sizeof(short)), 0);
        }

        public static uint ReadUInt32(int Address)
        {
            return BitConverter.ToUInt32(ReadBytes(Address, sizeof(uint)), 0);
        }

        public static int ReadInt32(int Address)
        {
            return BitConverter.ToInt32(ReadBytes(Address, sizeof(int)), 0);
        }

        public static ulong ReadUInt64(int Address)
        {
            return BitConverter.ToUInt32(ReadBytes(Address, sizeof(ulong)), 0);
        }

        public static long ReadInt64(int Address)
        {
            return BitConverter.ToInt64(ReadBytes(Address, sizeof(long)), 0);
        }

        public static float ReadFloat(int Address)
        {
            return BitConverter.ToSingle(ReadBytes(Address, sizeof(float)), 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static float ReadSingle(int Address) { return ReadFloat(Address); }

        public static double ReadDouble(int Address)
        {
            return BitConverter.ToDouble(ReadBytes(Address, sizeof(double)), 0);
        }

        public static bool WriteBytes(int Address, byte[] Buffer)
        {
            return WriteProcessMemory(Interface.Handle, Address, Buffer, Buffer.Length, ref int_);
        }

        public static bool WriteByte(int Address, byte Value)
        {
            byte[] Buffer = new byte[1];
            Buffer[0] = Value;
            return WriteBytes(Address, Buffer);
        }

        public static bool WriteUShort(int Address, ushort Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        public static bool WriteShort(int Address, short Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        public static bool WriteUInt32(int Address, uint Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        public static bool WriteInt32(int Address, int Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        public static bool WriteUInt64(int Address, ulong Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        public static bool WriteInt64(int Address, long Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        public static bool WriteFloat(int Address, float Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool WriteSingle(int Address, float Value) { return WriteFloat(Address, Value); }

        public static bool WriteDouble(int Address, double Value)
        {
            byte[] Buffer = BitConverter.GetBytes(Value);
            return WriteBytes(Address, Buffer);
        }

        /// <summary>
        /// Exactly like memcpy in C++.
        /// </summary>
        public static void Copy(int New, int Old, int Size) // memcpy implementation
        {
            byte[] OldBuffer = ReadBytes(Old, Size);
            WriteBytes(New, OldBuffer);
        }

        /// <summary>
        /// Exactly like memset in C++.
        /// </summary>
        public static void Set(int Address, byte Value, int Size) // memset implementation
        {
            for (int Idx = 0; Idx < Size; Idx++)
            {
                WriteByte(Address + Idx, Value);
            }
        }
    }
}