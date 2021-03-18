using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using static HackerFramework.WinAPI;

namespace HackerFramework
{
    /// <summary>
    /// Contains all the functions for scanning in HackerFramework.
    /// </summary>
    public class Scanner
    {
        internal static List<int> ScanMemory(Func<byte[], int, MEMORY_BASIC_INFORMATION, bool> Callback, int By = 1, int Start = -1, int Stop = -1)
        {
            List<int> Matches = new List<int>();
            int At = (Start == -1) ? Interface.ModuleAddress : Start;
            Stop = (Stop == -1) ? (Interface.ModuleAddress + Interface.ModuleSize) : Stop;
            //Console.WriteLine("0x{0:X2}, 0x{1:X2}", At, Stop);

            MEMORY_BASIC_INFORMATION Info;
            while (At < Stop)
            {
                VirtualQueryEx(Interface.Handle, At, out Info, 0x20);
                byte[] Bytes = Memory.ReadBytes(At, Info.RegionSize);
                for (int AddrAt2 = 0; AddrAt2 < Info.RegionSize; AddrAt2 += By)
                {
                    if (Callback(Bytes, AddrAt2, Info))
                    {
                        Matches.Add(At + AddrAt2);
                    }
                }

                At += Info.RegionSize;
            }

            return Matches;
        }

        internal static int[] CurrPattern;
        internal static bool Sigcheck(byte[] ToCheck, int At, MEMORY_BASIC_INFORMATION Mbi)
        {
            if ((Mbi.State & MEM_COMMIT) == MEM_COMMIT && (Mbi.Protect & PAGE_GUARD) != PAGE_GUARD && (Mbi.Protect & PAGE_NOACCESS) != PAGE_NOACCESS) // Make sure we don't touch the wrong memory.
            {
                for (int Idx = 0; Idx < CurrPattern.Length; Idx++)
                {
                    //Console.WriteLine("{0} {1} {2}", Idx, ToCheck[At + Idx], CurrPattern[Idx]);
                    if (CurrPattern[Idx] != -1 && ToCheck[At + Idx] != CurrPattern[Idx]) // If not wildcard and doesn't match then
                    {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }

        internal static List<int> PatternScan(int[] Pattern, int By = 1)
        {
            CurrPattern = Pattern;
            return ScanMemory(Sigcheck, By);
        }

        /// <summary>
        /// Parses a string into an AOB.
        /// </summary>
        /// <returns>An integer array from the string.</returns>
        public static int[] ParseStringAOB(string Pattern)
        {
            Pattern = Pattern.Replace(" ", "");

            bool ModifiedToFit = false;
            if (!((Pattern.Length / 2) % 2 == 0))
            {
                ModifiedToFit = true;
                Pattern += "??";
            }

            int Len = (Pattern.Length / 2);
            int[] NewPattern = new int[Len];
            int At = 0;
            for (int Idx = 0; Idx < Len; Idx++)
            {
                string Byte = Pattern.Substring(At, 2);
                if (Byte == "??" || Byte == "?")
                {
                    NewPattern[Idx] = -1;
                }
                else
                {
                    NewPattern[Idx] = byte.Parse(Byte, NumberStyles.HexNumber);
                }

                At += 2;
            }

            if (ModifiedToFit)
            {
                Array.Resize(ref NewPattern, NewPattern.Length - 1); // remove last wildcard
            }
            return NewPattern;
        }

        /// <summary>
        /// Turns a string into an AOB. Example: "Q" -> "51"
        /// </summary>
        /// <returns>The AOB from the string.</returns>
        public static string String2AOB(string aString)
        {
            string AOB = "";
            foreach (char Character in aString)
            {
                AOB += ((int)Character).ToString("X2") + " ";
            }

            return AOB.Substring(0, (AOB.Length - 1));
        }

        /// <summary>
        /// Turns an AOB array back into a string.
        /// </summary>
        /// <returns>A string representing the given AOB.</returns>
        public static string AOB2String(int[] AOB)
        {
            string AOBStr = "";
            foreach (int x in AOB)
            {
                if (x == -1)
                {
                    AOBStr += "?? ";
                }
                else
                {
                    AOBStr += x.ToString("X2") + " ";
                }
            }
            return AOBStr;
        }

        /// <summary>
        /// Turns an address into an AOB.
        /// </summary>
        /// <returns>The created AOB.</returns>
        public static string Addr2AOB(int Addr)
        {
            byte[] Bytes = BitConverter.GetBytes(Addr);
            string AOB = "";
            foreach (byte Byte in Bytes)
            {
                AOB += Byte.ToString("X2") + " ";
            }

            return AOB.Substring(0, (AOB.Length - 1));
        }

        /// <summary>
        /// Scans for an AOB by a string.
        /// </summary>
        /// <returns>A list of the found results.</returns>
        public static List<int> AOBScan(string Pattern)
        {
            return PatternScan(ParseStringAOB(Pattern));
        }

        /// <summary>
        /// Scans for an AOB by a byte array.
        /// </summary>
        /// <returns>A list of the found results.</returns>
        public static List<int> AOBScan(byte[] Pattern) // no wildcard
        {
            int[] Convert = new int[Pattern.Length];
            Array.Copy(Pattern, Convert, Pattern.Length);
            return PatternScan(Convert);
        }

        /// <summary>
        /// Scans for an AOB by a signed byte array.
        /// </summary>
        /// <returns>A list of the found results.</returns>
        public static List<int> AOBScan(sbyte[] Pattern) // -1 for wildcard
        {
            int[] Convert = new int[Pattern.Length];
            Array.Copy(Pattern, Convert, Pattern.Length);
            return PatternScan(Convert);
        }

        /// <summary>
        /// Scans for an AOB by an integer array.
        /// </summary>
        /// <returns>A list of the found results.</returns>
        public static List<int> AOBScan(int[] Pattern) // -1 for wildcard
        {
            return PatternScan(Pattern);
        }

        /// <summary>
        /// Creates a unique AOB from the shellcode in the given address. This is really good for AOB injection.
        /// </summary>
        /// <returns>The constructed AOB.</returns>
        public static string CreateUniqueAOB(int Address)
        {
            List<int> CurrAOB = new List<int>();
            int AddrOff = 0;

            List<int> ScanResults;
            do
            {
                //Console.WriteLine(Memory.ReadByte(Address + CurrIdx));
                CurrAOB.Add(Memory.ReadByte(Address + AddrOff));
                AddrOff++;
                ScanResults = AOBScan(CurrAOB.ToArray());
                //Console.WriteLine("Matches: {0}, AOB: {1}", ScanResults.Count, AOB2String(CurrAOB.ToArray()));
            }
            while (ScanResults.Count > 1);

            return AOB2String(CurrAOB.ToArray());
        }

        /// <summary>
        /// Creates a signature from two AOBs. This is good for creating update-individual AOBs.
        /// </summary>
        /// <returns>The created AOB signature.</returns>
        public static string MakeSig(string Upd1AOB, string Upd2AOB)
        {
            int[] AOB1 = ParseStringAOB(Upd1AOB);
            int[] AOB2 = ParseStringAOB(Upd2AOB);
            if (AOB1.Length != AOB2.Length)
            {
                throw new Exception("Both AOBs need the same length.");
            }

            string Signature = "";
            for (int Idx = 0; Idx < AOB1.Length; Idx++)
            {
                int Byte1 = AOB1[Idx];
                int Byte2 = AOB2[Idx];
                //Console.WriteLine("{0:X2}, {1:X2}", Byte1, Byte2);
                if (Byte1 == -1 || Byte2 == -1)
                {
                    Signature += "?? ";
                }
                if (Byte1 != Byte2)
                {
                    Signature += "?? ";
                }
                else
                {
                    Signature += Byte1.ToString("X2") + " ";
                }
            }

            return Signature;
        }

        /// <summary>
        /// Gets the cross-references of the given string.
        /// </summary>
        /// <returns>A list of integers that are xrefs to the string.</returns>
        public static List<int> GetCrossReferences(string String)
        {
            int[] ParsedScan = ParseStringAOB(String2AOB(String)); // It's basically a pointer you could say
            List<int> ScanResults = PatternScan(ParsedScan, 4);
            if (ScanResults.Count > 0)
            {
                return AOBScan(Addr2AOB(ScanResults.Last()));
            }
            else
            {
                return ScanResults;
            }
        }
    }
}
