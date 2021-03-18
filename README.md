# HackerFramework
HackerFramework is a C# exploiting utility for games.

## Usage
----
Add HackerFramework.dll as a reference. Add this to your source file:
```csharp
using HackerFramework;
```

Open and exit games with Interface:
```csharp
Interface.Attach("RobloxPlayerBeta.exe");
// Do stuff
Interface.Exit();
```

Steal register data:
```csharp
Interface.Attach("RobloxPlayerBeta.exe");
int Gettop = Memory.ASLR(0xDEADBEEF);
int rL = x86.Debug(Gettop + 3, R32.EBP, 8);
Console.WriteLine("Lua State: 0x{0:X}", rL);
Interface.Exit();
```

Hook functions indirectly (Without direct assembly access):
```csharp
static bool ShootHook()
{
    Console.WriteLine("You just shot a bullet.");
    return true;
}

static void Main()
{
    Interface.Attach("ac_client.exe");
    int BulletDecrement = Scanner.AOBScan("FF 0E 57 8B 7C 24 14 8D 74 24 28 E8 87")[0];
    x86.HookIndirect(BulletDecrement, ShootHook);
    Console.ReadLine();
    Interface.Exit();
}
```

Dump Offsets/Addresses:
```csharp
Interface.Attach("RobloxPlayerBeta.exe");
int DeserializerXREF = Scanner.GetCrossReferences(": bytecode version mismatch")[0];
Console.WriteLine("Deserialize: 0x{0:X8}", Memory.ASLRBase(x86.GetPrologue(DeserializerXREF)));
Console.ReadLine();
Interface.Exit();
```

## Features:
----
- Memory reading and writing.
- Memory allocation and deallocation.
- Memory protection overwriter.
- Rebasing tools.
- Fast AOB Scanning (With wildcard bytes).
- AOB Tools (Unique AOB creator, XREF scanner).
- x86 Debugger.
- Trampoline hooking.
- Function disabling.
- Indirect hooking.
- And many more functions.