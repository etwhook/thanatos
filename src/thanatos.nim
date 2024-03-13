#[
    << INTRO >>
    Thanatos, A Nim DLL Poisoner.
    What is DLL Poisoning?
    It's a way to proxy most of the functions of a legit DLL, then make custom (exported) functions that call the legit functions from the replaced DLL but with extra code that does whatever you want (eg. load Shellcode).
    So think of it as a way to "intercept" DLL functions *globally* without having to patch memory in all processes. 
    It's just really a modified way of proxying DLLs.
    You can intercept parameters / arguments easily with it.
    This can be used to bypass many ACs (um) like Byfron.
    I will mostly use NimProxy2's code in this PoC.
]#

#[
    << USAGE >>
    ./thanatos.exe -d <path_to_dll> -f <custom_functions> -o <output_path> -s <suffix>
]#
import winim, ptr_math, strformat, strutils

type
    Addresses = object
     Names: PDWORD
     Functions: PDWORD
     Ordinals: PWORD
     NumberOfNames: DWORD

proc DLLBase(dll: string): PVOID = 
    return cast[PVOID](LoadLibraryA(dll))

proc GetEATInfo(pe: DWORD_PTR): Addresses =
    let dosHeader = cast[PIMAGE_DOS_HEADER](pe)
    let ntHeader = cast[PIMAGE_NT_HEADERS](pe + dosHeader.elfanew)
    let optHeader = ntHeader.OptionalHeader
    var eat: PIMAGE_DATA_DIRECTORY = cast[PIMAGE_DATA_DIRECTORY](&(optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]))
    var eatDir: PIMAGE_EXPORT_DIRECTORY = cast[PIMAGE_EXPORT_DIRECTORY](pe + eat.VirtualAddress)
    var names: PDWORD = cast[PDWORD](pe + eatDir.AddressOfNames)
    var functions: PDWORD = cast[PDWORD](pe + eatDir.AddressOfFunctions)
    var ordinals: PWORD = cast[PWORD](pe + eatDir.AddressOfNameOrdinals)
    var numNames: DWORD = eatDir.NumberOfNames
    return Addresses(
        Names: names,
        Functions: functions,
        Ordinals: ordinals,
        NumberOfNames: numNames
    )

proc Thanatos( dllPath, output, suffix: string, args: seq[string]) =
    let base = DLLBase(dllPath)
    if (base == nil):
        quit(-1)
    let pe = cast[DWORD_PTR](base)
    let addresses = GetEATInfo(pe)
    var names = addresses.Names
    #var functions = addresses.Functions
    var ordinals = addresses.Ordinals
    var numNames = addresses.NumberOfNames
    let file = open(output,fmAppend)
    file.write("#include<Windows.h>\n")
    file.write("#define DllExport __declspec(dllexport)\n\n")
    for i in 0..numNames - 1:
        var name = $(cast[LPCSTR](pe + names[i]))
        if name in args:
            echo(fmt"[!!!] Function {name} Poison Template Considered!")
            continue
        var ordinal = cast[DWORD](ordinals[i])
        echo(fmt"[*] Proxying {name} @{{{ordinal}}}")
        let valid_path = dllPath.replace(".dll","").replace(r"\",r"\\")
        file.write($"""#pragma comment(linker , "/export:""" & name & "=" & valid_path & suffix & "." & name & """")""" & "\n")
    for function in args:
        file.write("\n\n" & fmt"DllExport void WINAPI {function} () {{}};")

    file.write("\n\n" & """
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch(fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            printf("Hello, Thanatos");
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return 1;
}
    """)

when isMainModule:
    import cligen; dispatch Thanatos