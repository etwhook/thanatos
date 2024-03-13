
# 🧪☣️ Thanatos

Dll **Poisoner** Written In **Nim**. 

```
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

```
## ⚙ Compiling

```
$ nim c -d:release thanatos.nim
```
## 🎡 Output

```
$ thanatos.exe -d C:\Windows\System32\cscapi.dll -o dllmain.c -s _1 OfflineFilesEnable
[*] Proxying CscNetApiGetInterface @{0}
[*] Proxying CscSearchApiGetInterface @{1}
[!!!] Function OfflineFilesEnable Poison Template Considered!
[*] Proxying OfflineFilesGetShareCachingMode @{3}
[*] Proxying OfflineFilesQueryStatus @{4}
[*] Proxying OfflineFilesQueryStatusEx @{5}
[*] Proxying OfflineFilesStart @{6}
...
```
