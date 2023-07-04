# DLL-Shellcode-Injector-x86
Downloads encrypted shellcode into memory from a server and maps it into an x86 process without touching the disk.

Barebones loader to paste
- Downloads XOR'd DLL bytearray from an ubuntu server
- Decrypts bytearray and stores in a buffer
- Injects into x86 process
- Erases PE Headers
- Erases Entrypoint
- Only works on games that have little to no anticheat, and where you can get a handle to the process with no issues.

