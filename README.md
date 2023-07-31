# DLL-Shellcode-Injector-x86
Downloads encrypted shellcode into memory from a server and maps it into an x86 process without touching the disk.

Barebones loader
- Downloads XOR'd DLL bytearray from an ubuntu server
- Decrypts bytearray and stores in a buffer
- Injects into x86 process
- Erases PE Headers
- Erases Entrypoint

#Note
- Needs to be able to get a handle to the process
- Uses CRT

