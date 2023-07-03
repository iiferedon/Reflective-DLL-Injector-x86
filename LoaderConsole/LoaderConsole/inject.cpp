#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "inject.h"
#include "Stream.h"
#define PROCESS_NAME L"processname.exe" //Change this (x86)

typedef struct {
    PBYTE imageBase;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
    while (relocation->VirtualAddress) {
        PWORD relocationInfo = (PWORD)(relocation + 1);
        for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
            if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
                *(PDWORD)(loaderData->imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;

        relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDirectory->Characteristics) {
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);

        HMODULE module = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDirectory->Name);

        if (!module)
            return FALSE;

        while (originalFirstThunk->u1.AddressOfData) {
            DWORD Function = (DWORD)loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->imageBase + originalFirstThunk->u1.AddressOfData))->Name);

            if (!Function)
                return FALSE;

            firstThunk->u1.Function = Function;
            originalFirstThunk++;
            firstThunk++;
        }
        importDirectory++;
    }

    if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
        DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
            (loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
            ((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);


        loaderData->rtlZeroMemory(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint, 32);

        loaderData->rtlZeroMemory(loaderData->imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);

        return result;
    }
    return TRUE;
}

VOID stub(VOID) { }

int _fastcall Inject()
{
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    HANDLE process = NULL;
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    if (Process32FirstW(processSnapshot, &processInfo)) {
        do {
            if (!lstrcmpW(processInfo.szExeFile, PROCESS_NAME)) {
                process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, processInfo.th32ProcessID);
                break;
            }
        } while (Process32NextW(processSnapshot, &processInfo));
    }
    CloseHandle(processSnapshot);

    if (!process)
        return 0;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(Streaming::binary_mem + ((PIMAGE_DOS_HEADER)Streaming::binary_mem)->e_lfanew);

    PBYTE executableImage = reinterpret_cast<PBYTE>(VirtualAllocEx(process, NULL, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    WriteProcessMemory(process, executableImage, Streaming::binary_mem,
        ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        WriteProcessMemory(process, executableImage + sectionHeaders[i].VirtualAddress,
            Streaming::binary_mem + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);

    LoaderData* loaderMemory = reinterpret_cast<LoaderData*>(VirtualAllocEx(process, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READ));

    LoaderData loaderParams;
    loaderParams.imageBase = executableImage;
    loaderParams.loadLibraryA = LoadLibraryA;
    loaderParams.getProcAddress = GetProcAddress;
    loaderParams.rtlZeroMemory = (VOID(NTAPI*)(PVOID, SIZE_T))GetProcAddress(LoadLibraryW(L"ntdll"), "RtlZeroMemory");

    WriteProcessMemory(process, loaderMemory, &loaderParams, sizeof(LoaderData),
        NULL);
    WriteProcessMemory(process, loaderMemory + 1, loadLibrary,
        (DWORD)stub - (DWORD)loadLibrary, NULL);
    WaitForSingleObject(CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(loaderMemory + 1),
        loaderMemory, 0, NULL), INFINITE);
    VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);


    printf("Injected!\n");
    delete[] Streaming::binary_mem;
    return TRUE;
}
