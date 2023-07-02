#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <wininet.h>
#include "encrypt.h"
#include "Stream.h"
#include <chrono>
#include <thread>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib") 
#include <iostream>
#include "inject.h"
#include "Auth.hpp"


typedef HMODULE(WINAPI* LoadLibraryFunc)(LPCWSTR);
typedef FARPROC(WINAPI* GetProcAddressFunc)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* DllMainFunc)(HMODULE, DWORD, LPVOID);


void _fastcall OpenConsole() {
    AllocConsole();

    FILE* file;
    freopen_s(&file, "CONOUT$", "w", stdout);
    freopen_s(&file, "CONIN$", "r", stdin);
}


int main(int argc, char* argv[]) {
    OpenConsole();
    printf(skCrypt("Starting)\n"));
   

    if (Streaming::stream_dll())
    {
        printf(skCrypt("Injecting...\n"));
        Inject();
    }
    else
    {
        printf(skCrypt("Failed\n"));
    }
    
    Sleep(10000);



    return 1;
}


std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}