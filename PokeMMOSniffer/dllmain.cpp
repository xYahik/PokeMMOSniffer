// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <psapi.h>
#include <vector>
#include <iostream>
#include "Utils.h"

DWORD old_protect;
unsigned char* hook_location;// = (unsigned char*)0x0379FA55 + 0x7; 
DWORD ret_adress;// = (DWORD)hook_location + 0x06;//0x02FD40E3;
bool bSend = false;
BYTE SendScanCount = 0;
Packet packet;



void print_hex(unsigned char* string, int arraysize) {
    for (int i = 0; i < arraysize; i++) {
        printf(" %02x", string[i]);
    }
}

__declspec(naked) void hSend() {

    __asm {
        pushad
        pushfd
        MOV EAX, DWORD PTR[EBX]
        MOV packet.unknown1, EAX

        MOV EAX, DWORD PTR[EBX + 0x4]
        MOV packet.unknown2, EAX

        MOV EAX, DWORD PTR[EBX + 0x8]
        MOV packet.unknown3, EAX

        MOV AX, WORD PTR[EBX + 0xC]
        MOV packet.unknown4, AX

        MOV AH, BYTE PTR[EBX + 0xE]
        MOV packet.packet_opcode, AH

        MOV packet.packet_length, EDI

        xor cx, cx
        loop1 :
        MOVZX ESI, CX
            MOV AH, BYTE PTR[EBX + 0xF + ESI]
            mov[packet.test + ESI], AH
            inc cx
            movzx AX, [packet.packet_length]
            cmp cx, AX
            jle loop1

    }
    printf("[%d] %x ", packet.packet_length, packet.packet_opcode);
    if (packet.packet_length > 1)
        print_hex(packet.test, (int)packet.packet_length - 1);
    printf("\n");

    __asm {
        popfd
        popad
        mov esi, edx
        mov edx, dword ptr ss : [esp + 0x78]
        jmp ret_adress
    }
}

DWORD FindPattern(std::vector<int> pattern, DWORD startAdress = 0, DWORD endAdress = 0) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (startAdress == 0) {
        startAdress = (DWORD)(si.lpMinimumApplicationAddress);
    }
    if (endAdress == 0) {
        endAdress = (DWORD)(si.lpMaximumApplicationAddress);
    }

    MEMORY_BASIC_INFORMATION mbi{ 0 };
    DWORD protectFlags = (PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS);

    for (DWORD i = startAdress; i < endAdress - pattern.size(); i++) {
        if (VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi))) {
            if (mbi.Protect & protectFlags || !(mbi.State & MEM_COMMIT)) {
                i += mbi.RegionSize;
                continue;
            }
            for (DWORD j = (DWORD)mbi.BaseAddress; j < (DWORD)mbi.BaseAddress + mbi.RegionSize - pattern.size(); j++) {
                for (DWORD k = 0; k < pattern.size(); k++) {
                    if (pattern.at(k) != -1 && pattern.at(k) != *(BYTE*)(j + k))
                        break;
                    if (k + 1 == pattern.size())
                        return j;
                }
            }
            i = (DWORD)mbi.BaseAddress + mbi.RegionSize;
        }
    }
    return NULL;
}

void SendFunc() {
    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    printf("Scanning for SendPattern\n");

    while (1) {
        Sleep(3000);
        std::vector<int> sig = { 0x89,0xB4,0x24,0xBC,0x00,0x00,0x00,0x8B,0xF2,0x8B,0x54,0x24,0x78,0x89,0x34,0x24,0x89,0x7C,0x24,0x04,0x89,0x5C,0x24,0x08 };
        DWORD entry = FindPattern(sig, 0x2000000, 0x5000000);
        if (entry != NULL && SendScanCount == 0) {
            SendScanCount = 1;
        }
        if (entry != NULL && !bSend && SendScanCount > 0) {
            printf("[Length] [Opcode] [Rest packet]\n");
            bSend = true;
            hook_location = (unsigned char*)entry + 0x7;
            ret_adress = (DWORD)hook_location + 0x6;
            VirtualProtect((void*)hook_location, 8, PAGE_EXECUTE_READWRITE, &old_protect);
            *hook_location = 0xE9;
            *(DWORD*)(hook_location + 1) = (DWORD)&hSend - ((DWORD)hook_location + 5);
            *(hook_location + 5) = 0x90;
        }
    }
}

DWORD WINAPI tThread(LPVOID param)
{
    std::thread threadSend(SendFunc);
    threadSend.join();
    return 0x0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CreateThread(nullptr, 0, tThread, nullptr, 0, nullptr);
        DisableThreadLibraryCalls(hModule);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


