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
unsigned char* hook_location;
DWORD SendPacketAdress;
unsigned char* SendPacketAdressRet;
DWORD RecvPacketAdress;
unsigned char* RecvPacketAdressRet;
BYTE SendScanCount = 0;
BYTE RecvScanCount = 0;
Packet packet;



void print_hex(unsigned char* string, int arraysize) {
    for (int i = 0; i < arraysize; i++) {
        printf("%02x ", string[i]);
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

        MOV packet.packet_length, ESI

        xor cx, cx
        loop1 :
        MOVZX ESI, CX
        MOV AH, BYTE PTR[EBX + 0xF + ESI]
        mov [packet.packet + ESI], AH
        inc cx
        movzx AX, [packet.packet_length]
        cmp cx, AX
        jle loop1

    }
    printf("Send: [%d]\t%02x ", packet.packet_length, packet.packet_opcode);
    if (packet.packet_length > 1)
        print_hex(packet.packet, (int)packet.packet_length - 1);
    printf("\n");

    __asm {
        popfd
        popad
        mov ecx, dword ptr ss : [esp + 0x48]
        mov dword ptr ss : [esp] , edi
        jmp SendPacketAdressRet
    }
}

__declspec(naked) void hRecv() {

    __asm {
        pushad
        pushfd

        MOV EAX, DWORD PTR[ESP + 0x24]
        MOV packet.unknown1, EAX

        MOV EAX, DWORD PTR[ESP + 0x24 + 0x4]
        MOV packet.packet_length, EAX

        MOV EBX, DWORD PTR[ESP + 0x24 + 0x8]

        MOV AH, BYTE PTR[EBX + 0xE]
        MOV packet.packet_opcode, AH

        xor cx, cx
        loop1 :
        MOVZX ESI, CX
        MOV AH, BYTE PTR[EBX + 0xF + ESI]
        mov[packet.packet + ESI], AH
        inc cx
        movzx AX, [packet.packet_length]
        cmp cx, AX
        jle loop1

    }

    printf("Recv: [%d]\t%02x ", packet.packet_length, packet.packet_opcode);
    if (packet.packet_length > 1)
        print_hex(packet.packet, (int)packet.packet_length - 1);
    printf("\n");

    __asm {
        popfd
        popad
        add esp, 0x78
        pop ebp
        mov ebx, dword ptr fs : [0]
        jmp RecvPacketAdressRet
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

void HookFunc() {
    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    printf("Looking for Send and Recv Patterns\n");

    //Looking for Send
    while (SendPacketAdress == NULL) {
        Sleep(1000);
        if (SendPacketAdress == NULL) {
            std::vector<int> patternSend = { 0x8B,0x4C,0x24,0x48,0x89,0x3C,0x24,0x89,0x74,0x24,0x04,0x89,0x5C,0x24,0x08,0x89,0x44,0x24,0x0C };
            SendPacketAdress = FindPattern(patternSend, 0x2000000, 0x5000000);
            if (SendPacketAdress != NULL && SendScanCount == 0) {
                SendPacketAdress = NULL;
                SendScanCount++;
            }
        }
        if (SendPacketAdress != NULL)
            printf("Found Send DecryptedPacket\n");

    }

    //Looking for Recv
    while (RecvPacketAdress == NULL) {
        Sleep(1000);
        if (RecvPacketAdress == NULL) {
            std::vector<int> patternRecv = { 0x8B,0x4C,0x24,0x60,0x89,0x3C,0x24,0x89,0x74,0x24,0x04,0x89,0x5C,0x24,0x08,0x89,0x44,0x24,0x0C };
            RecvPacketAdress = FindPattern(patternRecv, 0x2000000, 0x5000000);
            if (RecvPacketAdress != NULL && RecvScanCount == 0) {
                RecvPacketAdress = NULL;
                RecvScanCount++;
            }
        }
        if (RecvPacketAdress != NULL)
            printf("Found Recv DecryptedPacket\n");


    }
    printf("-\n");

    if (SendPacketAdress != NULL) {
        hook_location = (unsigned char*)SendPacketAdress;
        SendPacketAdressRet = hook_location + 0x7;
        VirtualProtect((void*)hook_location, 8, PAGE_EXECUTE_READWRITE, &old_protect);
        *hook_location = 0xE9;
        *(DWORD*)(hook_location + 1) = (DWORD)&hSend - ((DWORD)hook_location + 5);
        *(hook_location + 5) = 0x90;
        *(hook_location + 6) = 0x90;
    }

    if (RecvPacketAdress != NULL) {
        hook_location = (unsigned char*)RecvPacketAdress + 0x19;
        RecvPacketAdressRet = hook_location + 0xC;
        VirtualProtect((void*)hook_location, 8, PAGE_EXECUTE_READWRITE, &old_protect);
        *hook_location = 0xE9;
        *(DWORD*)(hook_location + 1) = (DWORD)&hRecv - ((DWORD)hook_location + 5);
        *(hook_location + 5) = 0x90;
        *(hook_location + 6) = 0x90;
        *(hook_location + 7) = 0x90;
        *(hook_location + 8) = 0x90;
        *(hook_location + 9) = 0x90;
        *(hook_location + 10) = 0x90;
        *(hook_location + 11) = 0x90;
    }
}

DWORD WINAPI tThread(LPVOID param)
{
    std::thread threadHook(HookFunc);
    threadHook.join();
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


