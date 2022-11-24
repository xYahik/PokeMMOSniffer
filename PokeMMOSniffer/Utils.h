#pragma once



struct Packet {
    DWORD unknown1;
    DWORD unknown2;
    DWORD unknown3;
    WORD unknown4;
    BYTE packet_opcode;
    DWORD packet_length;
    unsigned char packet[255];
};