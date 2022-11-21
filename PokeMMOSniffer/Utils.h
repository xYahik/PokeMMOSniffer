#pragma once



struct Packet {
    DWORD unknown1;
    DWORD unknown2;
    DWORD unknown3;
    WORD unknown4;
    BYTE packet_opcode;
    BYTE packet_sub_opcode;
    DWORD packet_length;
    unsigned char test[255];
};