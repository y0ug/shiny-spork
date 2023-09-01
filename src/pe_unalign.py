#!/usr/bin/env python3
import sys
import pefile


def pe_unalign(data):
    pe = pefile.PE(data=data)
    pe_len = pe.DOS_HEADER.e_lfanew + pe.OPTIONAL_HEADER.SizeOfHeaders
    clean_pe = bytearray(data[:pe_len])

    for section in pe.sections:
        if section.SizeOfRawData == 0:  # VirtualSection
            continue

        pos_raw = section.PointerToRawData
        size_data = section.SizeOfRawData
        pos_rva = section.VirtualAddress
        clean_pe[pos_raw:pos_raw+size_data] = data[pos_rva:pos_rva+size_data]
    return clean_pe


if __name__ == "__main__":
    data = open(sys.argv[1], 'rb').read()
    sys.stdout.buffer.write(pe_unalign(data))
