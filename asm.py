#!/usr/bin/env python3
# gba asm hacking
# by laqieer
# 2019-11-3

from capstone import *
from keystone import *
from struct import *

addr_rom_base = 0x8000000

def disassemble_here(rom, size, mode):
    '''
    disassemble assembly from rom
    '''
    if mode in ('arm', 'ARM', 'a', 'A', 32):
        cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    else:
        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    addr = rom.tell() + addr_rom_base
    code_byte = rom.read(size)
    code_asm = ''
    for i in cs.disasm(code_byte, addr):
        code_asm += i.mnemonic + ' ' + i.op_str + ';'
    return code_asm


def assemble_here(rom, code, mode):
    '''
    assemble assembly to rom
    '''
    if mode in ('arm', 'ARM', 'a', 'A', 32):
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    else:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    addr = rom.tell() + addr_rom_base
    code_asm = code.encode()
    code_byte = bytearray(ks.asm(code_asm, addr)[0])
    rom.write(code_byte)
    return addr - addr_rom_base, code_byte


def scan_here(rom, code, mode, offset_range=0):
    '''
    scan rom to find the first matched code offset
    '''
    start = rom.tell()
    rom.seek(0, 2)
    end = rom.tell()
    if offset_range == 0 or offset_range > end - start:
        offset_range = end - start
    offset = 0
    if mode in ('arm', 'ARM', 'a', 'A', 32):
        code_asm = code.encode()
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        while(offset < offset_range):
            code_byte = bytes(bytearray(ks.asm(code_asm, start + offset + addr_rom_base)[0]))
            rom.seek(start + offset, 0)
            rom_byte = rom.read(len(code_byte))
            if code_byte == rom_byte:
                break
            offset += 4
    elif mode in ('thumb', 'THUMB', 't', 'T', 16):
        code_asm = code.encode()
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        while(offset < offset_range):
            code_byte = bytes(bytearray(ks.asm(code_asm, start + offset + addr_rom_base)[0]))
            rom.seek(start + offset, 0)
            rom_byte = rom.read(len(code_byte))
            if code_byte == rom_byte:
                break
            offset += 2
    else:
        if code is str:
            code_byte = code.encode()
        else:
            code_byte = code
        while(offset < offset_range):
            rom.seek(start + offset, 0)
            rom_byte = rom.read(len(code_byte))
            if code_byte == rom_byte:
                break
            offset += 1        
    if offset >= offset_range:
        return False
    return offset


def update_pointer_here(rom, offset):
    '''
    update pointer by offset
    '''
    pointer = unpack('<I', rom.read(4))[0]
    rom.seek(-4, 1)
    rom.write(pack('<I', pointer + offset))
    print('{0:x}: {1:x} -> {2:x}'.format(rom.tell() - 4, pointer, pointer + offset))


def update_all_pointers(rom, pointer, offset, offset_range=0):
    '''
    update all occurences of specific pointer
    '''
    start = rom.tell()
    rom.seek(0, 2)
    end = rom.tell()
    if offset_range == 0 or offset_range > end - start:
        offset_range = end - start
    p = start
    while(p < start + offset_range):
        rom.seek(p, 0)
        pointer1 = unpack('<I', rom.read(4))[0]
        if pointer1 == pointer:
            rom.seek(-4, 1)
            rom.write(pack('<I', pointer + offset))
            print('{0:x}: {1:x} -> {2:x}'.format(rom.tell() - 4, pointer, pointer + offset))
        p += 4
    
    
def main():
    with open('../fireemblem8u/fireemblem8.gba', 'rb+') as rom:
        print(disassemble_here(rom, 4, 'ARM'))
        rom.seek(0xfffff0)
        print(assemble_here(rom, 'push {lr};pop {r0}; bx r0', 'THUMB'))
        rom.seek(0xc0)
        print(scan_here(rom, 'mov r3, #0x4000000; add r3, r3, #0x200', 'ARM', 0x100))
        rom.seek(0)
        print(scan_here(rom, 'FIREEMBLEM', 'b', 0xc0))


if __name__ == "__main__":
    main()
