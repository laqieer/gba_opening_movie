#!/usr/bin/env python3
# add opening movie to gba game
# by laqieer
# 2019-11-3

from asm import *
from sys import *

if len(argv) != 3:
    print('usage: {} game.gba movie.gba'.format(argv[0]))
    exit(1)

with open(argv[1], 'rb+') as rom, open(argv[2], 'rb') as movie:
    rom.seek(0, 2)
    rom_size = rom.tell()
    # align 4
    if rom_size % 4 != 0:
        rom.write(b'\0' * (4 - rom_size % 4))
        rom_size = rom.tell()
    # add movie.gba
    rom.write(movie.read())
    # connect game and movie
    rom.seek(rom_size)
    assemble_here(rom, 'bx pc', 'T')
    rom.seek(0xc0)
    inst = disassemble_here(rom, 4, 'A') + 'b #0x80000c4'
    rom.seek(0xc0)
    assemble_here(rom, 'b #{}'.format(rom_size + 0xc0 + addr_rom_base), 'A')
    rom.seek(rom_size + 4)
    assemble_here(rom, inst, 'A')
    # fix pointers
    p = rom_size + 0xc0
    rom.seek(p)
    offset = scan_here(rom, 'mov r0, #0x53;msr cpsr_c, r0;mov r0, #0x50;msr cpsr_c, r0', 'A', 0x300)
    if offset is False:
        print('Error: cannot find the 1st offset.')
        exit(2)
    # pointer 1
    p += offset + 0x30
    rom.seek(p)
    p1 = rom.read(4)
    rom.seek(p)
    update_pointer_here(rom, rom_size)
    # pointer 2
    p += 0x20
    rom.seek(p)
    update_pointer_here(rom, rom_size)
    p += 0x10
    rom.seek(p)
    # offset = scan_here(rom, 'add r7, r0, r1;mov r1, #1;mov r0, r7', 'T', 0x200)
    offset = scan_here(rom, p1, 'B', 0x200)
    if offset is False:
        print('Error: cannot find the 2nd offset.')
        exit(3)
    # p += offset + 0xa
    p += offset - 0x1c
    rom.seek(p)
    assemble_here(rom, 'b #{}'.format(rom_size + addr_rom_base), 'T')
    # pointer 3
    p += 0x1c
    rom.seek(p)
    update_pointer_here(rom, rom_size)
    # pointer 4
    # offset = scan_here(rom, '\x02\x00\x06\x00\x0A\x00\x0E\x00\x12\x00\x16\x00\x1A\x00\x1E\x00\xFE\xFF\xFA\xFF\xF6\xFF\xF2\xFF\xEE\xFF\xEA\xFF\xE6\xFF\xE2\xFF', 'b', 0x100)
    p = rom.tell()
    offset = scan_here(rom, b'\x02\x00\x06\x00', 'b', 0x100)
    if offset is False:
        print('Error: cannot find the 3rd offset.')
        exit(4)
    p += offset
    # print('3rd offset: {:x}'.format(p))
    update_all_pointers(rom, p + addr_rom_base - rom_size, rom_size)
    # pointer 5
    rom.seek(p - 8)
    if is_pointer_here(rom):
        update_pointer_here(rom, rom_size)
    # todo: more cases
    
