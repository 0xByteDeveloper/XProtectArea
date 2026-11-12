#!/usr/bin/env python3
# unic_x64_p3.py — test_b1iso_p.exe (x64 korumali) p3_main bolgesini
# Unicorn'da koşturur; stub+VM adimlari + NJCC kararini izler.
import struct, sys
from unicorn import *
from unicorn.x86_const import *

IMG = 0x140000000
IMGSZ = 0x800000
STK = 0x7FF000000000
STKSZ = 0x200000
TEB = 0x7FF100000000
PEB = 0x7FF200000000
SENT = 0x031F0000

def main():
    path = sys.argv[1]
    entry_rva = int(sys.argv[2], 0)
    ecx_val = int(sys.argv[3], 0)
    import pefile
    pe = pefile.PE(path)
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(IMG, IMGSZ)
    for s in pe.sections:
        d = s.get_data()
        if d:
            mu.mem_write(IMG + s.VirtualAddress, d)
    mu.mem_map(STK, STKSZ)
    mu.mem_map(TEB, 0x1000)
    mu.mem_map(PEB, 0x1000)
    mu.mem_map(SENT, 0x1000)
    mu.mem_write(TEB + 0x30, struct.pack('<Q', PEB))   # gs:[0x30] self
    mu.reg_write(UC_X86_REG_GS_BASE, TEB)
    rsp = STK + STKSZ - 0x10000
    mu.mem_write(rsp, struct.pack('<Q', SENT))          # ret -> SENTINEL
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_ECX, ecx_val)
    mu.reg_write(UC_X86_REG_RBP, STK + STKSZ - 0x8000)

    trace = '--trace' in sys.argv
    if trace:
        def hc(m, addr, size, ud):
            rax = m.reg_read(UC_X86_REG_RAX)
            rcx = m.reg_read(UC_X86_REG_RCX)
            print('  exec %012X rax=%016X rcx=%016X' % (addr, rax, rcx))
        mu.hook_add(UC_HOOK_CODE, hc)
    err = 'OK'
    try:
        mu.emu_start(IMG + entry_rva, SENT, timeout=30_000_000, count=50_000_000)
    except UcError as e:
        err = 'UCERR %s eip=%X' % (e, mu.reg_read(UC_X86_REG_RIP))
    print('ecx=%d -> rax=%016X (%d) err=%s'
          % (ecx_val, mu.reg_read(UC_X86_REG_RAX), mu.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF, err))

if __name__ == '__main__':
    main()
