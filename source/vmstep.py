#!/usr/bin/env python3
# vmstep.py — korumali exe'nin SDK bolgesini Unicorn'da komut-komut izle;
# orijinal ile karsilastir. x64.
import struct, sys
from unicorn import *
from unicorn.x86_const import *

def load_pe(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e+6)[0]
    optsz = struct.unpack_from('<H', d, e+20)[0]
    opt = e + 24
    ib = struct.unpack_from('<Q', d, opt + 24)[0]
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        name = d[o:o+8].split(b'\0')[0].decode(errors='replace')
        vsz, rva, rsz, rptr = struct.unpack_from('<IIII', d, o+8)
        secs.append((name, rva, vsz, rsz, rptr))
    return d, ib, secs

def run(path, start_rva, args, maxins=4000):
    d, ib, secs = load_pe(path)
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    top = max(rva + vsz for (_, rva, vsz, _, _) in secs)
    sz = (top + 0xFFFF) & ~0xFFFF
    mu.mem_map(ib, sz)
    for (_, rva, vsz, rsz, rptr) in secs:
        if rsz:
            mu.mem_write(ib + rva, d[rptr:rptr + rsz])
    STACK = 0x7FF000000000
    mu.mem_map(STACK - 0x100000, 0x100000)
    RETM = STACK - 0x800
    mu.mem_write(RETM, struct.pack('<Q', 0xDEAD0000))
    rsp0 = STACK - 0x1000
    mu.reg_write(UC_X86_REG_RSP, rsp0)
    for i, (reg, val) in enumerate(args):
        mu.reg_write(reg, val)
    trace = []
    def hook(uc, address, size, user_data):
        rip = address
        regs = []
        for name, reg in (('rax', UC_X86_REG_RAX), ('rbx', UC_X86_REG_RBX),
                          ('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX),
                          ('rsi', UC_X86_REG_RSI), ('rdi', UC_X86_REG_RDI)):
            regs.append(f"{name}={uc.reg_read(reg):#x}")
        trace.append((rip - ib, size, ' '.join(regs)))
    mu.hook_add(UC_HOOK_CODE, hook)
    try:
        mu.emu_start(ib + start_rva, RETM, count=maxins)
    except UcError as ex:
        print(f"[UC HATA] {ex} @rip={mu.reg_read(UC_X86_REG_RIP)-ib:#x}")
    return trace

if __name__ == '__main__':
    path = sys.argv[1]
    start = int(sys.argv[2], 16)
    orig = sys.argv[3] if len(sys.argv) > 3 else None
    ARGREGS = [(UC_X86_REG_RCX, 50), (UC_X86_REG_RBX, 0x1111), (UC_X86_REG_RDX, 0x2222)]
    tr = run(path, start, ARGREGS)
    print(f"== {path} @rva {start:#x} ({len(tr)} komut) ==")
    for (rva, size, regs) in tr[:60]:
        print(f"  {rva:06x}: {regs}")
    if orig:
        to = run(orig, start, ARGREGS)
        print(f"== ORIJINAL ({len(to)} komut) ==")
        for (rva, size, regs) in to[:20]:
            print(f"  {rva:06x}: {regs}")
