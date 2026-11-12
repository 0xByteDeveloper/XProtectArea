// bcd.c — XProtect bytecode cozumleyici (vm_opcodes.h birebir)
// Kullanim: ./bcd <exe> <stub_rva> > plain.bin
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t i32; typedef int64_t i64;
#include "vm_opcodes.h"

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "kullanim: %s <exe> <stub_rva(hex)> <image_base_rva .vmp0(hex)> <vmp0_raw(hex)>\n", argv[0]); return 1; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("ac"); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8* d = malloc(sz); fread(d, 1, sz, f); fclose(f);
    u32 stub_rva = (u32)strtoul(argv[2], 0, 16);
    u32 vmp_rva = (u32)strtoul(argv[3], 0, 16);
    u32 vmp_raw = (u32)strtoul(argv[4], 0, 16);
    u8* s = d + (stub_rva - vmp_rva) + vmp_raw;
    // stub ayristir
    if (s[0] != 0x60) { fprintf(stderr, "pushad yok\n"); return 1; }
    u32 SUB = *(u32*)(s+3);
    u8* p = s + 7;   // pushad+sub
    p += 7;           // lea eax,[esp+SUB]
    p += 7;           // mov [esp+A8],eax
    p += 5;           // add eax,0x20
    p += 7;           // mov [esp+B0],eax
    u32 key_lo = *(u32*)(p+1); p += 5;
    p += 4;           // mov [esp+0x10],eax
    u32 key_hi = *(u32*)(p+1); p += 5;
    p += 4;           // mov [esp+0x14],eax
    p += 5;           // call L1
    p += 1;           // pop eax
    u32 l1 = *(u32*)(p+1); p += 5;
    p += 4;           // mov [esp+0x18],eax
    u32 bc_rva = *(u32*)(p+1); p += 5;
    p += 3;           // mov [esp],eax
    u32 bc_len = *(u32*)(p+1); p += 5;
    p += 4;           // mov [esp+8],eax
    u32 perm = *(u32*)(p+7); p += 11;
    u32 ksflags = p[7]; p += 8;
    u32 vm_id = *(u32*)(p+7); p += 11;
    u64 keyraw = ((u64)key_hi << 32) | key_lo;
    u64 key = keyraw ^ VM_KEYXOR(bc_rva, bc_len);
    u64 ekey = key ^ VM_VMK(vm_id);
    int adv = ksflags & 1;
    fprintf(stderr, "SUB=%x key=%016llx bc_rva=%06x bc_len=%x perm=%08x ks=%02x vm_id=%u adv=%d l1=%x\n",
            SUB, (unsigned long long)key, bc_rva, bc_len, perm, ksflags, vm_id, adv, l1);
    u8* bc = d + (bc_rva - vmp_rva) + vmp_raw;
    u8* plain = malloc(bc_len);
    u8 prev = 0;
    for (u32 i = 0; i < bc_len; i++) {
        plain[i] = bc[i] ^ (adv ? VM_KSCA(ekey, prev, i) : VM_KSC(ekey, prev, i));
        prev = bc[i];
    }
    fwrite(plain, 1, bc_len, stdout);
    // itab'i da yaz (stderr)
    unsigned char itab[VM_OPN];
    vm_perm_tab(perm, itab, 1);
    fprintf(stderr, "itab: ");
    for (int i = 0; i < VM_OPN; i++) fprintf(stderr, "%02X", itab[i]);
    fprintf(stderr, "\n");
    return 0;
}
