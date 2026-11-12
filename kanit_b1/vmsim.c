// vmsim.c — vm_core.c'yi konak (Linux) uzerinde koşturan izolasyon
// simülatörü. Kullanim:
//   gcc -O1 -DVM_IS_X64 -DVM_TRACE -DVM_LINUX_SIM -o vmsim vmsim.c vm_core.c
//   ./vmsim <enc.bin> <key_hex> <bc_len> <seed_hex> [base_hex]
// VMContext kurar, vm_entry cagirir; VM_TRACE ile /tmp/plain.bin + adim izi.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/home/z/my-project/scripts/xiangu_gh/XProtect/source/XProtectUI_Source/vm_core.c"

int main(int argc, char** argv) {
    if (argc < 5) { fprintf(stderr, "kullanim: vmsim enc.bin key bc_len seed [base]\n"); return 2; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("enc.bin"); return 2; }
    static unsigned char enc[65536];
    size_t n = fread(enc, 1, sizeof enc, f);
    fclose(f);
    VMContext* c = calloc(1, sizeof(VMContext));
    (void)n;
    unsigned long long key = strtoull(argv[2], 0, 16);
    unsigned long long bcl = strtoull(argv[3], 0, 0);
    unsigned int seed = (unsigned)strtoul(argv[4], 0, 16);
    unsigned long long base = argc > 5 ? strtoull(argv[5], 0, 16) : 0x400000ULL;
    // bc = encoder'inkine BENZER obfuscasyon: vm_entry key'i VM_KEYXOR ile
    // geri cozer — biz dogrudan DUZ anahtar veriyoruz, bu yuzden obf yolluyoruz.
    c->bc = (u64)(unsigned long)enc;
    c->bc_len = bcl;
    c->base = base;
    // vm_entry: bc_rva = bc - base (garantiye gerek yok; key'i obf ile ver)
    unsigned int bc_rva = (unsigned)(0); // bc - base negatif olur! -> base'i bc uzerine kur
    (void)bc_rva;
    c->base = (u64)(unsigned long)enc;   // base = bc adresi -> bc_rva = 0
    u64 kx = key ^ VM_KEYXOR(0, (u32)bcl);
    c->key = kx;                          // vm_entry ^= VM_KEYXOR(0,len) -> key
    c->scratch[3] = seed;
    static unsigned long long parea[16];
    for (int i = 0; i < 16; i++) parea[i] = 0;
    c->push_area = (u64)(unsigned long)parea;
    c->init_rsp = 0x7FF000ULL;
    c->regs[4] = 0x7FF000ULL;             // shadow rsp (kullanilmazsa dokunulmaz)
    vm_entry(c);
    printf("done=%llu rax=%016llX rcx=%016llX rdx=%016llX r8=%016llX\n",
           (unsigned long long)c->done,
           (unsigned long long)c->regs[0], (unsigned long long)c->regs[1],
           (unsigned long long)c->regs[2], (unsigned long long)c->regs[8]);
    return 0;
}
