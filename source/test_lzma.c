// test_lzma.c — LZMA encode/decode saglama (motor disi hizli test)
// gcc -O2 test_lzma.c lzma/LzmaEnc.c lzma/LzFind.c lzma/LzmaDecode.cc -o /tmp/testlzma
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lzma/LzmaEnc.h"
#include "lzma/LzmaDecode.h"

static void *SzAlloc(void *p, size_t size) { (void)p; return malloc(size); }
static void SzFree(void *p, void *address) { (void)p; free(address); }
static ISzAlloc g_Alloc = { SzAlloc, SzFree };

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "kullanim: testlzma <dosya>\n"); return 2; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("acilamadi"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* src = (unsigned char*)malloc(n);
    if (fread(src, 1, n, f) != (size_t)n) { fprintf(stderr, "oku hatasi\n"); return 2; }
    fclose(f);
    printf("girdi: %ld bayt\n", n);

    CLzmaEncProps props; LzmaEncProps_Init(&props);
    props.level = 9;
    props.dictSize = 1 << 24;
    props.writeEndMark = 1;
    LzmaEncProps_Normalize(&props);

    unsigned char* dest = (unsigned char*)malloc(n + n / 2 + 4096);
    SizeT destLen = n + n / 2 + 4096;
    unsigned char propsEnc[LZMA_PROPERTIES_SIZE];
    SizeT propsSize = LZMA_PROPERTIES_SIZE;
    SRes r = LzmaEncode(dest, &destLen, src, (SizeT)n, &props, propsEnc, &propsSize, 1, 0, &g_Alloc, &g_Alloc);
    if (r != 0) { fprintf(stderr, "LzmaEncode hata %d\n", (int)r); return 1; }
    printf("props: %02X %02X%02X%02X%02X (lc/lp/pb byte=0x%02X dict=%u)\n",
        propsEnc[0], propsEnc[1], propsEnc[2], propsEnc[3], propsEnc[4],
        propsEnc[0], (unsigned)(propsEnc[1] | (propsEnc[2]<<8) | (propsEnc[3]<<16) | ((unsigned)propsEnc[4]<<24)));
    printf("sikistirilmis: %u bayt (oran %.3f)\n", (unsigned)destLen, (double)destLen / n);

    // ---- decode (ayni decoder) ----
    CLzmaDecoderState st;
    if (LzmaDecodeProperties(&st.Properties, propsEnc, LZMA_PROPERTIES_SIZE) != LZMA_RESULT_OK) {
        fprintf(stderr, "props hatasi\n"); return 1;
    }
    st.Probs = (CProb*)malloc(LzmaGetNumProbs(&st.Properties) * sizeof(CProb));
    SizeT sp = 0, dp = 0;
    unsigned char* outb = (unsigned char*)malloc(n + 4096);
    int rd = LzmaDecode(&st, dest, (SizeT)destLen, &sp, outb, (SizeT)n, &dp);
    printf("decode: rc=%d in=%u out=%u (beklenen %ld)\n", rd, (unsigned)sp, (unsigned)dp, n);
    if (rd == 0 && dp == (SizeT)n && memcmp(outb, src, n) == 0) { printf("BIREBIR OK\n"); return 0; }
    fprintf(stderr, "ESLESMEZ!\n"); return 1;
}
