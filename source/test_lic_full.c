// ============================================================
// test_lic_full.c — 0.7.0-final lisans tam test
// 1) gecerli serial  -> SetSerial=0, State=0, Data: name/email dolu
// 2) badsum serial   -> SetSerial=2 (INVALID)
// 3) badhwid serial  -> State=0x20 (BAD_HWID)
// 4) expire serial   -> State=0x08 (DATE_EXPIRED)
// derleme: x86_64-w64-mingw32-gcc -O2 test_lic_full.c xprotect_sdk.c
// serialler: keygen ciktisi (build.sh gomer)
// ============================================================
#include <stdio.h>
#include <string.h>
#include "xprotect_sdk.h"

#ifndef S_OK
#define S_OK   "YOK"
#endif
#ifndef S_BADSUM
#define S_BADSUM "YOK"
#endif
#ifndef S_BADHWID
#define S_BADHWID "YOK"
#endif
#ifndef S_EXPIRE
#define S_EXPIRE "YOK"
#endif

static void wprint(const char* tag, const wchar_t* w) {
    printf("%s=\"", tag);
    for (int i = 0; w[i] && i < 256; i++) printf("%c", (char)w[i]);
    printf("\"\n");
}

int main(void) {
    /* 1) gecerli serial */
    int r = XProtectSetSerialNumber(S_OK);
    int st = XProtectGetSerialNumberState();
    printf("ok: SetSerial=%d State=%d\n", r, st);
    {
        XProtectSerialNumberData d; memset(&d, 0, sizeof d);
        int g = XProtectGetSerialNumberData(&d, (int)sizeof d);
        printf("ok: GetData=%d nState=%d\n", g, d.nState);
        wprint("ok: name", d.wUserName);
        wprint("ok: email", d.wEMail);
        printf("ok: expire=%u-%u-%u maxbuild=%u-%u-%u rt=%d ud=[%02x %02x %02x %02x %02x %02x]\n",
               d.dtExpire.wYear, d.dtExpire.bMonth, d.dtExpire.bDay,
               d.dtMaxBuild.wYear, d.dtMaxBuild.bMonth, d.dtMaxBuild.bDay,
               d.bRunningTime, d.bUserData[0], d.bUserData[1], d.bUserData[2],
               d.bUserData[3], d.bUserData[4], d.bUserData[5]);
    }
    /* 2) badsum */
    {
        int r2 = XProtectSetSerialNumber(S_BADSUM);
        printf("badsum: SetSerial=%d State=%d\n", r2, XProtectGetSerialNumberState());
    }
    /* 3) badhwid */
    {
        int r3 = XProtectSetSerialNumber(S_BADHWID);
        printf("badhwid: SetSerial=%d State=%d\n", r3, XProtectGetSerialNumberState());
    }
    /* 4) expire */
    {
        int r4 = XProtectSetSerialNumber(S_EXPIRE);
        printf("expire: SetSerial=%d State=%d\n", r4, XProtectGetSerialNumberState());
    }
    /* 5) tekrar gecerli -> state toparlanmali */
    {
        int r5 = XProtectSetSerialNumber(S_OK);
        printf("reok: SetSerial=%d State=%d\n", r5, XProtectGetSerialNumberState());
    }
    return 42;
}
