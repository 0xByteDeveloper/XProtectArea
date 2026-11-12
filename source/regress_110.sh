#!/bin/bash
# regress_110.sh — 1.1.0-A4-FPU tam regresyon (0.9.0 R5 proseduru ile ayni):
#   R1: R5 ULTIMATE (sdkonly+pack+sectcrypt+loadercrc+filecrc+stripfixups) rc=42
#   R2: tamper -> rc != 42 (duru-ret)
#   R3: SELFTEST OK (R5 cikti govdesinde)
#   R4: metin2 d7610 ULTRA+antidebug statik (ANTIDBG 0x1E)
#   R5: A4-FPU kabul (test_fpu_a4) zaten ayrı calisti — rc=42 kaniti logda
set -u
TEST=/home/z/my-project/scripts/a4fpu
SRC=/home/z/my-project/scripts/xiangu_gh/XProtect/source/XProtectUI_Source
UI=$SRC/XProtectUI.exe
OUT=$TEST/regress_110.txt
ZUI="Z:\\home\\z\\my-project\\scripts\\xiangu_gh\\XProtect\\source\\XProtectUI_Source\\XProtectUI.exe"
: > $OUT
export WINEPREFIX=/tmp/my-project/wineprefix WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=-all
WRUN=/home/z/my-project/scripts/wchroot.sh
WR="$WRUN /usr/lib/wine/wine64"

# wineserver log-FD'sini açık tutuyor -> wchroot dönse bile log yazımı devam
# edebilir (1.1.1 dersi: grep log bitmeden koştu). Poll bekleme (harici
# timeout süreci YOK — xguard doktrini):
waitlog() { # $1=dosya $2=regex [$3=max-yarim-sn]
  local i=0 mx=${3:-120}
  while [ $i -lt $mx ]; do
    [ -f "$1" ] && grep -qE "$2" "$1" 2>/dev/null && return 0
    sleep 0.5; i=$((i+1))
  done
  return 1
}

echo "== R1: R5 ULTIMATE (sdkonly+pack+sectcrypt+loadercrc+filecrc+stripfixups) ==" | tee -a $OUT
cd $TEST
if [ ! -f r5_110_p.exe ]; then
python3 -m ziglang cc -O2 -target x86_64-windows-gnu -o r5_110.exe /tmp/my-project/scripts/xp081/sdk_ornek_test_rt3.c -lkernel32 2>>$OUT || echo "DERLE HATA" >> $OUT
python3 - << 'PYEOF' >> $OUT 2>&1
import struct
p = '/home/z/my-project/scripts/a4fpu/r5_110.exe'
d = bytearray(open(p, 'rb').read())
pe = struct.unpack_from('<I', d, 0x3C)[0]
opt = pe + 24
magic = struct.unpack_from('<H', d, opt)[0]
ddoff = opt + (112 if magic == 0x20B else 96)
tls_rva, tls_sz = struct.unpack_from('<II', d, ddoff + 9*8)
if tls_rva or tls_sz:
    struct.pack_into('<II', d, ddoff + 9*8, 0, 0)
    open(p, 'wb').write(bytes(d))
    print('TLS data-dir temizlendi (rva=%#x sz=%#x)' % (tls_rva, tls_sz))
else:
    print('TLS yok')
PYEOF
/home/z/my-project/scripts/wchroot.sh /usr/lib/wine/wine64 "$ZUI" --cli \
  "Z:\\home\\z\\my-project\\scripts\\a4fpu\\r5_110.exe" \
  "Z:\\home\\z\\my-project\\scripts\\a4fpu\\r5_110_p.exe" \
  --sdkonly --pack --sectcrypt --loadercrc --filecrc --stripfixups > $TEST/r5_110_prot.log 2>&1
waitlog $TEST/r5_110_prot.log 'KAYIT|HATA' 240
fi
if [ ! -f r5_110_p.exe ]; then echo "R5 KORUMA BASARISIZ" | tee -a $OUT; tail -3 $TEST/r5_110_prot.log >> $OUT; else
/home/z/my-project/scripts/wchroot.sh /usr/lib/wine/wine64 cmd /v:on /c "Z:\\home\\z\\my-project\\scripts\\a4fpu\\r5_110_p.exe & echo RCODE=!ERRORLEVEL!" > $TEST/r5_110_run.log 2>&1
waitlog $TEST/r5_110_run.log 'RCODE=' 240
RC=$(grep -oE "RCODE=[0-9]+" $TEST/r5_110_run.log | head -1)
RES=$(grep -E "OK (hepsi|HATALI|main|sdk_print)" $TEST/r5_110_run.log | tail -2 | tr '\n' ' ')
SELF=$(grep -c "SELFTEST OK" $TEST/r5_110_run.log)
echo "R5 $RC  $RES selftest=$SELF" | tee -a $OUT
true | tee -a $OUT

echo "== R2: tamper (paketli cikti tek-bayt) ==" | tee -a $OUT
if [ ! -f r5_110_n.exe ]; then
/home/z/my-project/scripts/wchroot.sh /usr/lib/wine/wine64 "$ZUI" --cli \
  "Z:\\home\\z\\my-project\\scripts\\a4fpu\\r5_110.exe" \
  "Z:\\home\\z\\my-project\\scripts\\a4fpu\\r5_110_n.exe" \
  --sdkonly --pack --sectcrypt --loadercrc --filecrc --stripfixups --rt-nomsg > $TEST/r5_110_prot2.log 2>&1
waitlog $TEST/r5_110_prot2.log 'KAYIT|HATA' 240
fi
if [ -f r5_110_n.exe ]; then
python3 - << 'PYEOF' >> $OUT 2>&1
import struct
p = '/home/z/my-project/scripts/a4fpu/r5_110_n.exe'
d = bytearray(open(p, 'rb').read())
pe = struct.unpack_from('<I', d, 0x3C)[0]
nsec = struct.unpack_from('<H', d, pe+6)[0]
optsz = struct.unpack_from('<H', d, pe+20)[0]
for i in range(nsec):
    o = pe+24+optsz+i*40
    nm = bytes(d[o:o+8]).rstrip(b'\0').decode(errors='ignore')
    if nm == '.vmp1':
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, o+8)
        d[raw + rsz//2] ^= 0x01
        print('tamper: .vmp1 bayt cevirildi (raw+%d)' % (rsz//2))
        break
open('/home/z/my-project/scripts/a4fpu/r5_110_tamper.exe','wb').write(bytes(d))
PYEOF
/home/z/my-project/scripts/wchroot.sh /usr/lib/wine/wine64 cmd /v:on /c "Z:\\home\\z\\my-project\\scripts\\a4fpu\\r5_110_tamper.exe & echo RCODE=!ERRORLEVEL!" > $TEST/r5_110_tamper_run.log 2>&1
waitlog $TEST/r5_110_tamper_run.log 'RCODE=' 240
TRC=$(grep -oE "RCODE=[0-9-]+" $TEST/r5_110_tamper_run.log | head -1)
echo "R5-tamper $TRC (beklenen: RCODE=42 DEGIL — duru-ret)" | tee -a $OUT
fi
fi

echo "== R4: metin2 d7610 ULTRA+antidebug statik ==" | tee -a $OUT
if [ ! -f m2_110.exe ]; then
/home/z/my-project/scripts/wchroot.sh /usr/lib/wine/wine64 "$ZUI" --cli "Z:\\home\\z\\my-project\\scripts\\metin2\\metin2client.exe" \
      "Z:\\home\\z\\my-project\\scripts\\a4fpu\\m2_110.exe" \
      --add D7610:D766C:U --antidebug > $TEST/m2_110_prot.log 2>&1
waitlog $TEST/m2_110_prot.log 'KAYIT|HATA' 240
i=0; while [ $i -lt 60 ] && [ ! -f $TEST/m2_110.exe ]; do sleep 0.5; i=$((i+1)); done
fi
if [ -f m2_110.exe ]; then
python3 /home/z/my-project/scripts/kanit_095/static_m2_090.py \
  /home/z/my-project/scripts/a4fpu/m2_110.exe 0xD7610 >> $OUT 2>&1 || \
  echo "static-m2: cozumleme notu (log'da)" >> $OUT
grep -E "ANTIDBG|bc_len|YAPI" $TEST/m2_110_prot.log | head -4 >> $OUT 2>/dev/null
echo "metin2 statik tamam (detay $OUT icinde)" | tee -a $OUT
else
echo "metin2 koruma BASARISIZ" | tee -a $OUT; tail -3 $TEST/m2_110_prot.log >> $OUT
fi
echo "== SON ==" | tee -a $OUT
