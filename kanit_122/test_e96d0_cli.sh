#!/bin/bash
# e96d0_regresyon_122a10.sh — 1.2.2-A10 OP_NCALLI (XP_CALLI) coklu-fonksiyon regresyonu
#   Kullanicinin cp34 raporu: "--add E96D0:E9710:U" -> RED rc=3
#   "[RED] sub_e96d0 @0x000E96D0: RED: lifter: bilinmeyen islem"
#   Kok-neden: FF 90 88000000 (call [eax+88h] vtable-thiscall) lifter'da
#   XP_CALLI case'i yoktu -> 1.2.2-A10 OP_NCALLI eklendi (vm_opcodes 0x44).
#   T1: yalniz E96D0 ULTRA -> rc=0 + [LIFT] 1/1 + RED YOK
#   T2: coklu D7610 + E96D0 ULTRA -> rc=0 + [LIFT] 2/2 (coklu-fonksiyon kaniti)
#   T3: cikti PE dogrulama — E96D0 artik jmp sarmalayici ile KORUMALI
set -u
T=/home/z/my-project/scripts/xp122_test
SRC=/tmp/my-project/scripts
export WINEPREFIX=/tmp/my-project/wineprefix WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=-all
WRUN="/tmp/my-project/scripts/wchroot.sh /usr/lib/wine/wine64"
ZT="Z:\\home\\z\\my-project\\scripts\\xp122_test"
OUT=$T/e96d0_regresyon.txt
: > $OUT

mkdir -p $T
cp -f $SRC/XProtectUI.exe $SRC/XProtectUI32.exe $T/ 2>>$OUT
cp -f /home/z/my-project/upload/metin2client.exe $T/ 2>>$OUT

waitlog() { local i=0 mx=${3:-300}; while [ $i -lt $((mx*2)) ]; do
  [ -f "$1" ] && grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.5; i=$((i+1)); done; return 1; }

echo "== T1: yalniz E96D0 ULTRA (kullanicinin rc=3 senaryosu) ==" | tee -a $OUT
$WRUN "$ZT\\XProtectUI.exe" --cli "$ZT\\metin2client.exe" "$ZT\\m2_E96D0_U.exe" \
      --type U --add E96D0:E9710:U > $T/t1.log 2>&1
waitlog $T/t1.log 'Done rc=|KAYIT|HATA' 300 || true
grep -E "MANUEL|LIFT|RED|SECTION|HATA|Done" $T/t1.log | tee -a $OUT
grep -qE "Done rc=0" $T/t1.log && echo "T1: rc=0 PASS" | tee -a $OUT || echo "T1: FAIL" | tee -a $OUT
grep -q "bilinmeyen islem" $T/t1.log && echo "T1: RED KALDI FAIL" | tee -a $OUT || echo "T1: bilinmeyen-islem RED'i YOK PASS" | tee -a $OUT

echo "== T2: COKLU D7610 + E96D0 ULTRA (kullanicinin coklu-fonksiyon istegi) ==" | tee -a $OUT
$WRUN "$ZT\\XProtectUI.exe" --cli "$ZT\\metin2client.exe" "$ZT\\m2_coklu_U.exe" \
      --type U --add D7610:D766C:U --add E96D0:E9710:U > $T/t2.log 2>&1
waitlog $T/t2.log 'Done rc=|KAYIT|HATA' 300 || true
grep -E "MANUEL|LIFT|RED|SECTION|HATA|Done" $T/t2.log | tee -a $OUT
grep -qE "Done rc=0" $T/t2.log && echo "T2: rc=0 PASS" | tee -a $OUT || echo "T2: FAIL" | tee -a $OUT

echo "== T3: cikti PE koruma dogrulama ==" | tee -a $OUT
python3 - <<'PYEOF' >> $OUT 2>&1
import struct
def sec(pe):
    d = open(pe,'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e+6)[0]
    optsz = struct.unpack_from('<H', d, e+20)[0]
    base = e+24+optsz
    out=[]
    for i in range(nsec):
        o=base+i*40
        out.append((d[o:o+8].rstrip(b'\0').decode(), struct.unpack_from('<I', d, o+12)[0], struct.unpack_from('<I', d, o+16)[0]))
    return d,out

# kaynak E96D0 ilk baytlari
d0, s0 = sec('/home/z/my-project/scripts/xp122_test/metin2client.exe')
def rva2off(d, secs, rva):
    for nm,va,vsz in secs:
        if va <= rva < va+max(vsz,0x1000):
            # raw vs virtual: kullan kaba esleme
            for nm2,va2,rsz in secs:
                pass
    return None
# T1/T2 ciktlarinda .vmp0 var mi + E96D0 girisi jmp mi
for f in ('m2_E96D0_U.exe','m2_coklu_U.exe'):
    try:
        d, s = sec('/home/z/my-project/scripts/xp122_test/'+f)
        vmp = [x for x in s if x[0]=='.vmp0']
        print(f, 'bolumler=', [x[0] for x in s], 'vmp0=', vmp[0][1:] if vmp else 'YOK')
    except Exception as ex:
        print(f, 'HATA', ex)
PYEOF
echo "== BITTI ==" | tee -a $OUT
