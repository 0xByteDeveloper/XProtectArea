#!/bin/bash
# coklu_pack_122a10.sh — 1.2.2-A10 coklu-fonksiyon×Pack ölçek izolasyonu
#   S1: D7610+E96D0 ULTRA + PACK → rc=0, cikti PE: .vmp0 + LZMA pack blogu
#   S2: cikti boyut/bolum sagligi (pack+VM birlikte: boyut artisi makul)
#   S3: determinizm — ayni komutu ikinci kez koştur, rc esit
#   S4: UCANTİ — pack'siz cikti ile boyut farki raporu (izolasyon)
set -u
T=/home/z/my-project/scripts/xp122_test
export DISPLAY=:99 WINEPREFIX=/tmp/my-project/wineprefix WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=-all
WRUN="/tmp/my-project/scripts/wchroot.sh /usr/lib/wine/wine64"
ZT="Z:\\home\\z\\my-project\\scripts\\xp122_test"
OUT=$T/coklu_pack.txt
: > $OUT

waitlog() { local i=0 mx=${3:-420}; while [ $i -lt $((mx*2)) ]; do
  [ -f "$1" ] && grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.5; i=$((i+1)); done; return 1; }

echo "== S1: COKLU (D7610+E96D0) ULTRA + PACK ==" | tee -a $OUT
$WRUN "$ZT\\XProtectUI.exe" --cli "$ZT\\metin2client.exe" "$ZT\\m2_coklu_pack.exe" \
      --type U --add D7610:D766C:U --add E96D0:E9710:U --pack > $T/s1.log 2>&1
waitlog $T/s1.log 'KAYIT|HATA|Done rc=' 420 || true
grep -E "LIFT|RED \[|SECTION|PACK|KAYIT|rc=" $T/s1.log | grep -v "^\[RED\].*RED:" | tail -8 | tee -a $OUT
grep -E "\[RED\]" $T/s1.log | head -3 | tee -a $OUT
grep -qE "rc=0" $T/s1.log && echo "S1: rc=0 PASS" | tee -a $OUT || echo "S1: FAIL" | tee -a $OUT

echo "== S4: pack'SIZ karsilastirma ==" | tee -a $OUT
ls -la $T/m2_coklu_pack.exe $T/m2_coklu_U.exe 2>/dev/null >> $OUT

echo "== S2/S3: PE saglik + determinizm ==" | tee -a $OUT
$WRUN "$ZT\\XProtectUI.exe" --cli "$ZT\\metin2client.exe" "$ZT\\m2_coklu_pack2.exe" \
      --type U --add D7610:D766C:U --add E96D0:E9710:U --pack > $T/s2.log 2>&1
waitlog $T/s2.log 'KAYIT|HATA|Done rc=' 420 || true
grep -qE "rc=0" $T/s2.log && echo "S3: ikinci-koşu rc=0 PASS" | tee -a $OUT || echo "S3: FAIL" | tee -a $OUT

python3 - <<'PYEOF' >> $OUT 2>&1
import struct, hashlib
def secs(p):
    d = open(p,'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    n = struct.unpack_from('<H', d, e+6)[0]
    optsz = struct.unpack_from('<H', d, e+20)[0]
    out = []
    for i in range(n):
        o = e+24+optsz+i*40
        out.append((d[o:o+8].rstrip(b'\0').decode(), struct.unpack_from('<I', d, o+12)[0], struct.unpack_from('<I', d, o+16)[0]))
    return d, out
for f in ('m2_coklu_pack.exe', 'm2_coklu_pack2.exe'):
    d, s = secs('/home/z/my-project/scripts/xp122_test/'+f)
    print(f, 'md5=', hashlib.md5(d).hexdigest()[:12], 'boyut=', len(d), 'bolum=', [x[0] for x in s])
d1, _ = secs('/home/z/my-project/scripts/xp122_test/m2_coklu_pack.exe')
d2, _ = secs('/home/z/my-project/scripts/xp122_test/m2_coklu_pack2.exe')
print('S2: pack cikti .vmp0 var mi:', b'.vmp0' in d1 and b'.vmp0' in d2)
PYEOF
echo "== BITTI ==" | tee -a $OUT
