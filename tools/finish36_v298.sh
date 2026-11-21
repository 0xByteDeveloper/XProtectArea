#!/bin/bash
# finish36_v298.sh — V298-3: 36 eksik allver dosyasını üret + REVERSE + zip'e ekle
# Eksikler (birebir tespit edildi):
#   Lite_3.10.4: StripFixups, PackOutput, MovePlayer_{mutation,virtualization,ultra}, ALL × (32exe,32dll,64exe,64dll) = 24
#   Ultimate_3.2.0: CheckDebugger, CheckVirtualMachine, CheckKernelDebugger, CryptValues, EncryptRegs, RunnerCRC × (32exe,32dll) = 12
# Not: allver_matrix.sh "tum surumlerde tek con" kullanir (3.5.1 console) — surum yalniz klasor adidir.
set -u
WROOT=~/winepkgs/root; W=$WROOT/usr/lib/wine/wine64   # cp298: wine64 binary — wrapper değil
export WINEPREFIX=/tmp/dbg297/wp LD_LIBRARY_PATH="$WROOT/usr/lib/x86_64-linux-gnu" WINEUSERSHARE="$WROOT/usr/share/wine"
BASE=/home/z/my-project/download/vmptest
CON=/home/z/my-project/scripts/vmpcon_bin/vmprotect_con.exe
WORK=/tmp/finish36
mkdir -p "$WORK"
cd "$WORK"

# VARIANTS: isim|mask|mod  (allver_matrix.sh ile birebir)
declare -A VMASK=(
  [CheckDebugger]=1024 [CheckVirtualMachine]=2048 [CheckKernelDebugger]=131072
  [CryptValues]=8 [EncryptRegs]=128 [RunnerCRC]=64
  [StripFixups]=32768 [PackOutput]=256 [ALL]=67194016
  [MovePlayer_mutation]=0 [MovePlayer_virtualization]=0 [MovePlayer_ultra]=0
)

resolve_vas(){ # dosya -> "VA1 VA2 ..." (MovePlayer GameTick GhostStep CheckCollision WrapPos)
  python3 - "$1" <<'PYEOF'
import pefile, sys
pe = pefile.PE(sys.argv[1], fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
want = ['MovePlayer','GameTick','GhostStep','CheckCollision','WrapPos']
vas = []
for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name and e.name.decode() in want:
        vas.append((want.index(e.name.decode()), pe.OPTIONAL_HEADER.ImageBase + e.address))
vas.sort()
print(' '.join(hex(v) for _, v in vas))
PYEOF
}

protect(){ # infile outname variant mode
  local INF=$1 OUTF=$2 VN=$3 MODE=$4
  local MASK=${VMASK[$VN]}
  local CT PROCS=""
  local SRC="$WINEPREFIX/drive_c/allver/$INF"
  local USE_VA=0 VAS=""
  if [[ "$INF" == *_32* ]]; then
    USE_VA=1
    VAS=$(resolve_vas "$SRC")
    [ -z "$VAS" ] && { echo "  $VN $INF VA-cozumleme BASARISIZ"; return 1; }
  fi
  case "$MODE" in
    all)       CT=2; if [ $USE_VA = 1 ]; then for VA in $VAS; do PROCS="$PROCS\t\t\t<Procedure Address=\"$VA\" CompilationType=\"$CT\" Options=\"0\"/>\n"; done
               else for FN in MovePlayer GameTick GhostStep CheckCollision WrapPos; do PROCS="$PROCS\t\t\t<Procedure MapAddress=\"$FN\" CompilationType=\"$CT\" Options=\"0\"/>\n"; done; fi ;;
    multra_all) CT=3; if [ $USE_VA = 1 ]; then for VA in $VAS; do PROCS="$PROCS\t\t\t<Procedure Address=\"$VA\" CompilationType=\"$CT\" Options=\"0\"/>\n"; done
               else for FN in MovePlayer GameTick GhostStep CheckCollision WrapPos; do PROCS="$PROCS\t\t\t<Procedure MapAddress=\"$FN\" CompilationType=\"$CT\" Options=\"0\"/>\n"; done; fi ;;
    mmut|mvirt|multra) CT=$( [ "$MODE" = mmut ] && echo 1 || { [ "$MODE" = mvirt ] && echo 2 || echo 3; } )
               if [ $USE_VA = 1 ]; then MP_VA=$(echo "$VAS" | tr ' ' '\n' | head -1); PROCS="\t\t\t<Procedure Address=\"$MP_VA\" CompilationType=\"$CT\" Options=\"0\"/>\n"
               else PROCS="\t\t\t<Procedure MapAddress=\"MovePlayer\" CompilationType=\"$CT\" Options=\"0\"/>\n"; fi ;;
  esac
  cat > "/tmp/finish36/proj.vmp" <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<Document Version="2">
	<Protection InputFileName="C:\\allver\\$INF" Options="$MASK" VMCodeSectionName=".vmp0">
		<Procedures>
$(printf "$PROCS")
		</Procedures>
	</Protection>
</Document>
EOF2
  mkdir -p "$WINEPREFIX/drive_c/allver/out"
  rm -f "$WINEPREFIX/drive_c/allver/out/$INF"
  # cp298: con Z: sürücü yolundan çağrılır (wineprefix dosdevices z: -> /)
  "$W" "Z:\\home\\z\\my-project\\scripts\\vmpcon_bin\\vmprotect_con.exe" "C:\\allver\\$INF" "C:\\allver\\out\\$INF" -pf "Z:\\tmp\\finish36\\proj.vmp" >/dev/null 2>&1
  [ -f "$WINEPREFIX/drive_c/allver/out/$INF" ] && [ "$(stat -c%s "$WINEPREFIX/drive_c/allver/out/$INF")" -gt 4096 ]
}

# --- hedefleri wine C:\allver'e kopyala ---
mkdir -p "$WINEPREFIX/drive_c/allver"
cp /tmp/my-project/download/vmptest/Test_32.exe /tmp/my-project/download/vmptest/Test_64.exe \
   /tmp/my-project/download/vmptest/Test_32.dll /tmp/my-project/download/vmptest/Test_64.dll \
   "$WINEPREFIX/drive_c/allver/"

# --- üretim listesi: sürüm|variant|mod|hedefler ---
MISSING_LITE="StripFixups|all PackOutput|all MovePlayer_mutation|mmut MovePlayer_virtualization|mvirt MovePlayer_ultra|multra ALL|multra_all"
MISSING_ULT="CheckDebugger|all CheckVirtualMachine|all CheckKernelDebugger|all CryptValues|all EncryptRegs|all RunnerCRC|all"

n_ok=0; n_fail=0
for spec in $MISSING_LITE; do
  VN="${spec%%|*}"; MODE="${spec#*|}"
  for F in Test_32.exe Test_64.exe Test_32.dll Test_64.dll; do
    OUT="Lite_3.10.4/${F%.*}_vmp_$VN.${F##*.}"
    [ -f "$WORK/$OUT" ] && { echo "SKIP $OUT"; continue; }
    mkdir -p "$(dirname "$OUT")"
    if protect "$F" "$OUT" "$VN" "$MODE"; then
      cp "$WINEPREFIX/drive_c/allver/out/$F" "$OUT" && n_ok=$((n_ok+1)) && echo "OK  $OUT"
    else
      n_fail=$((n_fail+1)); echo "FAIL $OUT"
    fi
  done
done
for spec in $MISSING_ULT; do
  VN="${spec%%|*}"; MODE="${spec#*|}"
  for F in Test_32.exe Test_32.dll; do
    OUT="Ultimate_3.2.0/${F%.*}_vmp_$VN.${F##*.}"
    [ -f "$WORK/$OUT" ] && { echo "SKIP $OUT"; continue; }
    mkdir -p "$(dirname "$OUT")"
    if protect "$F" "$OUT" "$VN" "$MODE"; then
      cp "$WINEPREFIX/drive_c/allver/out/$F" "$OUT" && n_ok=$((n_ok+1)) && echo "OK  $OUT"
    else
      n_fail=$((n_fail+1)); echo "FAIL $OUT"
    fi
  done
done
echo "URETIM: ok=$n_ok fail=$n_fail"
echo "BITTI — REVERSE adimi icin: mvpreverse3.py reverse ile $WORK/<Surum>/ dosyalari"
