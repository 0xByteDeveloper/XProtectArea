#!/bin/bash
# pkg_070.sh — XProtect_0.7.0 (FINAL) paketleme
set -e
SRC=/home/z/my-project/scripts/xp070
OUT=/tmp/pkg070/XProtect_0.7.0
rm -rf /tmp/pkg070 && mkdir -p $OUT/kanit $OUT/source/XProtectUI_Source

cp $SRC/XProtectUI.exe  $OUT/XProtectUI.exe
cp $SRC/XProtectUI32.exe $OUT/XProtectUI32.exe
cp $SRC/xprotect_sdk.h  $OUT/xprotect_sdk.h
cp $SRC/xprotect_sdk.c  $OUT/source/XProtectUI_Source/ 2>/dev/null || true
cp $SRC/CHANGELOG_0.7.0.md $OUT/
cp $SRC/README_0.7.0.txt   $OUT/

# kanit
cp -r $SRC/kanit/. $OUT/kanit/

# kaynak
for f in xprotect_ui.cpp engine_main.cpp engine_pe.cpp engine_disasm.cpp engine_mut.cpp \
         engine_lift.cpp engine_stub.cpp engine_util.cpp engine_sym.cpp engine_sym.hpp engine.hpp \
         engine_pack.cpp vm_core.c vm_opcodes.h vm_blob.cpp xrt_core.c xrt_license.c xrt_blob.cpp \
         build_ui.sh build_xrt.sh gen_blob.py gen_xrt_blob.py xprotect_keygen.py \
         test_lic_full.c test_sdk40.c sdk_ornek_test_rt.c hwidprint.c runmat.sh; do
  cp $SRC/$f $OUT/source/XProtectUI_Source/ 2>/dev/null || true
done
cp -r $SRC/lzma $OUT/source/XProtectUI_Source/lzma 2>/dev/null || true

# worklog kopyasi (PAT'siz) — repo kopyasinda maskeleme uyarisi
grep -v "github_pat_" /home/z/my-project/worklog.md > $OUT/worklog.md 2>/dev/null || true

cd /tmp/pkg070 && zip -qr /home/z/my-project/download/XProtect/XProtect_0.7.0.zip XProtect_0.7.0
md5sum /home/z/my-project/download/XProtect/XProtect_0.7.0.zip
unzip -l /home/z/my-project/download/XProtect/XProtect_0.7.0.zip | tail -2
