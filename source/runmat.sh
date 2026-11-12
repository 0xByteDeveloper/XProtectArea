#!/bin/bash
# runmat.sh — guvenilir wine test kosucu (exit kodu: cmd /v:on !ERRORLEVEL%)
export WINEPREFIX=/tmp/my-project/wineprefix WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=-all
EXE="$1"
/tmp/my-project/scripts/wchroot.sh /usr/lib/wine/wine64 cmd /v:on /c "Z:\\home\\z\\my-project\\scripts\\xp070\\$(basename $EXE) & echo RCODE=!ERRORLEVEL!" 2>&1
