#!/bin/bash
# restore_xrt_prod.sh — uretim xrt blob'unu geri koyar (trace test sonrasi)
cd "$(dirname "$0")"
if [ -f xrt_blob.cpp.prod ]; then cp xrt_blob.cpp.prod xrt_blob.cpp; rm xrt_blob.cpp.prod; fi
echo "uretim blob geri yuklendi"
