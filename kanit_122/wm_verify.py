#!/usr/bin/env python3
# wm_verify.py — UO core.cc Watermark::SearchByte 1:1 port (test tarafı)
# Kullanım: wm_verify.py <dosya> <hexvalue> [<hexvalue>...]
# Çıkış: her değer için bulunan kopya sayısı (maske durum makinesi ile)
import sys

def wm_compile(value: str):
    """UO Watermark::Compile 1:1 -> (dump, mask). Hex olmayan karakter = joker (mask 0)."""
    dump, mask = [], []
    for i, ch in enumerate(value):
        p = i // 2
        if p >= len(dump):
            dump.append(0); mask.append(0)
        m = 0xFF; b = None
        if '0' <= ch <= '9': b = ord(ch) - ord('0')
        elif 'A' <= ch <= 'F': b = ord(ch) - ord('A') + 0x0A
        elif 'a' <= ch <= 'f': b = ord(ch) - ord('a') + 0x0A
        else: m = 0
        if i % 2 == 0:
            dump[p] = (dump[p] & 0x0F) | ((b or 0) << 4)
            mask[p] = (mask[p] & 0x0F) | (m << 4)
        else:
            dump[p] = (dump[p] & 0xF0) | ((b or 0) & 0x0F)
            mask[p] = (mask[p] & 0xF0) | (m & 0x0F)
    return bytes(dump), bytes(mask)

class WM:  # UO SearchByte durum makinesi 1:1
    def __init__(self, value):
        self.dump, self.mask = wm_compile(value)
        self.pos = []
    def search_byte(self, v):
        if not self.dump: return False
        res = False
        for i in range(len(self.pos) - 1, -2, -1):
            p = 0 if i == -1 else self.pos[i]
            if (self.dump[p] & self.mask[p]) == (v & self.mask[p]):
                p += 1
                if p == len(self.dump):
                    res = True
                    if i > -1: self.pos.pop(i)
                elif i == -1:
                    self.pos.append(p)
                else:
                    self.pos[i] = p
            elif i > -1:
                self.pos.pop(i)
        return res

def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    print(f"dosya: {path} ({len(data)} bayt)")
    ok_all = True
    for val in sys.argv[2:]:
        w = WM(val)
        cnt = 0
        for by in data:
            if w.search_byte(by): cnt += 1
        # ic surum imzasi ozel isim
        name = val
        if val == "5850726F74656374312E322E32": name = "XProtect1.2.2 (ic surum)"
        print(f"  watermark {name}: {cnt} kopya bulundu")
        if cnt == 0: ok_all = False
    sys.exit(0 if ok_all else 1)

if __name__ == "__main__":
    main()
