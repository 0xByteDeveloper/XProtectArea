#!/usr/bin/env python3
# xprotect_keygen.py — XProtect 0.7.0 serial üretici
# VMProtect keygen (PHP/manager) muadili: RSA-2048 "private-encrypt" +
# 00 02 NN..NN 00 bloklar + SHA-1 checksum + base64.
# Kullanim:
#   keygen.py --key key.pem --prodcode 0102030405060708 --hwid <b64>
#             [--name "Ad"] [--email a@b.c] [--exp 2027-01-01]
#             [--maxbuild 2027-01-01] [--runtime 60] [--data HEX]
#             [--badhwid | --badsum | --expire 2020-01-01]   # negatif testler
import sys, struct, hashlib, base64, argparse, subprocess, os

def der_parse_privkey(der):
    # PKCS#8 (BEGIN PRIVATE KEY) veya PKCS#1 (BEGIN RSA PRIVATE KEY) ikisi de
    def rdlen(b, i):
        l = b[i]; i += 1
        if l & 0x80:
            n = l & 0x7F; l = int.from_bytes(b[i:i+n], 'big'); i += n
        return l, i
    def rdint(b, i):
        assert b[i] == 0x02, 'INTEGER beklenir'
        i += 1
        l, i = rdlen(b, i)
        return b[i:i+l], i + l
    def rdseq(b, i):
        assert b[i] == 0x30, 'SEQ beklenir'
        i += 1
        l, i = rdlen(b, i)
        return i, i + l
    assert der[0] == 0x30
    _, end = rdlen(der, 1)
    i = 1
    if der[i] == 0x02:
        # PKCS#1: ver,n,e,d,...
        ver, i = rdint(der, i)
        n, i = rdint(der, i)
        e, i = rdint(der, i)
        d, i = rdint(der, i)
    else:
        # PKCS#8: ver, algSEQ, OCTET( PKCS#1 )
        ver, i = rdint(der, i)
        _, i = rdseq(der, i)
        assert der[i] == 0x04
        i += 1
        l, i = rdlen(der, i)
        inner = der[i:i+l]
        j, i2 = rdseq(inner, 0)
        ver, j = rdint(inner, j)
        n, j = rdint(inner, j)
        e, j = rdint(inner, j)
        d, j = rdint(inner, j)
    return int.from_bytes(n, 'big'), int.from_bytes(e, 'big'), int.from_bytes(d, 'big')

def load_key(pem):
    # openssl -text ciktisindan n/e/d hex bloklarini al (ASN.1 parser'siz)
    txt = subprocess.run(['openssl', 'rsa', '-in', pem, '-text', '-noout'],
                         capture_output=True, check=True).stdout.decode('latin1')
    def field(name, nxt):
        i = txt.index(name)
        j = txt.index(nxt, i)
        body = txt[i + len(name):j]
        hx = ''
        for l in body.splitlines():
            t = l.strip().replace(':', '')
            if t and all(c in '0123456789abcdefABCDEF' for c in t):
                hx += t
        return int(hx, 16) if hx else 0
    n = field('modulus:', 'publicExponent:')
    e = field('publicExponent:', 'privateExponent:')
    d = field('privateExponent:', 'prime1:')
    return n, e, d

def date_enc(s):
    y, m, d = (int(x) for x in s.split('-'))
    return struct.pack('<I', (y << 16) | (m << 8) | d)

def build_blocks(a):
    b = b'\x01\x01'                                   # version 1
    if a.name:
        nb = a.name.encode('utf-8')
        b += b'\x02' + bytes([len(nb)]) + nb
    if a.email:
        eb = a.email.encode('utf-8')
        b += b'\x03' + bytes([len(eb)]) + eb
    if a.hwid:
        hb = base64.b64decode(a.hwid)
        assert len(hb) % 4 == 0 and len(hb) <= 32, 'HWID 4B kati, <=32B'
        if a.badhwid:
            hb = bytes(x ^ 0xFF for x in hb)
        b += b'\x04' + bytes([len(hb)]) + hb
    exp = a.expire if a.expire else a.exp
    if exp:
        b += b'\x05' + date_enc(exp)
    if a.runtime:
        b += b'\x06' + bytes([a.runtime & 0xFF])
    b += b'\x07' + bytes.fromhex(a.prodcode)          # product code (zorunlu)
    if a.data:
        db = bytes.fromhex(a.data)
        b += b'\x08' + bytes([len(db)]) + db
    if a.maxbuild:
        b += b'\x09' + date_enc(a.maxbuild)
    h = hashlib.sha1(b).digest()
    b += b'\xFF' + h[3::-1] if not a.badsum else b'\xFF' + bytes([h[3] ^ 0xFF, h[2], h[1], h[0]])
    return b

def sign(blocks, n, d):
    # 00 02 NN..NN(8-16 nonzero rastgele) 00 <blocks> <MM dolgu> = 256B
    import random
    nn = random.randint(8, 16)
    pad = bytes(random.choice([x for x in range(1, 256)]) for _ in range(nn))
    body = b'\x00\x02' + pad + b'\x00' + blocks
    body += bytes(random.randint(0, 255) for _ in range(256 - len(body)))
    assert len(body) == 256
    m = int.from_bytes(body, 'big')
    s = pow(m, d, n)
    return s.to_bytes(256, 'big')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', default='key.pem')
    ap.add_argument('--prodcode', required=True)
    ap.add_argument('--hwid', default='')
    ap.add_argument('--name', default='')
    ap.add_argument('--email', default='')
    ap.add_argument('--exp', default='')
    ap.add_argument('--expire', default='')       # negatif: gecmis tarih
    ap.add_argument('--maxbuild', default='')
    ap.add_argument('--runtime', type=int, default=0)
    ap.add_argument('--data', default='')
    ap.add_argument('--badhwid', action='store_true')
    ap.add_argument('--badsum', action='store_true')
    ap.add_argument('--pubkey', action='store_true')  # sadece modulus bas
    a = ap.parse_args()
    n, e, d = load_key(a.key)
    if a.pubkey:
        print('%0512X' % n)
        return
    blocks = build_blocks(a)
    sig = sign(blocks, n, d)
    print(base64.b64encode(sig).decode())

if __name__ == '__main__':
    main()
