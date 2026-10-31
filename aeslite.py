#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# © 2026 M87 · 自有手写资产，未经授权禁止复制、转售或二次分发
"""纯手写 AES 解密（只用标准库），用于破解免费主机那类 JS Cookie 门禁。

支持 128/192/256 位密钥、ECB 单块解密与 CBC 整段解密，无任何第三方依赖。
"""


def _mul(a, b):
    """GF(2^8) 乘法。"""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x1B) if a & 0x80 else (a << 1)
        a &= 0xFF
        b >>= 1
    return r


def _inverse(x):
    if x == 0:
        return 0
    for y in range(1, 256):
        if _mul(x, y) == 1:
            return y
    return 0


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_tables():
    sbox = [0] * 256
    for i in range(256):
        v = _inverse(i)
        sbox[i] = v ^ _rotl8(v, 1) ^ _rotl8(v, 2) ^ _rotl8(v, 3) ^ _rotl8(v, 4) ^ 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_tables()

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


class AES:
    """只实现解密方向，够用即可。"""

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError('密钥长度必须是 16/24/32 字节')
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.round_keys = self._expand(key)

    def _expand(self, key):
        w = [list(key[4 * i:4 * i + 4]) for i in range(self.nk)]
        total = 4 * (self.nr + 1)
        for i in range(self.nk, total):
            temp = list(w[i - 1])
            if i % self.nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // self.nk - 1]
            elif self.nk > 6 and i % self.nk == 4:
                temp = [_SBOX[b] for b in temp]
            w.append([w[i - self.nk][j] ^ temp[j] for j in range(4)])
        return w

    def _add_key(self, s, rnd):
        k = self.round_keys
        for c in range(4):
            word = k[rnd * 4 + c]
            for r in range(4):
                s[4 * c + r] ^= word[r]

    @staticmethod
    def _inv_shift(s):
        for r in range(1, 4):
            row = [s[4 * c + r] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                s[4 * c + r] = row[c]

    @staticmethod
    def _inv_mix(s):
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
            s[i + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
            s[i + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
            s[i + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)

    def decrypt_block(self, block):
        s = list(block)
        self._add_key(s, self.nr)
        for rnd in range(self.nr - 1, 0, -1):
            self._inv_shift(s)
            for i in range(16):
                s[i] = _INV_SBOX[s[i]]
            self._add_key(s, rnd)
            self._inv_mix(s)
        self._inv_shift(s)
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]
        self._add_key(s, 0)
        return bytes(s)


def ecb_decrypt(data, key):
    cipher = AES(key)
    return b''.join(cipher.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def cbc_decrypt(data, key, iv, unpad=True):
    if len(data) % 16:
        raise ValueError('密文长度不是 16 的整数倍')
    cipher = AES(key)
    prev = bytes(iv)
    out = []
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        plain = bytes(a ^ b for a, b in zip(cipher.decrypt_block(block), prev))
        out.append(plain)
        prev = block
    raw = b''.join(out)
    if unpad and raw:
        pad = raw[-1]
        if 0 < pad <= 16 and raw[-pad:] == bytes([pad]) * pad:
            raw = raw[:-pad]
    return raw
