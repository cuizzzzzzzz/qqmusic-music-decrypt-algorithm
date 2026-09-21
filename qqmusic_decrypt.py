#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ 音乐 QMC 加密文件解密引擎 — 纯 Python 实现（逆向自 libekey_decrypt.so / ARM64）

======================= 免责声明 =======================
本文件仅用于**安全研究与文件格式学习**。它实现的是从 Android 客户端动态库中
逆向得到的解密流程（TEA / RC4 变体密钥流）。
请勿用于破解付费内容、绕过版权保护或商业用途；后果自负。
=======================================================

算法概要
--------
1. derive_key(ekey):
     base64 解码 ekey → 前 8 字节作为种子
     用 SimpleMakeKey(seed=106, len=8) 生成 8 字节，与 ekey 原始字节交错合并成 16 字节 TEA 密钥
     余下字节用 oi_symmetry_decrypt2（QQ 版 TEA-ECB）解密，拼到密钥流后面
2. rc4_ksa(key_stream): 标准 RC4 KSA + 计算 hash_base（连乘上限）
3. 逐块解密:
     key_length <= 300 : 用 mapLE 生成的密钥流做异或
     key_length >  300 : 分段 RC4 变体（前 128 字节一段，之后每 5120 字节一段，
                         每段按 (pos+1)*key_byte 推导丢弃字节数）
4. 文件尾部若有 "STag" footer（8 字节：4B 元数据长度 + STag），解密时跳过

用法:
    python3 qqmusic_decrypt.py selftest                     # 自检
    python3 qqmusic_decrypt.py key <ekey>                   # 推导密钥流，打印长度
    python3 qqmusic_decrypt.py decrypt <输入> <输出> <ekey>  # 解密整个文件
"""

from __future__ import annotations

import base64
import math
import struct
import sys
from pathlib import Path

# ============================================================
# 1. SimpleMakeKey
# ============================================================

def simple_make_key(seed: int, length: int) -> bytearray:
    """由种子生成 length 字节密钥：byte = int(abs(tan(seed + i*0.1)) * 100) & 0xFF"""
    out = bytearray(length)
    for i in range(length):
        out[i] = int(abs(math.tan(seed + i * 0.1)) * 100.0) & 0xFF
    return out


# ============================================================
# 2. TEA 解密
# ============================================================

DELTA = 0x9E3779B9
TEA_ROUNDS = 16


def tea_decrypt_block(v0: int, v1: int, key: list[int]) -> tuple[int, int]:
    """解密单个 TEA 块（64-bit，大端）。key = [k0,k1,k2,k3]。"""
    n = TEA_ROUNDS
    s = (DELTA * n) & 0xFFFFFFFF
    for _ in range(n):
        v1 = (v1 - ((((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3])))) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1])))) & 0xFFFFFFFF
        s = (s - DELTA) & 0xFFFFFFFF
    return v0, v1


def bytes_to_u32be(data: bytes) -> list[int]:
    return [struct.unpack(">I", data[i:i + 4])[0] for i in range(0, len(data), 4)]


# ============================================================
# 3. oi_symmetry_decrypt2（QQ 版 TEA-ECB，带块间异或链）
# ============================================================

def oi_symmetry_decrypt2(ciphertext: bytes, tea_key: bytes) -> bytes:
    N = len(ciphertext)
    if N & 7 != 0 or N <= 15:
        raise ValueError(f"oi_symmetry_decrypt2: 输入长度 {N} 非法（需 >15 且为 8 的倍数）")

    k = bytes_to_u32be(tea_key)

    v0, v1 = struct.unpack(">II", ciphertext[0:8])
    d0, d1 = tea_decrypt_block(v0, v1, k)
    scratch = bytearray(struct.pack(">II", d0, d1))

    pad_flag = scratch[0] & 7
    out_len = N - 10 - pad_flag
    if out_len < 0:
        return b""

    zero_buf = b"\x00" * 8
    ptr_A = zero_buf
    ptr_B = ciphertext[0:8]
    next_off, consumed = 8, 8
    result = bytearray(out_len)
    out_idx = 0
    pos = 1 + pad_flag
    phase = 1

    def _next_block():
        """推进一个 8 字节块：scratch ^= 新密文块 → TEA 解密。"""
        nonlocal ptr_A, ptr_B, next_off, consumed, scratch
        ptr_A = ptr_B
        block = ciphertext[next_off:next_off + 8]
        ptr_B = block
        for j in range(8):
            scratch[j] ^= block[j]
        a, b = struct.unpack(">II", bytes(scratch))
        da, db = tea_decrypt_block(a, b, k)
        scratch = bytearray(struct.pack(">II", da, db))
        next_off += 8
        consumed += 8

    # 跳过前导填充（两阶段推进，与原实现一致）
    while phase <= 2:
        if pos <= 7:
            pos += 1
            phase += 1
        elif pos == 8:
            _next_block()
            pos = 0
        else:
            break

    while out_idx < out_len:
        if pos <= 7:
            result[out_idx] = scratch[pos] ^ ptr_A[pos]
            out_idx += 1
            pos += 1
        elif pos == 8:
            _next_block()
            pos = 0
        else:
            break

    return bytes(result)


# ============================================================
# 4. 密钥推导
# ============================================================

def derive_key(ekey: str) -> tuple[bytes, int]:
    """
    ekey → (key_stream, key_length)

    ekey 是 base64；前 8 字节为种子，其余用于生成密钥流。
    """
    pad = (4 - len(ekey) % 4) % 4
    if pad:
        ekey += "=" * pad
    raw = base64.b64decode(ekey)
    N = len(raw)

    simple_key = simple_make_key(106, 8)
    merged_key = bytearray(16)
    for i in range(16):
        merged_key[i] = simple_key[i // 2] if i % 2 == 0 else raw[i // 2]

    key_stream = bytearray(raw[:8])
    if N > 8:
        key_stream.extend(oi_symmetry_decrypt2(raw[8:], bytes(merged_key)))

    return bytes(key_stream), len(key_stream)


# ============================================================
# 5. RC4 KSA + hash_base
# ============================================================

def rc4_ksa(key_stream: bytes, key_length: int) -> tuple[bytearray, int]:
    S = bytearray(key_length)
    for i in range(key_length):
        S[i] = i & 0xFF

    j = 0
    for i in range(key_length):
        j = (j + S[i] + key_stream[i % key_length]) % key_length
        S[i], S[j] = S[j], S[i]

    hash_base = 1
    for i in range(key_length):
        val = key_stream[i]
        if val == 0:
            continue
        product = (hash_base * val) & 0xFFFFFFFF
        if product == 0 or product <= hash_base:
            break
        hash_base = product

    return S, hash_base


# ============================================================
# 6. mapLE（短密钥流模式）
# ============================================================

def map_le(key_stream: bytes, key_length: int, offset: int) -> int:
    off = offset if offset <= 0x7FFF else offset % 32767
    temp = (off * off) + 0x1162E
    idx = temp % key_length
    byte_val = key_stream[idx]
    shift = idx & 7
    shift = shift - 4 if shift > 3 else shift + 4
    return ((byte_val << shift) | (byte_val >> shift)) & 0xFF


# ============================================================
# 7-9. RC4 变体分段（长密钥流模式）
# ============================================================

def enc_first_segment(key_stream: bytes, key_length: int, hash_base: int,
                      file_offset: int, data: bytearray, start: int, size: int) -> None:
    for i in range(size):
        pos = file_offset + i
        byte_val = key_stream[pos % key_length]
        prod = (pos + 1) * byte_val
        if prod == 0:
            data[start + i] ^= key_stream[0]
        else:
            data[start + i] ^= key_stream[int(hash_base / prod * 100.0) % key_length]


def enc_a_segment(sbox: bytearray, key_length: int, key_stream: bytes, hash_base: int,
                  block_index: int, file_offset: int, data: bytearray, start: int, size: int) -> None:
    S = bytearray(sbox)
    local_idx = block_index & 0x1FF
    if local_idx >= key_length:
        return
    prod = (block_index + 1) * key_stream[local_idx]
    num_drops = (int(hash_base / prod * 100.0) & 0x1FF) if prod != 0 else 0
    warmup = num_drops + (file_offset % 5120)

    i = j = 0
    for _ in range(warmup):
        i = (i + 1) % key_length
        j = (j + S[i]) % key_length
        S[i], S[j] = S[j], S[i]

    for n in range(size):
        i = (i + 1) % key_length
        j = (j + S[i]) % key_length
        S[i], S[j] = S[j], S[i]
        data[start + n] ^= S[(S[i] + S[j]) % key_length]


def process_by_rc4(sbox: bytearray, key_length: int, key_stream: bytes, hash_base: int,
                   offset: int, data: bytearray, size: int) -> None:
    remaining, buf_offset, off = size, 0, offset

    if off < 128:
        chunk = min(128 - off, remaining)
        if chunk > 0:
            enc_first_segment(key_stream, key_length, hash_base, off, data, buf_offset, chunk)
            buf_offset += chunk
            off += chunk
            remaining -= chunk

    while remaining > 0:
        rem_in_seg = off % 5120
        chunk = min(5120 - rem_in_seg, remaining) if rem_in_seg != 0 else min(5120, remaining)
        if chunk <= 0:
            break
        enc_a_segment(sbox, key_length, key_stream, hash_base, off // 5120, off,
                      data, buf_offset, chunk)
        buf_offset += chunk
        off += chunk
        remaining -= chunk


def decrypt_chunk(key_stream: bytes, key_length: int, sbox: bytearray | None,
                  hash_base: int, offset: int, data: bytearray) -> None:
    """按密钥流长度自动选择两种解密模式（异或流 / 分段 RC4）。"""
    if key_length > 0x12C:
        if sbox is not None:
            process_by_rc4(sbox, key_length, key_stream, hash_base, offset, data, len(data))
    else:
        for i in range(len(data)):
            data[i] ^= map_le(key_stream, key_length, offset + i)


# ============================================================
# 10. 解密器
# ============================================================

class QMCDecryptor:
    """QMC 解密器：给一个 ekey，就能解密对应的加密文件。"""

    def __init__(self, ekey: str):
        self.ekey = ekey
        self.key_stream, self.key_length = derive_key(ekey)
        self.sbox, self.hash_base = rc4_ksa(self.key_stream, self.key_length)

    def decrypt(self, data: bytearray, offset: int = 0) -> bytearray:
        decrypt_chunk(self.key_stream, self.key_length, self.sbox, self.hash_base, offset, data)
        return data

    def decrypt_file(self, src: str | Path, dst: str | Path,
                     chunk_size: int = 512 * 1024, strip_footer: bool = True) -> None:
        src_path, dst_path = Path(src), Path(dst)
        dst_path.parent.mkdir(parents=True, exist_ok=True)

        file_size = src_path.stat().st_size
        footer_size = 0
        if strip_footer:
            try:
                with open(src_path, "rb") as f:
                    f.seek(-8, 2)
                    tail = f.read(8)
                    if tail[-4:] == b"STag":
                        meta_len = int.from_bytes(tail[:4], "big")
                        if 0 < meta_len <= 256:
                            footer_size = meta_len + 8
            except Exception:
                pass

        decrypt_size = file_size - footer_size
        offset = 0
        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            while offset < decrypt_size:
                buf = bytearray(fin.read(min(chunk_size, decrypt_size - offset)))
                if not buf:
                    break
                self.decrypt(buf, offset)
                fout.write(bytes(buf))
                offset += len(buf)


# ============================================================
# 11. 扩展名推断
# ============================================================

QMC_EXT_MAP = {
    ".mflac": ".flac", ".mflac0": ".flac", ".mflac1": ".flac",
    ".mflac2": ".flac", ".mflac3": ".flac", ".mflac4": ".flac",
    ".mflac5": ".flac", ".mdolby": ".flac",
    ".mgg": ".ogg", ".mgg0": ".ogg", ".mgg1": ".ogg", ".mgg2": ".ogg",
    ".qmc": ".ogg", ".qmc0": ".flac", ".qmc3": ".mp3", ".qmc6": ".ogg",
}


def infer_output_ext(src: str) -> str:
    src_lower = src.lower()
    for enc_ext, audio_ext in sorted(QMC_EXT_MAP.items(), key=lambda x: -len(x[0])):
        if src_lower.endswith(enc_ext):
            return audio_ext
    return ".flac"


# ============================================================
# 自检 / CLI
# ============================================================

def _selftest() -> int:
    ok = True

    def chk(cond, msg):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + msg)
        ok = ok and cond

    # simple_make_key 是确定性的
    sk = simple_make_key(106, 8)
    chk(len(sk) == 8 and sk == simple_make_key(106, 8), "simple_make_key(106,8) 确定性 8 字节")

    # TEA 解密可跑（对固定输入得到固定输出）
    k = bytes_to_u32be(b"0123456789abcdef")
    out = tea_decrypt_block(0x12345678, 0x9ABCDEF0, k)
    chk(isinstance(out, tuple) and len(out) == 2, f"tea_decrypt_block → {out[0]:#x},{out[1]:#x}")

    # derive_key 走完整路径（8 字节头 + 16 字节密文 = 24 字节 → base64）
    fake = base64.b64encode(bytes(i & 0xFF for i in range(72))).decode()
    ks, klen = derive_key(fake)
    chk(klen > 8, f"derive_key 得到密钥流 {klen} 字节")

    # 解密是异或流 → 同一偏移解两次应还原
    dec = QMCDecryptor(fake)
    data = bytearray(b"hello qqmusic " * 64)
    orig = bytes(data)
    dec.decrypt(data, 0)
    dec.decrypt(data, 0)
    chk(bytes(data) == orig, "异或流自反：解两次还原原文")

    # 长密钥流走 RC4 分支
    fake2 = base64.b64encode(bytes(i & 0xFF for i in range(400))).decode()
    dec2 = QMCDecryptor(fake2)
    chk(dec2.key_length > 0x12C, f"长密钥流模式 key_length={dec2.key_length}")
    buf = bytearray(b"A" * 6000)
    dec2.decrypt(buf, 0)
    chk(any(b != 0x41 for b in buf[:6000]), "RC4 分段解密确实改写了数据")

    chk(infer_output_ext("song.mflac0") == ".flac" and infer_output_ext("x.mgg1") == ".ogg",
        "扩展名推断 .mflac0→.flac / .mgg1→.ogg")

    print("\n自检:", "全部通过 ✅" if ok else "有失败 ❌")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[1]
    if cmd == "selftest":
        return _selftest()
    if cmd == "key" and len(argv) > 2:
        ks, klen = derive_key(argv[2])
        print(f"key_length = {klen}\nkey_stream[:32] = {ks[:32].hex()}")
        return 0
    if cmd == "decrypt" and len(argv) > 4:
        src, dst, ekey = argv[2], argv[3], argv[4]
        QMCDecryptor(ekey).decrypt_file(src, dst)
        print(f"已解密: {src} -> {dst}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
