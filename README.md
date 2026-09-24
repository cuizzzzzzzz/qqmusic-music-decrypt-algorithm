**English** · [简体中文](README.zh-CN.md)

# QQ Music Android Client — QMC Decryption (.mflac / .mgg / .qmc*)

> ### 📱 This is the **mobile (Android client)** implementation
> Decryption of QQ Music's encrypted audio files (`mflac` / `mflac0` / `mgg` / `qmc*`),
> derived from the Android app's **`libekey_decrypt.so` (ARM64)**.
>
> ⚠️ **How this differs from other public QQ Music RE projects**: most public projects target the
> **web / PC client** (web `sign` computation, PC-client `qmc` decryption). This project targets the
> **Android app**, whose ekey derivation and keystream are **completely different and not interchangeable**.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib_only-success)
![Platform](https://img.shields.io/badge/target-Android%20%2F%20ARM64-orange)
![Network](https://img.shields.io/badge/network-none-lightgrey)

---

## What this is

The QQ Music (Tencent Music / TME) Android client stores downloaded high-quality audio in QMC formats:

| Encrypted | Decrypted | Notes |
|---|---|---|
| `.mflac` `.mflac0~5` `.mdolby` | `.flac` | lossless / master |
| `.mgg` `.mgg0~2` | `.ogg` | high-quality OGG |
| `.qmc0` / `.qmc3` / `.qmc6` | `.flac` / `.mp3` / `.ogg` | legacy formats |

Decryption requires a **per-track `ekey`** (obtained by the client while online). This repository
provides the **decryption algorithm itself** — pure Python, standard library only, **no network code**.

## Algorithm overview (mobile-specific)

1. **Key derivation** `derive_key(ekey)`
   - base64-decode `ekey` → first 8 bytes act as a seed
   - `SimpleMakeKey(seed=106, len=8)` (`tan(seed + i*0.1)*100`) produces 8 bytes which are
     **interleaved** with the raw ekey bytes into a 16-byte TEA key
   - Remaining bytes are decrypted with `oi_symmetry_decrypt2` — a **QQ-private TEA variant**
     (chaining uses the *XOR-ed input block*, not standard CBC/ECB) — and appended to the keystream
2. **RC4 KSA** `rc4_ksa()` — standard KSA plus a `hash_base` (running-product bound)
3. **Per-block decryption**, one of two modes depending on keystream length:
   - `key_length <= 300`: XOR with a `mapLE`-generated keystream (self-inverse)
   - `key_length > 300`: **segmented RC4 variant** — first 128 bytes as one segment, then **5120-byte**
     segments, each dropping `(pos+1) * key_byte` warm-up bytes
4. **File footer**: if the file ends with an `STag` footer (4-byte metadata length + `STag`), it must
   be skipped during decryption

## Install & usage

```bash
git clone https://github.com/cuizzzzzzzz/qqmusic-music-decrypt-algorithm.git
cd qqmusic-music-decrypt-algorithm

python3 qqmusic_decrypt.py selftest                      # self-test
python3 qqmusic_decrypt.py key <ekey>                    # inspect keystream length
python3 qqmusic_decrypt.py decrypt <in> <out> <ekey>     # decrypt a whole file
```

As a library:

```python
from qqmusic_decrypt import QMCDecryptor, infer_output_ext, derive_key

QMCDecryptor(ekey).decrypt_file("song.mflac0", "song.flac")
```

**Requirements**: Python 3.8+, **no third-party dependencies** (no numpy / pycryptodome / ffmpeg).

## Self-test

```
$ python3 qqmusic_decrypt.py selftest
PASS simple_make_key(106,8) deterministic 8 bytes
PASS tea_decrypt_block -> 0x21c2674d,0xd5aff1cd
PASS derive_key produced 55-byte keystream
PASS XOR stream is self-inverse (decrypt twice restores)
PASS long-keystream mode key_length=383
PASS segmented RC4 path actually rewrites data
PASS extension inference .mflac0->.flac / .mgg1->.ogg

self-test: all passed
```

## Keywords

`QQ Music decrypt` `QMC decoder` `ekey decrypt` `mflac` `mgg` `qmc0` `qmc3` `Android reverse engineering`
`mobile client` `ARM64` `libekey_decrypt` `TEA` `RC4` `Tencent Music` `TME` `QQ音乐解密`

## Related projects

- **[qqmusic-network-signature-algorithm](https://github.com/cuizzzzzzzz/qqmusic-network-signature-algorithm)**
  — the **request signature** chain of the same Android client (TEA-CBC / OpenUDID / M-Value / HMAC-SHA1)

## Disclaimer

This project is for **security research and file-format study only**. Do not use it to break paid
content, bypass copyright protection, or for any commercial purpose. This repository provides **no
way to obtain an ekey** and contains **no network code**. Use at your own risk.
