[English](README.md) · **简体中文**

# QQ 音乐 安卓客户端 QMC 解密算法 · QQMusic Android Client QMC Decryption

> ### 📱 这是**手机端（Android 客户端）**的逆向实现
> 加密音频文件 `mflac` / `mflac0` / `mgg` / `qmc*` 的解密流程，逆向自 Android App 的
> **`libekey_decrypt.so`（ARM64）**。
>
> ⚠️ **与网上其他 QQ 音乐逆向项目的区别**：目前公开的项目**绝大多数是 Web / PC 端**
> （网页版 `sign` 计算、PC 客户端 `qmc` 解密）。本项目针对的是**移动端 App** 的
> ekey 密钥推导与 QMC 文件解密，**算法与密钥流完全不同**，不能混用。

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-stdlib_only-success)
![Platform](https://img.shields.io/badge/target-Android%20%2F%20ARM64-orange)
![No network](https://img.shields.io/badge/network-none-lightgrey)

---

## 这是什么

QQ 音乐（Tencent Music / TME）安卓客户端会把下载的高音质音频加密成 QMC 系列格式：

| 加密文件 | 解密后 | 说明 |
|---|---|---|
| `.mflac` `.mflac0~5` `.mdolby` | `.flac` | 无损 / 母带 |
| `.mgg` `.mgg0~2` | `.ogg` | OGG 高音质 |
| `.qmc0` / `.qmc3` / `.qmc6` | `.flac` / `.mp3` / `.ogg` | 早期格式 |

解密需要**每一首歌自己的 `ekey`**（客户端联网时获得）。本仓库提供的是**拿到 ekey 之后**的
完整解密算法 —— 纯 Python、只用标准库、不含任何网络请求。

## 算法概要（移动端特征）

1. **密钥推导** `derive_key(ekey)`
   - `ekey` 经 base64 解码 → 前 8 字节作种子
   - `SimpleMakeKey(seed=106, len=8)`（`tan(seed + i*0.1)*100`）生成 8 字节，
     与 ekey 原始字节**交错合并**成 16 字节 TEA 密钥
   - 其余字节经 `oi_symmetry_decrypt2`（**QQ 私有 TEA 变体**：块间用"异或后的输入"做链，非标准 CBC/ECB）
     解密后拼到密钥流尾部
2. **RC4 KSA** `rc4_ksa()` —— 标准 KSA + 推导 `hash_base`（连乘上限，用于后面算丢弃字节数）
3. **逐块解密**（按密钥流长度二选一）
   - `key_length <= 300`：`mapLE` 密钥流异或（自反）
   - `key_length > 300`：**分段 RC4 变体** —— 头部 128 字节一段，之后每 **5120** 字节一段，
     每段用 `(pos+1) * key_byte` 推导热身丢弃字节数
4. **文件尾部**：若以 `STag` footer（4B 元数据长度 + `STag`）结尾，解密时需跳过

## 安装与使用

```bash
git clone https://github.com/cuizzzzzzzz/qqmusic-music-decrypt-algorithm.git
cd qqmusic-music-decrypt-algorithm

python3 qqmusic_decrypt.py selftest                      # 自检
python3 qqmusic_decrypt.py key <ekey>                    # 只看密钥流长度
python3 qqmusic_decrypt.py decrypt <输入> <输出> <ekey>   # 解密整个文件
```

作为库调用：

```python
from qqmusic_decrypt import QMCDecryptor, infer_output_ext, derive_key

QMCDecryptor(ekey).decrypt_file("song.mflac0", "song.flac")
```

**环境要求**：Python 3.8+，**无第三方依赖**（不需要 numpy / pycryptodome / ffmpeg）。

## 自检结果

```
$ python3 qqmusic_decrypt.py selftest
PASS simple_make_key(106,8) 确定性 8 字节
PASS tea_decrypt_block → 0x21c2674d,0xd5aff1cd
PASS derive_key 得到密钥流 55 字节
PASS 异或流自反：解两次还原原文
PASS 长密钥流模式 key_length=383
PASS RC4 分段解密确实改写了数据
PASS 扩展名推断 .mflac0→.flac / .mgg1→.ogg

自检: 全部通过 ✅
```

## 关键词 / Keywords

`QQ音乐解密` `QMC解密` `mflac解密` `mgg解密` `qmc0` `qmc3` `ekey` `安卓客户端` `移动端逆向`
`QQMusic decrypt` `QMC decoder` `ekey decrypt` `mflac` `mgg` `Android reverse engineering`
`Tencent Music` `TME` `libekey_decrypt` `ARM64` `TEA` `RC4`

## 相关项目

- **[qqmusic-network-signature-algorithm](https://github.com/cuizzzzzzzz/qqmusic-network-signature-algorithm)**
  —— 同一个安卓客户端的**网络请求签名**算法（TEA-CBC / OpenUDID / M-Value / HMAC-SHA1）

## 免责声明

本项目仅用于**安全研究与文件格式学习**。请勿用于破解付费内容、绕过版权保护或任何商业用途。
本项目**不提供任何 ekey 获取途径**，也不包含任何网络请求代码。因使用本项目产生的一切后果由使用者自负。
