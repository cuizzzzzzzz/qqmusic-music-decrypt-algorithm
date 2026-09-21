# QQ 音乐 QMC 解密算法（QMC / ekey decrypt）

QQ 音乐加密音频文件（`.mflac` / `.mgg` / `.qmc*`）的解密流程 —— 纯 Python 实现，
逆向自 Android 客户端动态库 `libekey_decrypt.so`（ARM64）。

**只依赖 Python 标准库**，无第三方依赖，无网络请求。

## 算法概要

1. **密钥推导** `derive_key(ekey)`
   - `ekey` base64 解码 → 前 8 字节作种子
   - `SimpleMakeKey(seed=106, len=8)` 生成 8 字节，与 ekey 原始字节**交错合并**成 16 字节 TEA 密钥
   - 余下字节经 `oi_symmetry_decrypt2`（QQ 版 TEA，带块间异或链）解密，接在密钥流后
2. **RC4 KSA** `rc4_ksa(key_stream)` —— 标准 KSA + 推导 `hash_base`（连乘上限）
3. **逐块解密**，按密钥流长度二选一：
   - `key_length <= 300`：`mapLE` 生成的密钥流做异或（自反）
   - `key_length > 300`：分段 RC4 变体 —— 前 128 字节一段，之后每 5120 字节一段，
     每段按 `(pos+1)*key_byte` 推导需要丢弃多少字节
4. **文件尾部**：若以 `STag` footer 结尾（4B 元数据长度 + `STag`），解密时跳过

## 用法

```bash
python3 qqmusic_decrypt.py selftest                      # 自检
python3 qqmusic_decrypt.py key <ekey>                    # 推导密钥流
python3 qqmusic_decrypt.py decrypt <输入> <输出> <ekey>   # 解密整个文件
```

作为库使用：

```python
from qqmusic_decrypt import QMCDecryptor, infer_output_ext

QMCDecryptor(ekey).decrypt_file("song.mflac0", "song.flac")
```

## 自检结果

```
PASS simple_make_key(106,8) 确定性 8 字节
PASS tea_decrypt_block → 0x21c2674d,0xd5aff1cd
PASS derive_key 得到密钥流 55 字节
PASS 异或流自反：解两次还原原文
PASS 长密钥流模式 key_length=383
PASS RC4 分段解密确实改写了数据
PASS 扩展名推断 .mflac0→.flac / .mgg1→.ogg
```

## 免责声明

本项目仅用于**安全研究与文件格式学习**。请勿用于破解付费内容、绕过版权保护或任何商业用途。
本项目不提供任何密钥获取途径，也不包含任何网络请求代码 —— 你需要自行取得 `ekey`。
因使用本项目产生的一切后果由使用者自负。
