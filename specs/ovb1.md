# OVB1 开放加密归档

M1 冻结 **信封 v1**：固定头 + 单 AEAD 密文。逻辑快照 JSON 见设计第 14 章。

## 文件布局

```text
[header_bytes][ciphertext_bytes]
```

## 头部（二进制，big-endian 长度前缀除外）

| 偏移 | 长度 | 字段 |
|:---|:---|:---|
| 0 | 4 | Magic `OVB1` |
| 4 | 1 | `format_major` = 1 |
| 5 | 1 | `format_minor` = 0 |
| 6 | 16 | `vault_id`（UUID 原始字节） |
| 22 | 32 | `archive_id`（随机） |
| 54 | 1 | `cipher_id` = 1（AES-256-GCM） |
| 55 | 12 | `nonce` |
| 67 | 4 | `header_slots_len`（u32 BE） |
| 71 | N | `header_slots_bytes`（密钥槽 TLV，与 CPVC 同编码） |
| 71+N | 4 | `ciphertext_len`（u32 BE） |

**AAD** = 从 magic 起至 `header_slots_bytes` 结束（不含 `ciphertext_len` 与密文）。

## 快照密钥

`snapshot_key = HKDF-SHA256(vmk, salt=vault_id, info="credpivot/ovb-snapshot/v1" || archive_id)`

## 限制（解析前检查）

| 项 | 上限 |
|:---|:---|
| 文件大小 | 256 MiB |
| `header_slots_len` | 64 KiB |
| `ciphertext_len` | 文件大小 - header |
| 槽数量 | 8 |
| Argon2 memory | 128 MiB |

超限 → 拒绝解析。
