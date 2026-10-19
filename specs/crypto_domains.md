# 密码学域分离（M1）

所有 HKDF 使用 **SHA-256**，输出长度 32 字节。

| 用途 | salt | info |
|:---|:---|:---|
| SQLCipher 原始密钥 | `vault_id`（16 字节） | `credpivot/local-db/v1` |
| OVB 快照 AEAD 密钥 | `vault_id`（16 字节） | `credpivot/ovb-snapshot/v1` \|\| `archive_id`（32 字节） |
| CPVC 配置 MAC 密钥 | `vault_id`（16 字节） | `credpivot/config-mac/v1` |
| 恢复槽 KEK | 槽 `salt`（32 字节） | `credpivot/recovery-kek/v1` \|\| `vault_id` |

## Argon2id（主密码槽默认）

- `memory_kib`: 65536
- `iterations`: 3
- `parallelism`: 4
- `salt`: 32 字节随机

实现允许读取槽内记录参数；不得自行替换为更弱参数。

## 恢复密钥（人类可读）

- 256-bit 秘密，Crockford Base32（大写，无填充）
- 展示：8 组，每组 5 字符 + `-`，最后一组 5 字符后为 `-` + 2 字符校验
- 校验：`CRC-16/CCITT-FALSE` 作用于去分隔符的 Base32 载荷，十六进制 2 字符

验证失败不得解锁。
