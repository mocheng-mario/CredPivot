# CPVC1 本地控制配置（vault.json）

与 `docs/Plans/CredPivot_V1.1_Design.md` 第 12.3、13.2、附录 A.2 对齐。M1 冻结 v1。

## 文件形态

- 路径：`CredPivotVault/vault.json`（UTF-8 JSON）
- Magic：`"CPVC1"`（`format_major` 必须为 `1`）

## 字段

| 字段 | 类型 | 说明 |
|:---|:---|:---|
| `magic` | string | 固定 `CPVC1` |
| `format_major` | u8 | `1` |
| `vault_id` | string | UUID v4 字符串 |
| `control_id` | string | 每次改密/轮换递增的配置实例 ID（UUID） |
| `control_revision` | u64 | 单调递增修订号 |
| `key_slots` | array | 见「密钥槽」 |
| `control_mac` | string | Base64url，**写入时置于 JSON 末尾** |

## 配置 MAC（control_mac）

1. 用 VMK 经 HKDF 派生 `config_mac_key`（见 `specs/crypto_domains.md`）。
2. 对 **不含 `control_mac` 字段** 的规范 JSON 正文计算 HMAC-SHA256（见「规范 JSON」）。
3. `control_mac` = Base64url(no pad) 编码的 32 字节 MAC。

规范 JSON：对象键按 UTF-8 字典序递归排序；数组保持顺序；数字为 JSON number；字符串 UTF-8；无空白。

## 密钥槽

主密码槽与恢复槽共用字段集（与 OVB 头槽编码一致，见 `crates/core/src/key_slot.rs`）。

- `master-password`：Argon2id → KEK → AES-256-GCM 包装 VMK
- `recovery-key`：恢复密钥材料 → HKDF → KEK → AES-256-GCM 包装 VMK

AAD（GCM）：`CPVC1-AAD` + vault_id + slot_id + slot_type + format_major（见实现）。

## 改密与崩溃恢复

1. 写入 `vault.json.next`（完整新配置 + 有效 MAC）。
2. `fsync` 后 `rename` 覆盖 `vault.json`。
3. 保留 `vault.json.bak` 为上一代（可选，实现默认开启）。
4. 启动时若存在 `.next` 且 MAC 合法则完成替换；若仅 `.bak` 合法则回退提示。
