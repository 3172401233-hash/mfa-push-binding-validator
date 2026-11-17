# mfa-push-binding-validator

JavaScript MFA 推送挑战状态机。修复"只检查 challenge ID 是否存在"的缺陷：每一次批准 / 拒绝 / 兑换都强制绑定到**原始设备密钥**和**登录动作摘要**，且批准结果只能兑换一次。

## 状态机

```
createChallenge ──> pending ──approve──> approved ──consume──> consumed
                     │  │
                     │  └─deny(用户取消)/rebindDevice(设备重新绑定)──> denied
                     └─超时(惰性检测或 sweep)────────────────────────> expired
```

- `pending`：挑战已创建，等待设备端响应。
- `approved`：绑定设备已批准，等待服务端兑换。
- `denied`：用户取消，或设备重新绑定导致旧挑战失效。
- `expired`：超过 `expiresAt`（访问时惰性迁移，也可调用 `sweep()` 批量处理）。
- `consumed`：批准结果已兑换，**终态**，再次兑换抛 `ERR_ALREADY_CONSUMED`。

所有状态迁移在单次同步调用内完成，并发批准只有一个能成功，其余得到 `ERR_INVALID_STATE`。

## 绑定字段

`createChallenge({ challengeId, accountId, deviceKey, actionDigest, nonce, expiresAt })` 创建挑战时绑定以下字段，后续 `approve` / `deny` / `consume` 必须逐项匹配（使用 `crypto.timingSafeEqual` 常量时间比较）：

| 字段 | 作用 |
| --- | --- |
| `challengeId` | 挑战唯一标识，重复创建抛 `ERR_CHALLENGE_EXISTS` |
| `accountId` | 账号，nonce 去重与设备重新绑定的作用域 |
| `deviceKey` | 设备密钥，批准必须来自原设备，否则 `ERR_DEVICE_MISMATCH` |
| `actionDigest` | 登录动作摘要（如 `sha256:login:web:session-9`），动作内容变化即 `ERR_ACTION_MISMATCH` |
| `nonce` | 一次性随机数；同账号跨挑战复用抛 `ERR_NONCE_REPLAY`，不匹配抛 `ERR_NONCE_MISMATCH` |
| `expiresAt` | 过期时间戳（ms），超时后挑战进入 `expired` |

### 签名

严格模式（默认，`requireSignature: true`）下，`approve` / `deny` 还需携带 HMAC-SHA256 签名，把批准加密绑定到设备密钥与动作摘要：

```
signature = HMAC_SHA256(deviceKey,
  "mfa-push-v1|" + challengeId + "|" + accountId + "|" + actionDigest + "|" + nonce + "|" + decision)
```

`decision` 为 `approve` 或 `deny`。库导出 `signApproval(deviceKey, fields)` 供设备端/测试使用。签名不匹配抛 `ERR_BAD_SIGNATURE`——即使攻击者知道 challenge ID，没有其他设备的密钥也无法伪造批准。

## 并发与异常处理

- **并发批准**：状态检查与迁移在同一同步区段完成，`Promise.all` 并发提交时仅一个成功。
- **设备重新绑定**：`rebindDevice({ accountId, newDeviceKey })` 将该账号所有 `pending` / `approved` 挑战置为 `denied`（原因 `device_rebind`），旧设备的批准与未兑换结果一并作废。
- **nonce 重放**：nonce 按账号记录，跨挑战复用在创建时即被拒绝；同挑战内因状态迁移天然只能决策一次。
- **用户取消**：`deny` 同样校验设备、nonce 与签名；取消后 `approve` / `consume` 均抛 `ERR_INVALID_STATE`。
- **超时**：每次访问惰性检查 `expiresAt`；`sweep()` 可批量清理，返回过期数量。

## 降级方式

构造函数支持 `new MfaPushStateMachine({ requireSignature: false })` 用于推送签名通道不可用时的降级运行：

- 降级模式跳过 HMAC 签名校验，但**仍然强制**设备密钥、动作摘要、nonce 的逐项相等校验与单次兑换语义。
- 适用场景：设备端暂时无法计算签名（如旧版 App），服务端以安全通道下发生成的 `deviceKey` 作为持有证明。
- 不可降级的部分：设备绑定、动作摘要绑定、nonce 一次性、单次兑换、过期处理。任何情况下都不应退化为"只查 challenge ID 是否存在"。
- 恢复严格模式只需重新以默认选项构造实例；建议降级期间缩短 `expiresAt` 并提升 `actionDigest` 的熵。

## 测试

```sh
node --test
```

覆盖：另一端设备替批准、伪造签名、动作内容变化、重复消费、并发批准、设备重新绑定、nonce 重放、用户取消、超时与批量清理。
