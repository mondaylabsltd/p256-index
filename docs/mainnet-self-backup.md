# 用户自助主网备份(Mainnet Self-Backup)设计文档

> 状态:设计定稿,待实施。本文档是实施时的唯一参考。
> 前置事实(2026-08-27 已完成):V13 已部署并完成 V11 全量数据迁移验证。

## 0. 一句话

用户自愿、自费地把自己的注册记录镜像到以太坊主网上的同域 registry 部署,
作为"任何服务商/任何便宜链都死掉"之后的最后一层保障;系统负责让"备份"
和"从备份查询/恢复"都是几次标准 RPC 调用的事。

## 1. 信任模型与角色

- **备份不是授权**:payload 自带 P256 签名证明,主网合约会完整重放验签。
  伪造/篡改的 payload 上不了链。因此任何人都可以替任何人备份(calldata
  是公开的),"用户自费"只是出资模型,不是权限模型。
- **server 永远不是信任方**:它可以提供便利(见 §5),但用户拿到的字节
  是否有效由主网合约裁决。
- **可选性**:不备份的用户仍受运营方兜底保护(Redis + R2 小时级归档 +
  Gnosis 链上数据 + 建议中的主网 merkle 锚定);主网个人镜像是在这之上
  的、无需信任任何人的一层。

## 2. 依赖的合约能力(V13 已具备)

| 能力 | 合约版本 | 说明 |
|---|---|---|
| 冻结签名域 | V12+ | challenge 绑定构造时传入的 `(DOMAIN_CHAIN_ID, DOMAIN_REGISTRY)`,不读 `block.chainid`/`address(this)`。全系域为 `(100, 0x5266DfF591B9F9EecfEdb8E7EfEf6c687854edaf)`(V11 地址,永不再变) |
| payload 自存储 | V13 | 每笔通过验证的写入把 `msg.data` 原样存链上;`registerPayloadOf(unitId)` / `referPayloadOf(referenceId)` 纯 eth_call 取出可重放字节 |
| 幂等重放 | V10+ | 群 key 单次使用 + content hash 去重 + (unit, entry) 引用去重:重复提交安全失败 |

当前部署:

- Gnosis V11(旧正典,server 仍在写):`0x5266DfF591B9F9EecfEdb8E7EfEf6c687854edaf`
- Gnosis V13(新正典候选,已全量迁移):`0x94fD1A891EB6c5F340622Baf2F3A0cb70A941EA9`
- Gnosis V12(中间产物镜像,无视即可):`0x70d8126c9cC42F60fEeFd1666633cbf40538e18a`

## 3. 主网部署规格

- 合约:`WebAuthnP256PublicKeyRegistry`(V13 同一份字节码)。
- 构造参数:`(100, 0x5266DfF591B9F9EecfEdb8E7EfEf6c687854edaf)` —— 与
  Gnosis V13 完全相同的域。
- 部署方式:CREATE2(`script/DeployRegistry.s.sol`,forge 默认
  deterministic deployer)。**同 initcode + 同 salt ⇒ 主网地址与 Gnosis
  V13 相同**(`0x94fD1A891EB6c5F340622Baf2F3A0cb70A941EA9`),客户端可以
  硬编码一个地址走天下。部署前用 `DEPLOY_SALT` 保持与 Gnosis V13 部署时
  一致(当时为默认 `bytes32(0)`)。
- 前置检查:主网 `0x100` 的 P256VERIFY 预编译(EIP-7951,Fusaka 已上线)。
  部署前按 `DeployRegistry.s.sol` 注释里的 cast 命令用已知向量验证一次。
- 部署账户:任意;合约无 owner、无特权角色。

## 4. 客户端"备份到主网"流程(核心交付)

放在 vela-wallet 各端的钱包详情页。所有步骤都是标准 JSON-RPC,无自定义
后端依赖:

```
1. unitId   = gnosisV13.getUnitByGroupKey(groupPublicKey).unitId      // eth_call
2. payload  = gnosisV13.registerPayloadOf(unitId)                     // eth_call
3. (可选) 对每个引用: referPayloadOf(referenceId)                     // eth_call
4. 用户钱包(任意 EOA/合约钱包,与 passkey 无关)向主网 registry 地址
   发送 tx,data = payload,自付 gas
5. 依赖序:register 先落地,refer 后发(refer 需要目标组已存在)
```

- **费用**:单成员组 register ≈ 1.2M~2.4M gas(V13 payload 存储约使
  gas 翻倍)。UI 里用 `eth_estimateGas` 实价展示,不要硬编码。
- **状态判断(UI 三态)**:对主网合约 eth_call 同一 payload:
  - 成功(会写入)⇒ **未备份**;
  - revert `GroupKeyAlreadyUsed()` / `AlreadyReferenced()` ⇒ **已备份**;
  - 其他 revert ⇒ 异常,展示原始错误。
  这个"以重复错误证明存在"的判断不需要任何专门 getter,与
  `p256-replay verify` 同一原理。
- **恢复路径(灾难时反向)**:主网 registry 上同样有
  `registerPayloadOf`/`referPayloadOf`(payload 递归自带),从主网读出
  再重放到任何新链,流程同上。

## 5. server 支持(便利层,均为只读)

1. `GET /api/replay-payload?groupPublicKey=0x…`
   返回 `{ registerPayload, refers: [{ referenceId, payload }] }`。
   实现:优先 Redis task 缓存,miss 时链上 `registerPayloadOf` 兜底。
   纯便利,客户端也可以完全绕开它直接走 §4。
2. `/api/query` 结果附 `mirroredOnMainnet: true|false`(用 §4 的
   重复错误探测,结果可缓存;这是引导用户去备份的产品钩子)。
3. 配置:server 增加主网 RPC 与主网 registry 地址两个 env(只读用途)。

## 6. V13 切换(备份功能的前置,单独执行)

顺序不可乱:

1. 发布带域分离支持的 server(`P256_INDEX_DOMAIN_REGISTRY` 已实现,
   代码在库;需出新镜像版本);
2. 服务器 `.env`:
   `P256_INDEX_CONTRACT_ADDRESS=0x94fD1A891EB6c5F340622Baf2F3A0cb70A941EA9`
   `P256_INDEX_DOMAIN_REGISTRY=0x5266DfF591B9F9EecfEdb8E7EfEf6c687854edaf`
3. 切换窗口内做一次增量补迁:`p256-replay export`(V11)→ `replay`(V13),
   幂等,重复跑无害;
4. 同一窗口更新 vela-wallet 只读地址(仅两处,挑战流程走 server API
   无需改动):
   - `app-web/getvela.app/src/lib/chain.ts:29` `CONTRACT_ADDRESS`
   - `app-web/getvela.app/src/routes/+page.svelte:70` `CURRENT_CONTRACT`
5. 验证:`/api/health` 显示 `registry=V13, domainRegistry=V11`;注册一个
   新 passkey 走通全流程;`p256-replay verify` 对 V13 全绿。
6. V11 保留只读,不下线(它是签名域的名义锚点,也是历史事件的原始出处)。

## 7. 实施清单

- [ ] 主网部署 V13(§3,验证 P256VERIFY → CREATE2 → 核对地址与域)
- [ ] server:`/api/replay-payload` + `mirroredOnMainnet` + 主网只读配置(§5)
- [ ] vela-wallet:备份按钮 + 三态展示 + 费用估算 + 恢复入口(§4;各端
      RegistryClient 只加只读 RPC 逻辑,不碰挑战/注册流程)
- [ ] 文档/FAQ:向用户解释"备份了什么、防的是什么、多少钱"
- [ ] 运营:R2 归档定期 `p256-replay export`;(可选)运营方主网 merkle
      锚定作为无镜像用户的兜底证明

## 8. 明确不做的

- 不做 server 代付主网 gas(违背"用户自持"的成本与激励模型);
- 不做主网双写(写路径增加活性依赖,可用性变差);
- 不做主网优先读(主网只有部分镜像,日常读仍是 本地缓存 → Gnosis)。
