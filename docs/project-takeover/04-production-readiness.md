
# 04 — 生产就绪审计

> 审计基线 commit `113a8c6`(2026-07-09)。方法:1 名接管架构师亲读全部核心源码 + 实机 smoke test + 一个多代理审计工作流(6 维度 × 对抗验证,45 个 agent,0 错误)。工作流产出 **59 条确认发现(3×P1 / 20×P2 / 36×P3)+ 3 条被对抗验证驳回**。本文所有条目均对照源码复核。

## 结论摘要

**核心资金路径(队列状态机、双钱包 nonce、commit-reveal、毒丸隔离、reconcile、幂等、receipt 校验)经过两轮加固,质量扎实,未发现 P0。** 阻碍上线的是**可靠性盲区与运维可观测性**,而非功能正确性。本次接管已修复全部 3 个 P1 及若干高价值 P2 并补了回归测试;其余为可带缓解措施延期的 P2/P3。


| 严重度 | 确认数 | 本次已修 | 剩余          |
| -------- | -------- | ---------- | --------------- |
| P0     | 0      | —       | 0             |
| P1     | 3      | 3        | 0             |
| P2     | 20     | 6        | 14            |
| P3     | 36     | 2        | 34(债务/优化) |

基线验证(修复后)全部通过:`deno test` **149 passed / 0 failed / 5 ignored**;`npm test` **28 passed**;`deno check deno/index.ts` 通过;`deno task build` 成功产出二进制;`npm audit --omit=dev` 0 漏洞;实机 smoke(health/challenge/stats 真实链读/create/限流/CORS)全部符合预期。新增回归测试 8 个(Deno:Alchemy 写端点轮转、PRIVATE_KEY 校验 4 个、Telegram 失败告警 3 个;CF:DO Alchemy 接线 2 个)。

## 被对抗验证驳回的 3 条(不作为问题)

1. **"commit-reveal 抢跑防护被 publicKey 前置暴露击穿"** → 驳回:状态查询由不可猜的 `crypto.randomUUID` job id 门控;query 回退需高熵 credentialId;链上 commit 是 keccak 哈希,mempool 观察者看不到明文;且 walletRef 抢注是**合约层**属性,本 API 不增加攻击者能力(任何知道 victim publicKey 的人可直接上链抢注)。残留仅为文档措辞的防御深度提示,非阻塞。
2. **"DLQ 无运维工具/静默删除"** → 驳回:`06-operations-runbook.md` 已给出 DLQ 列表与重放 SQL;部分唯一索引 `WHERE status!='failed'` 就是为重放设计;失败后用户可重新 POST(idempotency.test.ts 已锁);/api/health 在 dlq≥25 报 degraded。残留仅"缺便捷脚本"。
3. **"revert 交易 gas 不可见 / commit 隔离可循环烧 gas"** → 驳回:processPending 每轮重新 estimate,确定性 revert 会在下一轮 estimate 失败→隔离→计数入 DLQ(可见);commit 幂等,nonce 冲突归类 transient(走计数路径)。残留仅"无 revert/gas 指标",属 P3。

## P1(上线前必须解决)—— 本次全部已修复

### P1-1 写路径无 RPC 健康追踪 + gas 检查失败前告警盲区 ✅ 已修

- **证据**:`markFailed/markHealthy` 只在读路径调用(`shared/contract-read.ts:77,86`),写路径的 `getWriteRpc()`(`shared/rpc.ts:130`)对 Alchemy/WRITE_RPCS 的 `isAvailable()` 永远为真。每轮开头的 gas 检查失败时,`processQueue` 在 `checkAlerts` **之前** return(`deno/queue.ts:336`、`worker/queue-processor.ts:127`)。
- **触发**:生产 `.env` 配了 `ALCHEMY_API_KEY`;Alchemy 宕机/限流/吊销 → 每轮 gas 检查都打这个"钉死"的死端点并失败 → 整个写管线停摆,`/api/create` 仍回 202,**运维零告警**。长时间会把重试项推入 EXHAUSTED DLQ。
- **修复**:gas 检查捕获里 `markFailed(gasRpc)`(下轮 `getWriteRpc` 轮转到公共 RPC,含把死 Alchemy 冷却掉),成功时 `markHealthy`;**return 前先跑 `checkAlerts`**,让积压/低余额/DLQ 告警在故障期照常发出。CF 侧同修,并补齐 Deno 已有的 gas-price 告警(见 P2-CF-gas)。
- **回归**:`deno/tests/rpc.test.ts` 新增 "getWriteRpc rotates OFF a failed Alchemy endpoint"。
- **残留(P3)**:发送路径(commit/create tx)本身仍不 `markFailed`;但 gas 检查是每轮闸门,冷却它足以让全轮轮转away,已解决停摆核心。

### P1-2 CF Worker 零 CI:移动真实资金的 630 行 DO 从不被测试/类型检查 ✅ 已修

- **证据**:`.github/workflows/ci.yml` 只跑 `deno check deno/index.ts` + `deno task test`(仅 deno/tests)。`npm test`(vitest)从不在 CI 跑;无 tsconfig,worker/*.ts 从不被任何工具类型检查。`worker/queue-processor.ts` 有三条历史生产 bug 修复(0bd4ec0/2da0f7e/6e878c4)。
- **触发**:任何 `shared/*.ts` 改动破坏 worker 会 CI 全绿,仅在 `wrangler deploy` 后于生产 DO alarm 循环中崩。
- **修复**:`ci.yml` 新增 `worker` job(`npm ci` + `npm test`),vitest 通过 esbuild 编译并运行 worker + D1 队列路径,shared 改动破坏 CF 运行时即会红。同时新增 2 个 QueueProcessor 构造测试(Alchemy 接线)。
- **残留(P2)**:仍无独立 `tsc --noEmit`(vitest 走 esbuild 不做完整类型检查);DO `alarm()`/commit-reveal/资金转移逻辑仍缺深度单测(需 mock viem)。见 08。

### P1-3 无 dev/prod 隔离:`deno task dev` 自动加载真实私钥并无条件启动主网队列 ✅ 已修

- **证据**:`dev` task 带 `--env`(加载含真实私钥的 `.env`),`deno/index.ts:82` 无条件 `startQueueWorker()`,其内 `ensureCommitWalletFunded()` 在**每次热重载**都会读主网余额并可能发真实 xDAI 转账。链/合约硬编码,无 DRY_RUN/TESTNET 开关。
- **触发**:开发者在有 `.env` 的机器上 `deno task dev` → 笔记本变成第二个主网签名者,与生产主机争同一对 EOA 的 nonce(两者从同 PRIVATE_KEY 派生同钱包,各自独立 nonce 池)。
- **修复**:`startQueueWorker()` 用 `QUEUE_WORKER` 环境变量**opt-out** 门控(默认开,生产行为不变;`dev` task 设 `QUEUE_WORKER=0`)。实测:`QUEUE_WORKER=0` 打印 "worker DISABLED",默认打印 "Worker started"。读接口两种模式都正常。
- **残留**:dev 仍加载真实 `.env`,手动 POST /api/create 仍可能触链——建议开发用独立 `.env.dev`(未充值/测试网 key)。见 08。

## P2(重要,可带明确缓解延期)

### 本次已修的 P2(6 项)


| 发现                                               | 位置                          | 处置                                                                             |
| ---------------------------------------------------- | ------------------------------- | ---------------------------------------------------------------------------------- |
| CF Worker 缺 gas-price 告警(Deno 有)               | worker/queue-processor.ts:563 | ✅`checkAlerts(config, gasPriceGwei?)` 增加 ⛽ 告警,与 Deno 对齐                 |
| 告警管线在 gas 探测失败时盲区                      | deno/queue.ts:322-345         | ✅ 随 P1-1:gas 失败 return 前先 checkAlerts(idle 空队列无需告警)                 |
| 源码内裸 NUL 字节使 shared/queue.ts 变二进制       | shared/queue.ts:169           | ✅ 换成字节等价的`\0` 转义,hashIp 输出不变(实测)                                 |
| 无启动配置校验(坏 PRIVATE_KEY 崩溃/静默派生错钱包) | deno/config.ts:21             | ✅`isValidPrivateKey` 严格校验,坏 key fail-fast 明确报错;两运行时同修 + 回归测试 |
| 12 处 console.warn 绕过脱敏泄漏 Alchemy key        | deno/queue.ts:337 等          | ✅ 全部改走`shortMsg()`(redactSecrets + 截断);Alchemy 接线后此泄漏更易触发       |
| Telegram 唯一告警通道且完全静默失败                | shared/queue.ts:238           | ✅ catch 与非 2xx 响应都`log.warn`(token 经 redactSecrets 擦除);坏配置可被发现   |
| (附)CF DO 未接 Alchemy 优先写 RPC                  | worker/queue-processor.ts     | ✅ DO 构造函数`setAlchemyRpc`,补 `ALCHEMY_API_KEY` 绑定 + 回归测试               |

### 剩余 P2(14 项,带缓解可延期)

> 这些不阻塞受控上线,但应进入上线后短期整改计划。每条给出**为何可延期**。

1. **CF 三道写闸门在 D1 出错时一起 fail-open**(worker/queue.ts:104-122)。缓解:全局 gas 上限被绕过时,Gnosis 单笔 gas 极低;且 D1 全挂时 enqueue 本身也失败(500)。**权衡是刻意的**(不因 D1 抖动阻塞正常创建)。整改方向:全局上限/背压无法评估时对 create fail-**closed**,仅 per-IP 保持 fail-open。
2. **无 P256 on-curve 校验**(shared/validation.ts:45)。格式合法但不在曲线上的 key 会烧 commit gas 后在 reveal revert→DLQ。缓解:全局 120/分上限 + 隔离机制封顶损失,Gnosis gas 极低。整改:入队前用 @noble/curves 做 on-curve 检查。
3. **chunked/无 Content-Length 请求体无界缓冲 → Deno 单进程内存 DoS**(deno/routes/create.ts:14-35)。缓解:生产在 Cloudflare 之后(边缘限 100MB 并缓冲),systemd MemoryMax=256M + Restart 自愈。整改:按字节上限流式读取 body。
4. **无卡单交易替换/加价路径**(deno/queue.ts:666)。underpriced tx 堵住钱包,重试叠新 tx。缓解:Gnosis 极少拥堵,MAX_GAS_PRICE_GWEI 闸门先挡住高价期。整改:按 nonce 记录 hash,receipt 超时用同 nonce 加价重发。
5. **迁移未版本化且不对称**(worker/queue.ts:59 无迁移,Deno 有临时 ALTER)。缓解:当前 schema 稳定,近期无加列计划。整改:共享 `PRAGMA user_version` 编号迁移。
6. **100MB 缓存上限 > 进程内存预算**(shared/cache.ts:2;Deno 256M / CF 128M isolate)+ estimateSize 低估。缓解:当前全量数据仅 ~845 条记录,离 100MB 极远;近期不会触发。整改:降到 32MB(Deno)/8-16MB(CF)并 env 可调,estimateSize 乘系数。
7. **读放大:读无限流 + 无负缓存 + page 无上界**(deno/routes/query.ts:91)。缓解:读走缓存优先 + 断路器 + 陈旧服务已抑制大部分链读放大。整改:404/空页短 TTL 负缓存,page 上限,读侧轻量限流。
8. **全局写上限 120/分 ≈ 管线排空速率的 2-5 倍**(shared/queue.ts:48),持续满速可把队列推到 10k 背压阈值。缓解:需持续攻击性满速数小时;/api/health 会先 degraded。整改:降到实测排空能力(如 40/分)或 env 可调。
9. **Telegram 是唯一告警通道**(已加日志,但仍单点)。整改:加 OnFailure systemd 直连 Telegram + 外部拨测。
10. **money-path 仅靠 gated 链上 e2e 可测**(deno/queue.ts:278)且文档命令因权限/陈旧路径跑不通。整改:把 viem client 抽成可注入接口做确定性单测(reliability.test.ts 已证此模式)。
11. **CI 单测依赖真实 Gnosis RPC + 链状态**(stats.test.ts/query.test.ts),且每次跑 1000-key perf 测试写库到仓库根。整改:注入 fake client / 把这些移到独立 integration task。
12. **占位测试**:server.test.ts 断言的是已与真实 server 分叉的手抄路由;毒丸隔离测试不测隔离。整改:导出真实 handler 供测试。
13. **部署/回滚 runbook 与实现不符**:健康闸门硬编码端口、substring 'ok' 判断、失败不自动回滚、rollback 在两个最新 release 间来回。已在 `05-deployment-runbook.md` 记录人工规避。整改见 08。
14. **服务宕机结构性不可探测**:全部告警都在被监控进程内,systemd 5 次/60s 后停重试。整改:外部 liveness 监控(独立于进程)。

## P3(债务/优化,36 项)

已修 2 项(NUL 字节归入 P2 表;dead 'committing' 状态与文档漂移见 08)。其余为:双活运行时 nonce 争用(已在 05 加显著警告)、DLQ 无重放端点(runbook 有 SQL)、无备份逻辑(runbook 有建议)、READ_DEADLINE 未在途中强制(最坏 ~20s)、DO 10s vs Deno 60s 节奏未对齐、request_id 未透传到下层、缓存/健康/日志分级等。完整清单与验收标准见 `08-open-issues.md`。

## 上线阻塞判定

修复后,**无未解决的 P0/P1**;剩余均为可带缓解延期的 P2/P3。关键路径(读、写入队、后台 commit-reveal、幂等、降级)已通过单测 + 实机 smoke + 真实链读验证。**唯一未能在本环境验证的是需真实资金的链上写全流程 e2e**(见 05,受 PRIVATE_KEY 门控)。因此结论为 **CONDITIONAL GO**——详见交付说明与前置条件清单。
