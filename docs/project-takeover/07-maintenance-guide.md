# 07 — 维护指南

## 修改的黄金法则

1. **队列状态机只有一份**(2026-07 重构后):资金路径逻辑在 `shared/queue-engine.ts`,改它**必须**让 `deno/tests/queue-engine.test.ts` 假链套件先红后绿。routes 层(`deno/routes/*` ↔ `worker/routes/*`)与两个薄壳(`deno/queue.ts` / `worker/queue-processor.ts` 的 store/告警实现)仍需双边同步——diff 只动一边=红旗
2. **纯逻辑进 shared/**:可单测的决策逻辑(分类、拆分、退避、状态机)放 `shared/`,I/O 留在运行时层——全部快速测试靠这个分层
3. **每个出站调用带超时**:worker 是单飞的;一个无界 await = 整个队列停摆
4. **错误分类优先于错误处理**:新失败模式先问"transient/permanent/poison?",落到 `classifyError`(shared/reliability.ts:179)的模式表里,而不是在调用点写 if

## 高风险区域(按危险度排序)

### ① 队列状态机(shared/queue-engine.ts + 两个 store 薄壳)

回归高发区。git 历史上的事故:重复行毒化整批(→唯一索引)、buildCommitment 抛错炸整轮(→buildCommitmentsSafe)、commit 永不确认无限横跳(→handleFailure 推进 retries)、receipt 超时重发 revert 整批(→reconcileReady)。
**改动前必读** `03-core-flows.md` 的不变量清单。**修改流程**:先在 `queue-engine.test.ts` 用假链写出期望行为(红)→ 改 `shared/queue-engine.ts`(绿)→ 跑全量。store 薄壳(SQL)改动需两运行时同步。真链验证用 e2e.test.ts(花 gas,慎)。
依赖注入接口:`QueueStore`(存储)、`ChainOps`(链,真实现在 `shared/chain-viem.ts`)、`nonces`、`hooks`(告警)。加新链上操作时:接口 + chain-viem 实现 + FakeChain 默认值三处同步。

### ② nonce 管理(shared/nonce.ts;deno/nonce.ts 为薄包装,worker 直接用共享管理器)

只有 ~100 行但极精妙:互斥只包获取;成功=消耗、失败=release→全池重同步。**不要**改成 release 时递减(池里可能已发出更高 nonce)。改动必须过 nonce.test.ts + queue-engine.test.ts 的 nonce 记账断言,并真链验证连续批次。

### ③ 错误分类(shared/reliability.ts)

把 transient 误判成 poison → 无辜项进 DLQ;把 poison 误判成 transient → 毒丸重试 10 次×退避,阻塞吞吐。新增模式串时注意大小写(全部小写匹配)与上下文(rpc-write 的 revert 是 poison,rpc-read 是 permanent)。25 个测试锁行为。

### ④ 脱敏面(防抢跑 + 防泄密)

三处必须同步:`/api/create/:id` 非 done 响应、`/api/query` 队列回退、日志/error 列的 `redactSecrets`。新增返回字段时先问:pending 项的这个字段会帮助抢跑吗?

### ⑤ 校验(shared/validation.ts)

放松任何 hex/长度约束前,想清楚该值会流到哪:ABI 编码(炸批)、SQL(参数化,安全)、日志(已脱敏)、Telegram(注入无害但难看)。

## 安全修改的操作序列

```bash
git checkout -b fix/xxx
# 1. 改 shared/ 或两个运行时同步改
# 2. 补/改测试(先让新测试红,再改绿)
deno task test && npm test && deno check deno/index.ts && deno lint
# 3. 无私钥冒烟(见 02)
# 4. 涉及队列/nonce/链写 → 考虑跑一次 e2e(花 gas)
# 5. PR → CI 绿 → merge → 先部署 CF(便宜秒回滚)观察 → 再部署 Deno
```

## 依赖升级

- viem:锁在 2.47.5。升级需重点回归 `inspect()` 错误结构游走(shared/reliability.ts:113——viem 错误包装层次变了分类就漂移)+ e2e
- wrangler/vitest-pool-workers:dev-only,可随时升(npm audit 的漏洞都在这条链上)
- Deno:`deno task start` 有 `--frozen`,升级 Deno 大版本先本地全量测试
- RPC 端点:增删 `ALLOWED_RPC_HOSTS`(shared/rpc.ts:34)与 `WRITE_RPCS`(rpc.ts:22)。新增主机必须是信誉良好的公共节点——白名单是防第三方列表投毒的唯一防线

## 调参速查(都在 shared/ 常量,改动=发版)

| 想要 | 改 |
|---|---|
| 收紧/放松单 IP 限流 | `DEFAULT_RATE_LIMIT`(shared/queue.ts:41) |
| 控制 gas 总预算 | `DEFAULT_GLOBAL_WRITE_LIMIT`(:48)、`MAX_GAS_PRICE_GWEI`(:49) |
| 队列吞吐 | `TX_BATCH_SIZE`(:39)、`CREATE_SUB_BATCH`(:57)、`WORKER_INTERVAL`(:37,Deno)/`ALARM_INTERVAL`(worker/queue-processor.ts:46,CF) |
| 缓存 | `DEFAULT_CACHE_TTL`/`DEFAULT_MAX_MEMORY_BYTES`(shared/cache.ts:1-2) |
| 降级阈值 | shared/routes/health.ts:17-22 |

## 测试策略

- 单元/集成(不触网):`deno task test`+`npm test`,PR 必须全绿
- 纯逻辑优先:新队列行为先写成 shared/ 纯函数测试
- e2e(真链、花 gas、门控):大改队列/nonce/合约交互后手动跑
- 禁止:为过测试放宽校验、删测试、mock 掉分类逻辑
