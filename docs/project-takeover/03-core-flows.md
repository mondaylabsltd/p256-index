# 03 — 核心流程与业务规则

> 引用均为 commit `113a8c6` 的 `文件:行号`。

## 流程 1:创建公钥记录(最重要的写路径)

入口:`deno/routes/create.ts:13` / `worker/routes/create.ts:13`(两者镜像)。

1. **体积门**:Content-Length 与实际体 > 32KB → 413(`create.ts:11-19,32-35`)
2. **必填**:rpId/credentialId/publicKey/name(`create.ts:44`)
3. **格式校验**(`shared/validation.ts`):长度上限;publicKey 必须 `04+128hex`(未压缩 P256);walletRef 必须 32 字节;metadata 必须字节对齐 —— 这些是**队列毒丸防线**:不合格数据一旦入队,会在 ABI 编码时炸掉整个批次
4. **限流**:IP 取 `cf-connecting-ip`(CF 注入,不可伪造)→ `x-forwarded-for[0]`(可伪造,仅公平性参考)→ `x-real-ip`;单 IP 5 次/分。**真正防 gas 燃烧的是全局上限**:全表 60s 窗口 ≥120 条 → 503(`shared/queue.ts:42-48`)
5. **walletRef 绑定**:服务端从 publicKey 确定性推导(Safe 代理地址,`shared/wallet-ref.ts:106`);客户端传入必须一致,否则 400 —— 防止把记录绑到他人地址(`create.ts:74-82`)
6. **幂等**:缓存/链上已存在 → 201 + 完整记录;队列已有活跃行 → 202 + 原 id
7. **背压**:活跃队列 ≥10000 或全局限流 → 503 + Retry-After(fail-open:统计失败时放行)
8. **入队** → 202 `{id, status:"pending"}`

### 关键防线:链上预查失败不能拒绝创建

`create.ts:96-106`:hasRecord 预查只是快速路径;链不可达时**跳过预查继续入队**,由后台 reconcile 收敛。历史上这里曾把 D1/链抖动放大成 500(见 git 9dfb161)。

## 流程 2:后台队列(最难改、最易回归的部分)

> **2026-07 重构**:队列状态机已从两份手工同步的分叉统一为**单一实现** `shared/queue-engine.ts`(`runQueueCycle` + 各阶段函数),依赖(存储/链/nonce/告警钩子)全部注入。真实链适配在 `shared/chain-viem.ts`,nonce 池在 `shared/nonce.ts`。运行时只剩薄壳:Deno(`deno/queue.ts`,60s 单飞 setInterval + SQLite store)、CF(`worker/queue-processor.ts`,DO alarm 10s 永远重新武装 + cron 兜底 + D1 store)。整个资金状态机由 `deno/tests/queue-engine.test.ts` 的 19 个假链确定性测试锁定(无网络、注入时钟)。

每轮顺序(两边一致):

```
0. 无待处理 → 只做清理,跳过一切 RPC(省钱省调用)
1. gas 价检查:>0.1 Gwei → 本轮跳过(告警),防高价期烧钱
2. processCreating   — 遗留 'creating' 行对账(滚动升级安全网)
3. processCommitted  — commit 已上链且过 1 块 → reconcile → batchCreateRecord → done
4. processPending    — batchCommit → committed
5. 清理(done>7天、failed>30天)+ 告警检查
```

### 失败处理的不变量(改动前必须理解)

- **分类**(`shared/queue.ts:147` → `shared/reliability.ts:179`):写路径 revert=poison,RPC 4xx=transient(轮转端点),超时/网络=transient
- **transient** → `handleFailure` 指数退避(5s×3^n,上限 12h),≥10 次 → `EXHAUSTED:` 入 DLQ
- **poison** → 立即 `POISON:` 入 DLQ,**决不重试**
- **批失败隔离**:batch revert 时逐项重估/单发,让元凶入 DLQ、无辜项通过(`shared/queue-engine.ts` isolatePoisonCreate);批内互相冲突(如两条同 walletRef)也能收敛——顺序单发,后者 revert 被隔离
- **reconcile 先于重发**(`shared/queue-engine.ts` reconcileReady):receipt 超时但 tx 实际落链的情况,重发会 RecordAlreadyExists 炸整批;所以发送前先 hasRecord 多播,已在链上的直接 done
- **幂等唯一索引**:`idx_queue_active_unique (rpId,credentialId) WHERE status!='failed'`(`shared/queue.ts:87`);并发同键 INSERT 输者返回已有活跃行 id
- **nonce**:成功=消耗,失败=release→下次强制链上重同步(`deno/nonce.ts:66-91`)。不要"聪明地"改成递减——池里可能已发出更高 nonce

### 崩溃一致性

进程在任何点被杀都安全:状态推进只在**收到成功 receipt 后**落库;丢 receipt 的情况由 reconcile 收敛;commit 落链但库仍 pending 的情况,重发 batchCommit 无害(commitment 幂等,只是多花一点 gas)。

## 流程 3:查询

`deno/routes/query.ts` / `worker/routes/query.ts`(镜像):

- 缓存键防碰撞:`cacheKey()` 对各段 percent-escape,防 `rpId="x:a"` 与 `credentialId="a:b"` 的键替换攻击(`shared/cache.ts:88`)
- 链读失败 → 有 ≤1h 陈旧缓存则 200+`X-Served-Stale: true`+`Cache-Control: no-cache`,否则 503+Retry-After —— **决不把链故障误报为 404**(`shared/contract-read.ts:119-123` 注释是铁律)
- 链上无记录 → 查队列回退,**脱敏**返回(无 credentialId/walletRef/initialCredentialId)防抢跑

## 流程 4:commit-reveal 为什么存在

链上合约要求先提交 `keccak256(所有字段)` 承诺,过 ≥1 块后才能 createRecord。目的:防止 mempool 观察者抢先用相同 (rpId,credentialId) 注册。服务侧配合的脱敏点:

1. `GET /api/create/:id` pending/committed 时不返回 credentialId/walletRef(`create.ts:149-172`)
2. `GET /api/query` 队列回退同样脱敏
3. 双钱包分离(commit 钱包由 PRIVATE_KEY 哈希派生),链上观察者难以将 commit 与 reveal 关联

**已知残余暴露**(设计权衡,见 04 审计):pending 响应仍含 publicKey,而 walletRef 可由 publicKey 公开算法推导;且服务不验证注册者持有 P256 私钥(旧 release 分支曾有断言签名验证,main 移除)。攻击者若知道受害者 publicKey 可直接上链抢注 walletRef 槽位——这属于合约层约束,服务层无法完全防御。

## 隐含约束(不成文但破坏即事故)

1. **队列状态机只有一份**(`shared/queue-engine.ts`)——改它必须过 `queue-engine.test.ts` 假链套件。routes 层(`deno/routes/*` ↔ `worker/routes/*`)仍是镜像,改一边必须同步另一边
2. **`creating` 状态不能删**:虽无新写入,是滚动升级安全网(`shared/queue-engine.ts` processCreating 注释)
3. **错误字符串前缀是操作接口**:`POISON:`/`EXHAUSTED:` 被运维流程依赖(DLQ 分诊)
4. **所有出站调用必须有超时**:Telegram 5s、RPC 10s、nonce 同步 5s、receipt 60s——单飞 worker 里任何无界 await 都会卡死整个队列
5. **`markHealthy` 必须在读成功时调用**:断路器靠它秒级恢复(`shared/contract-read.ts:77`)
6. **测试注入点**(`_setRateLimitForTest` 等下划线函数)只允许测试使用
