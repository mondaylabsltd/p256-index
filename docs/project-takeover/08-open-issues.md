# 08 — 未决事项

> 基线 commit `113a8c6`。本次接管修复见"已关闭"节;剩余按优先级列出,含验收标准。完整证据见 `04-production-readiness.md`。

## 已关闭(本次接管修复 + 回归测试)

| # | 严重度 | 问题 | 修复 | 验证 |
|---|---|---|---|---|
| 1 | P1 | 写路径无 RPC 健康追踪 + gas 检查失败告警盲区 | markFailed/markHealthy 接入 gas 检查;失败前先 checkAlerts;CF 同修 | rpc.test.ts 新增 Alchemy 轮转测试;149/28 全绿 |
| 2 | P1 | CF Worker 零 CI(资金 DO 不测/不类型检查) | ci.yml 新增 worker job(npm ci + npm test) | 本地 28 tests 绿;CI 新 job 已配置 |
| 3 | P1 | 无 dev/prod 隔离(dev 自动启动主网 worker) | QUEUE_WORKER opt-out 门控,dev task 设 0 | 实测 on/off 两态 |
| 4 | P2 | CF 缺 gas-price 告警 | checkAlerts 增 ⛽ 告警,与 Deno 对齐 | vitest 编译通过 |
| 5 | P2 | 源码裸 NUL 字节 | 换 `\0` 转义(字节等价) | hashIp 输出实测不变;security/log 测试绿 |
| 6 | P2 | 无启动配置校验(坏 PRIVATE_KEY) | isValidPrivateKey fail-fast,两运行时 | config.test.ts 新增 |
| 7 | P2 | 12 处 console.warn 泄漏 Alchemy key | 全改走 shortMsg(redactSecrets) | grep 确认 0 裸 err.message |
| 8 | P2 | Telegram 静默失败 | catch + 非 2xx 都 log.warn | check/test 绿 |
| 9 | — | CF DO 未接 Alchemy 写 RPC | DO 构造 setAlchemyRpc + ALCHEMY_API_KEY 绑定 | worker.test.ts 新增 2 测 |

修改文件:`shared/{queue,rpc}.ts`、`deno/{config,index,queue}.ts`、`deno.json`、`worker/{config,index,queue-processor,types}.ts`、`.github/workflows/ci.yml`、`.env.example`、`scripts/cf-setup.sh`、`README.md`、`deno/index.html`(README 同步)、`deno/tests/{rpc,config}.test.ts`、`worker/tests/worker.test.ts`。

## 剩余 P2(上线后短期整改;上线可带缓解延期)

| # | 问题 | 位置 | 负责条件 | 验收标准 |
|---|---|---|---|---|
| P2-1 | CF 三道写闸门 D1 出错一起 fail-open | worker/queue.ts:104-122 | 需权衡"D1 抖动不阻塞创建" vs "滥用防护" | 全局上限/背压无法评估时 create fail-closed(429/503),per-IP 保持 fail-open;补测试 |
| P2-2 | 无 P256 on-curve 校验 | shared/validation.ts:45 | 引入 @noble/curves 依赖 | 非曲线点 key 入队前 400;补边界测试 |
| P2-3 | chunked body 无界缓冲内存 DoS | deno/routes/create.ts:14-35 | — | 按字节上限流式读取;或缺 Content-Length 且超限即拒;补测试 |
| P2-4 | 无卡单交易加价重发 | deno/queue.ts:666 | 需真链验证 | receipt 超时按同 nonce 加价重发;链上验证不再堆叠 |
| P2-5 | 迁移未版本化/不对称(CF 无迁移) | worker/queue.ts:59 | — | 共享 PRAGMA user_version 编号迁移;加列在两运行时都生效 |
| P2-6 | 缓存 100MB > 进程预算 | shared/cache.ts:2 | — | 降到 32MB(Deno)/8-16MB(CF)且 env 可调;estimateSize 乘系数 |
| P2-7 | 读放大(无限流/无负缓存/page 无上界) | deno/routes/query.ts:91 | — | 404/空页短 TTL 负缓存;page 上限;读侧轻量限流 |
| P2-8 | 全局写上限 > 排空速率 | shared/queue.ts:48 | 需实测排空能力 | 上限 ≤ 实测排空速率或 env 可调 + 文档 |
| P2-9 | 告警单通道(已加日志仍单点) | shared/queue.ts | — | OnFailure systemd 直连 Telegram + 外部拨测 /api/health |
| ~~P2-10~~ | ~~money-path 仅链上 e2e 可测~~ | — | **✅ 已关闭(2026-07 队列引擎重构)**:状态机统一到 `shared/queue-engine.ts`(依赖注入),`deno/tests/queue-engine.test.ts` 31 个假链测试覆盖 commit-reveal/毒丸隔离/reconcile/退避/EXHAUSTED/nonce 记账/子批切片/索引对齐/清理边界 | — |
| P2-11 | CI 依赖真实 RPC/链状态 + 每次跑 1000-key perf | deno/tests/stats.test.ts:9 | — | 注入 fake client;perf 移到 env 门控;CI 不触网 |
| P2-12 | 占位测试(server.test.ts 分叉副本;毒丸测试不测隔离) | deno/tests/server.test.ts:33 | — | 导出真实 handler 供测试;隔离已由 queue-engine.test.ts 真正断言,server 副本仍待处理 |
| P2-13 | 部署/回滚 runbook 与实现不符 | scripts/deploy.ts:276-288 | — | 健康闸门读远端 .env 端口 + JSON status 判断;失败自动回滚;rollback 接受目标 tag |
| P2-14 | 服务宕机结构性不可探测 | systemd unit:20-21 | — | 外部 liveness 监控(独立进程) |
| P2-15 | 无独立 tsc 类型检查(vitest 走 esbuild 不做完整检查) | (无 tsconfig) | — | 加 tsconfig + `tsc --noEmit` CI 步骤,或 `wrangler deploy --dry-run` |
| ~~P2-16~~ | ~~DO alarm/commit-reveal/资金转移逻辑缺深度单测~~ | — | **✅ 大部关闭(同上重构)**:DO 的 processQueue 主体=共享引擎,已被假链套件覆盖;仅 DO 壳(alarm 重武装/checkAlerts/充值)仍靠 vitest 编译+构造测试 | — |

## 重构后对抗审查追认(2026-07,queue-engine 统一重构)

多智能体审查(4 视角 + 反驳式验证)对重构 diff 产出 20 条确认/0 驳回。处置:

- **P2 端点亲和性回归 ✅ 已修**:重构初版让 estimate/send/receipt 各自解析 RPC 端点(轮转推进 → 发送与回执轮询跨节点 → 假超时 → 重复 batchCommit)。修复:引擎每阶段调 `chain.beginPhase()`,`shared/chain-viem.ts` 按阶段 memo 端点/钱包客户端;reconcile 多播改走 create 钱包客户端(`via:"wallet"`,与后续 send 同端点、同 8s×1 预算)——恢复重构前结构。由引擎测试 `beginPhaseCalls===3` 与 `via==="wallet"` 断言钉住。
- **追认第 5 个有意 delta**:`hashIp` 分隔符空格→`\0`(消除 salt/ip 歧义)。副作用:部署瞬间所有既存 IP 哈希失配 → D1 `rate_limits` 老行不再命中,**每客户端限流窗口一次性重置**(短暂超额放行,60s 窗口内自愈);create_queue 的 ip 溯源列跨部署不可比。已接受。
- **其余 P3**:reconcile 预算差异已随亲和性修复一并恢复;QUEUE_WORKER/PRIVATE_KEY 校验/Telegram 日志为本 session 已文档化的有意修复,追认;12 个测试缺口(子批切片、break/continue、隔离后索引对齐、nonce 角色、清理边界、commit 隔离、getBlockNumber 中止、retryAfter 门控、fresh-creating 等)已全部按审查 sketch 补齐 → 引擎套件 31 个测试。

## 剩余 P3(债务/优化,择机)

- **双活运行时 nonce 争用**:Deno + CF 同 PRIVATE_KEY 并发 → nonce 冲突。**已在 `05-deployment-runbook.md` 加显著警告**。根治:不同 key 或只跑一个。(`deno/nonce.ts:23`)
- **DLQ 无重放端点**:仅手工 SQL(runbook 有)。可加 `scripts/dlq.ts` 或受保护端点。(`shared/queue.ts:54`)
- **无队列库备份**:runbook 有 sqlite `.backup` / D1 Time-Travel 建议。(`scripts/deploy.ts:153`)
- **READ_DEADLINE(12s)未在途中强制**:单次 attempt 起于 t=11.9s 仍可跑满 10s → 最坏 ~20s+。传 AbortSignal 到 viem transport。(`shared/contract-read.ts:26`)
- **isContractRevert 是裸子串匹配** `includes("revert")`:含"revert"字样的非 revert 错误会被误判成 404。触发概率低但应改用结构化 `classifyError`。(`shared/contract.ts:213`)
- **DO 10s vs Deno 60s 节奏未对齐**:CF 每 10s 跑 gas RPC + D1 计数 + 每请求一个 DO 子请求。(`worker/queue-processor.ts:46`)
- **request_id 未透传到下层**:handler/queue/RPC 日志不带 request_id,无法关联。(`shared/log.ts:28`)
- **/api/health 单一 degraded 桶**:队列深/DLQ/卡单/统计读失败混在一起;始终 HTTP 200。(`shared/routes/health.ts:24`)
- **dead code**:`committing` 状态(无读写)、`getHealthyRpc/failover/isHealthy/Deadline/withDeadline`(无生产调用者)。(`shared/queue.ts:13`, `shared/rpc.ts:229`)
- **/api/challenge 装饰性**:从不验证(开放 API 设计);可删或文档标注。(`shared/routes/challenge.ts:1`)
- **文档漂移**:README "69 tests"(实际 146)、/api/health 示例缺 degraded/queue 字段、walletRef 描述与实现不符;项目 CLAUDE.md 列了 4 个未用依赖(@noble/*、s3-lite-client、@db/sqlite)。(`README.md:342`)
- **wrangler 配置漂移**:真正用的 `wrangler.json` 被 gitignore(setup 脚本生成),提交的 `wrangler.jsonc` 是死配置(空 database_id)。生产 CF 配置不可从仓库复现。(`package.json:8`)
- **版本固定缺口**:~~CI Deno 浮动 v2.x~~(已钉到 v2.7.x,与 02 验证环境同 minor);生产 Deno 首次安装 unpinned-latest;compatibility_date 2024-09-23 约 21 月龄。
- **IP 哈希盐 = 原始 PRIVATE_KEY**:密钥卫生问题;空 key 时回退公开常量,64 位截断可暴力破解。(`deno/index.ts:20`)
- **无优雅停机**:SIGTERM(每次部署)杀掉 mid-batch worker → 广播 commit tx 重发多花 gas;in-flight HTTP 丢弃。(`deno/index.ts:82`)
- **dev 仍加载真实 .env**:手动 create 仍触链;建议独立 `.env.dev`(未充值/测试网 key)。
- 其余可观测性/性能优化(日志分级、缓存内存核算、DO 冷启动重跑 DDL 等)见 `04` P3 段。

## 优先级建议

1. **上线前(CONDITIONAL GO 前置)**:见交付说明——用真实资金跑一次链上写 e2e;确认双活运行时的 key 隔离策略;配置外部 liveness 拨测。
2. **上线后 1-2 周**:P2-1(fail-closed)、P2-2(on-curve)、P2-13(回滚脚本)、P2-15(tsc)。
3. **上线后 1 月**:P2-6/7/8(缓存/读放大/写上限调参)、P2-10/11/12(测试质量)。
4. **持续**:P3 债务清理。
