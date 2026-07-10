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

## P2/P3 全量整改(2026-07-10)——上线运营者硬性要求驱动

运营者指令:**用户绝不能因本服务创建不了账户;任何需开发者干预的情况(代码bug/需充钱)必须到 Telegram;健壮性与性能做到最好。** 据此把 08 的 P2×14 + P3 全部整改,并经两轮多智能体对抗审查(第一轮 27 确认含 1 P0 + 6 P1,第二轮验证修复)。

### 可用性 / 用户永不被本服务挡住
- **P0(修复中引入并当场修掉)**:负缓存哨兵 `NOT_FOUND` 曾被 create 快速路径当作已存在记录返回 201「done」→ **静默丢弃用户创建**。已修:`cached && cached !== NOT_FOUND` 双运行时;哨兵也不会被当陈旧记录体返回;回归测试钉住。
- on-curve P256 校验:格式合法但不在曲线上的 key 入队前 400(否则烧 commit gas 后 reveal revert 进 DLQ)。
- 流式 body 限制(shared/body.ts):chunked/无 Content-Length 请求不再无界缓冲(内存 DoS)。
- 负缓存 + page 上界 + 每 IP 读限流(shared/read-limit.ts,fail-open):抑制读放大;但**读路径仍先查缓存、再查队列**,刚入队的 create 永远可见(walletRef 路径也补了队列回退)。
- CF 三道写闸门 fail-open 是**明确的可用性优先决策**(D1 抖动绝不挡创建),并记日志可见。

### 告警完整性(见 06 覆盖矩阵)
- 引擎钩子 `ItemFailureInfo{terminal,poison}` + `AlertReason` + `onStuckTx`:**终态 DLQ 隔离(代码bug/耗尽重试)即时告警**;空闲周期也跑告警(钱包被掏空立即发现);连续 gas 失败/cycle 抛错/DO alarm 抛错/无签名有排队/卡死 nonce 均有专用 Telegram 页;终态节流有补发不丢计数;Telegram 未配置会记一次日志 + `/api/health` 暴露 `telegramConfigured`;systemd OnFailure 单元在进程死后进程外直连 curl 告警。

### 资金路径健壮性(卡单自愈,不需人工)
- **卡单交易自动解堵重写**:以**链上已确认 nonce** 为唯一真相(不再依赖记录的 hash——旧版会产生永不清除的僵尸行饿死 sweep)。nonce < 已确认 → 删行(僵尸免疫);nonce >= 已确认且超时 → 同 nonce 递增 gas(150%/200%/…,**上限 MAX_GAS_PRICE_GWEI**)自转账替换;≥5 次仍不清 → onStuckTx 告警。空闲周期也解堵。ledger 读写用 safeRecord/safeDelete 包裹,绝不把成功广播错误地打入失败路径。43 个假链测试覆盖(含僵尸/递增/封顶/告警/空闲/读失败)。
- 版本化迁移(shared/migrations.ts,schema_migrations):INSERT OR IGNORE 并发冷启动安全;DO 首 cycle 前 ensureMigrated;worker init 记忆化 promise 失败可重试;D1 瞬态分类排除 constraint/duplicate-column。

### 配置 / 运维
- 缓存预算 32MB(CF 8MB)+ ×2 系数 + env 可调;全局写上限 120→40 + env;LOG_LEVEL;派生 IP 盐(不再用原始私钥);优雅停机(SIGTERM 排空);DO ping 仅在 create 时触发。
- deploy:健康闸门读远端 PORT + JSON status + **失败自动回滚到 last-known-good 并验证** + 记录实际 live 版本 + 失败 exit 1;systemd 用 sudo 安装;Deno 钉 v2.7.5;Restart=always;OnFailure 告警单元;alert 单元 EnvironmentFile 可选。
- CI:worker tsc 严格类型检查 + vitest;触网/perf 测试门控(RUN_LIVE_TESTS/RUN_PERF),默认套件全离线。
- 测试质量:server.test.ts 改测真实 handler(deno/handler.ts);wrangler.jsonc 成为入库唯一配置(可复现);迁移幂等 + 遗留库升级测试。

**当前测试:deno 189/0(15 门控忽略),vitest 28,tsc 严格,deno check —— 全绿。**

## 2026-07-10(下午)— 上线部署 + 外部拨测/心跳/CONFLICT 整改

**背景**:发现生产双运行时仍跑 6 月初旧版(VPS release 20260605、CF worker 2026-06-04 部署)——两轮整改的代码从未上线;CF worker 承接真实流量(getvela.app 等,D1 30 条 done),且 D1 DLQ 有 2 条 POISON(getvela.app 用户 2026-07-03 实际创建失败,根因 `WalletRefAlreadyExists`:同一把 passkey 曾以 rpId=localhost 注册)。

**处置(全部完成)**:
- 双运行时部署到 main(worker `wrangler deploy` + VPS 健康闸门部署,迁移 v1-v3 生效);**真实资金 e2e 双端上链 done**(worker `0x05a5…fa0b`、VPS `0x1033…c728`)→ CONDITIONAL GO 的 e2e 前置项关闭。
- **双 key 隔离确认**:VPS create 钱包 `0xb8f1…06cE` ≠ worker `0xc870…46da`,nonce 冲突不存在 → 第二个前置项关闭。
- **外部拨测内建**(第三个前置项关闭):CF worker 每分钟 cron 拨测 VPS `/api/health`(shared/watchdog.ts 纯决策 + worker/watchdog.ts 接线 + 迁移 v4 `watchdog_state`),3 连败页呼/30min 重呼/恢复✅/每日摘要。
- **CONFLICT 用户冲突分类**:API 层 walletRef 双重预检(队列+链上,fail-open)→ 409;引擎 `WalletRefAlreadyExists` → `CONFLICT:` 隔离**不页呼**;`RecordAlreadyExists` revert → 视为已上链标 done。DLQ 处置:getvela 行改标 CONFLICT,diag.example 合成垃圾行删除。
- **每日心跳**(Deno):余额+runway 估算+队列+DLQ+release,启动首轮即发(兼部署确认);告警通道静默变得可察觉。
- 测试:引擎 49(+4 CONFLICT 语义)、watchdog 8、heartbeat 4、create 409 5、vitest 30(+2 watchdog 接线)。

## 剩余 P2(上线后短期整改;上线可带缓解延期)

> 原 P2-1…P2-16 已全部在 2026-07-10 上午的 P2/P3 全量整改中关闭(见上节);外部拨测/真实 e2e/双 key 隔离三个人工前置项已于下午关闭。以下为当前仍真实存在的事项。

| # | 问题 | 缓解/现状 | 验收标准 |
|---|---|---|---|
| R-1 | Cloudflare 平台宕机时 watchdog 与 worker 同时失联(拨测盲区) | 每日心跳/摘要缺席可在一天内察觉 | 可选:UptimeRobot 等三方同时拨 VPS 域名 + workers.dev 两个入口 |
| R-2 | DLQ 无重放端点(仅手工 SQL) | runbook 有 SQL;CONFLICT 类已不需重放 | `scripts/dlq.ts` 列表/重放/删除子命令 |
| R-3 | VPS queue.db 无定期备份 | 链上是权威源,丢库仅失未上链排队项;D1 有 Time Travel | cron 每小时 `sqlite3 .backup`(runbook 已给命令) |
| R-4 | `isContractRevert` 裸子串匹配 `includes("revert")` | 触发概率低 | 改走结构化 classifyError |
| R-5 | publicKey 长度上限 130 拒绝 `0x` 前缀形式(e2e 中实测) | 客户端不带前缀即可;错误信息明确 | 放宽到 132 并在入口归一化去前缀 |
| R-6 | wrangler v3.114(v4 可用)、compatibility_date 2024-09-23 | 功能正常,仅陈旧 | 升级并回归 vitest |
| R-7 | CONFLICT 行计入 health `queue.dlq` → 25 条即 degraded | 冲突极少;可见性优先 | 如成噪声,health 统计排除 CONFLICT 行 |
| R-8 | request_id 未透传到队列/RPC 下层日志 | 顶层日志已可关联大多数问题 | logger 支持 per-request 上下文 |
| R-9 | `/api/challenge` 装饰性(从不验证) | 开放 API 设计使然 | 文档标注或删除 |

## 优先级建议(2026-07-10 修订)

1. **已全部完成**:~~真实资金 e2e~~、~~双活 key 隔离确认~~、~~外部 liveness 拨测~~ —— CONDITIONAL GO 的三个人工前置项全部关闭,**服务处于 GO 状态**。
2. **上线后 1-2 周**:R-3(备份 cron,5 分钟工作量)、R-2(DLQ 工具)、R-5(0x 前缀放宽)。
3. **择机**:R-1(三方拨测)、R-4/6/7/8/9。