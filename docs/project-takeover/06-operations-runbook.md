# 06 — 运维 Runbook

## 日志

- 格式:每行一个 JSON(`shared/log.ts`),可按字段查询:`dependency`、`operation`、`outcome`、`error_category`、`latency_ms`、`job_id`、`request_id`
- 脱敏:`redactSecrets` 擦除 RPC URL 中的 API key(`/v2/<key>`)、Telegram bot token、`?key=`/`?token=` 等查询参数;私钥类字段名整体 `[redacted]`。序列化后再擦一遍(纵深防御)
- Deno:journald(`journalctl -u webauthnp256-publickey-index -f`);CF:`npx wrangler tail` / Dashboard(wrangler.json 中 `logs.enabled=true, invocation_logs=true`)
- 关联:每个请求有 `X-Request-Id` 响应头,同 id 出现在日志与 500 响应体

## 健康与监控

`GET /api/health`(便宜,纯本地状态,不打链):

```json
{"status":"ok|degraded","rpcCircuit":"closed|open","queue":{"depth":N,"dlq":N,"oldestJobAgeMs":N}}
```

| 信号 | 阈值(`shared/routes/health.ts:17-19`) | 含义/处置 |
|---|---|---|
| `status:"degraded"` | depth≥2000 或 dlq≥25 或 oldest≥30min | 见下方分诊 |
| `rpcCircuit:"open"` | 所有读 RPC 冷却中 | 链/RPC 面故障;读走陈旧缓存;通常 60s 内自愈(半开探测 5s 一次) |
| `queue.dlq > 0` | — | 有 POISON/EXHAUSTED 项,需人工分诊(见 DLQ) |
| queue stats 读取失败 | — | 返回 degraded + `queue:{error}`:数据库有问题 |

**当前没有指标系统(Prometheus 等)**。外部拨测已内建(2026-07-10):**CF Worker 的每分钟 cron 从 Cloudflare 独立基础设施拨测 VPS 的 `/api/health`**(`worker/watchdog.ts`,决策逻辑 `shared/watchdog.ts`),连续 3 次失败 → Telegram 页呼,持续宕机每 30 分钟重呼,恢复时发 ✅;每日一条 watchdog 摘要(VPS 状态 + worker 队列 + `telegramConfigured` 哨兵)。拨测目标可用 `WATCHDOG_TARGET_URL` 变量覆盖。状态存 D1 `watchdog_state`(迁移 v4),D1 故障时退化为 isolate 内存节流。

## Telegram 告警覆盖矩阵(2026-07 整改后)

**设计原则(运营者指令):任何需要开发者干预的情况——代码 bug 或需要充钱——必须到 Telegram。** 空闲周期也跑告警检查(节流 5 分钟),钱包被掏空不再等到下一个用户 create 才被发现。

| 条件 | 含义 | 告警 | 节流 |
|---|---|---|---|
| 🚨 POISON 入 DLQ | **代码/数据 bug**,该 create 永不完成 | 即时(聚合) | 60s |
| 🚨 EXHAUSTED 入 DLQ | 故障期耗尽 10 次重试 | 即时(聚合) | 60s |
| 🪫 create 钱包余额低 | **需要充钱** | checkAlerts(含空闲) | 5min |
| 🪫 无法自动充值 commit 钱包(主钱包太穷) | **需要充钱** | checkAlerts + 启动时 | 5min |
| ⚠️ 自动充值交易失败 | 检查余额/RPC | checkAlerts | 5min |
| ⛽ gas 价超限队列暂停 | 等待或调参 | checkAlerts(两运行时) | 5min |
| ⚠️ 队列积压 ≥100 | 排水跟不上 | checkAlerts | 5min |
| 🔴 DLQ 数量变化 | 有新失败 | checkAlerts | 5min |
| 🔌 写 RPC 连续 ≥3 轮不可达 | creates 不在处理 | 专用告警 | 5min |
| 🛑 队列 cycle 卡死 >3min | worker 停摆 | 专用告警 | 3min |
| 🛑 systemd 单元 FAILED(进程死/重启限流) | 服务下线 | **OnFailure 单元直连 curl**(进程外!) | — |
| 每累计 10 次非终态 tx 失败 | 抖动异常多 | 批量告警 | 按次数 |
| Telegram 自身投递失败 | 告警通道坏 | `log.warn`(journald 可见)+ 每日心跳缺席可察觉 | — |
| 🔴 VPS `/api/health` 连续 3 次拨测失败 | **主机/进程/网络级宕机**(进程内告警发不出的类别) | **CF watchdog**(进程外!) | 30min 重呼 + 恢复✅ |
| 💓 每日心跳(Deno) | 余额+runway+队列+DLQ+release;**心跳停发 = 有问题** | 每日一条(启动后首轮即发,兼作部署确认) | 24h |
| 💓 每日 watchdog 摘要(CF) | watchdog/worker 存活证明 + VPS 状态 + `telegramConfigured` 哨兵 | 每日一条 | 24h |

**CONFLICT 例外(2026-07-10 起)**:`WalletRefAlreadyExists`(同一把 passkey 公钥已在别的凭据下注册,如 2026-07-03 getvela.app 实际故障——该 key 曾以 rpId=localhost 注册)是**用户输入冲突,不是代码 bug 也不是没钱**——终态进 DLQ、状态端点可见(`CONFLICT:` 前缀),但**不页呼开发者**,也不计入"永久失败需人工干预"计数。API 层同时有前置拦截:双运行时 create 路由对 walletRef 做队列+链上双重预检,冲突直接 409(fail-open,引擎隔离兜底)。`RecordAlreadyExists` revert 则直接视为"已上链"标 done(revert 本身就是存在证明)。

CF 侧:同矩阵(OnFailure 除外——平台自管进程;DO alarm 停摆由每分钟 cron 重新武装兜底)。

**卡单交易自动解堵(不再需要人工)**:每笔广播记入 `pending_txs` 账本;>2min 无回执的交易被同 nonce、150% gas 的自转账 cancel 替换,自动解除钱包 nonce 堵塞。日志 `stuck tx replaced with same-nonce cancel` 可查;若反复失败会持续以更新价重试并留在账本。

## 常见故障分诊

### 1. create 一直 pending / oldestJobAgeMs 增长

```bash
journalctl -u webauthnp256-publickey-index --since "10 min ago" | grep -E "queue|gas|nonce"
```

- `Gas price too high ... queue paused`:gas >0.1 Gwei,等待或调 `MAX_GAS_PRICE_GWEI`(shared/queue.ts:49,需发版)
- `Cannot fund commit wallet` / `balance low`:给 create 钱包充 xDAI(地址见告警或日志)
- `queue cycle still running — possible stall`(>3min):看是哪个 await 卡住;所有外呼有超时,通常自愈;连续出现则重启服务
- RPC 全挂:`rpcCircuit:"open"`,等自愈;持久则检查 `ALLOWED_RPC_HOSTS`(shared/rpc.ts:34)里的端点是否集体失效

### 2. DLQ 有货(dlq>0)

```sql
-- Deno: sqlite3 /opt/webauthnp256-publickey-index/data/queue.db
-- CF:  npx wrangler d1 execute webauthnp256-queue --command "..."
SELECT id, rpId, substr(error,1,80), retries, datetime(updatedAt/1000,'unixepoch')
FROM create_queue WHERE status='failed' ORDER BY updatedAt DESC LIMIT 20;
```

- `POISON: ...`:确定性失败(合约 revert / 数据坏)。**先修根因**(常见:walletRef 槽位已被占 WalletRefAlreadyExists、记录已存在但对账前被判毒)。修完重放:
  ```sql
  UPDATE create_queue SET status='pending', retries=0, retryAfter=0, error='' WHERE id='<id>';
  ```
- `EXHAUSTED: ...`:transient 重试 10 次耗尽(长时间链故障)。链恢复后直接重放(同上 SQL)
- `superseded-duplicate`:迁移期去重产物,无需处理
- 重放前**不要删行**:活跃唯一索引会拦住同键新建,重放旧行即可

### 3. 查询 404 但用户声称已创建

1. 先看 `/api/create/:id`(id 在创建响应里)——若 failed 见 DLQ 分诊
2. 直接链上核对:`cast call 0xdd93…e9c3 "hasRecord(string,string)(bool)" <rpId> <credentialId> --rpc-url https://rpc.gnosischain.com`
3. 链上有而 API 404:缓存问题(等 5min TTL)或 RPC 读故障(看 rpcCircuit)

### 4. 429 / 503 投诉

- 429:单 IP 5 次/分,正常保护;通过 CF 时取的是 `cf-connecting-ip`(真实客户端)
- 503 + `service busy`:背压(depth≥10000)或全局写入 ≥120/分——查 depth;若是攻击性流量,这正是设计行为(护住 gas)
- 503 + Retry-After(query):链不可达且无可用缓存;看 rpcCircuit

### 5. 内存

Deno 侧 systemd `MemoryMax=256M`,进程内缓存上限 100MB(近似 LRU)。OOM 表现为 systemd 频繁重启:`systemctl status` 看 `Restart counter`。缓解:降低 `DEFAULT_MAX_MEMORY_BYTES`(shared/cache.ts:2,需发版)或提高 MemoryMax。

## 数据备份(当前缺失,接管后应尽快落实)

建议(Deno 侧):cron 每小时 `sqlite3 queue.db ".backup /backup/queue-$(date +%H).db"`(WAL 模式在线备份安全)。丢库的实际损失仅"未上链的排队项"(链上数据是权威源),故 RPO 1h 可接受。CF 侧 D1 有 Time Travel(30 天),`npx wrangler d1 time-travel` 可恢复。

## 剩余人工项(代码侧无法替代)

- ~~**外部拨测**~~ **已闭环(2026-07-10)**:CF Worker cron 每分钟从独立基础设施拨测 VPS(见"健康与监控")。残余盲区:Cloudflare 平台自身宕机时 watchdog 与 worker 同时失联——由每日心跳/摘要缺席兜底(一天内可察觉);如需分钟级三方独立层,可另加 UptimeRobot 同时拨 VPS 域名与 `webauthnp256-publickey-index.atshelchin.workers.dev/api/health`。
- **双运行时口径(2026-07-10 确认)**:VPS(域名入口)与 CF Worker(workers.dev 入口,getvela.app 等接入方在用)**各持独立 PRIVATE_KEY**(create 钱包分别为 `0xb8f1…06cE` / `0xc870…46da`),不存在 nonce 冲突;两边钱包都要保有余额(心跳/🪫 告警分别覆盖)。

## 密钥轮换流程

1. 生成新 PRIVATE_KEY;2. 用旧 create 钱包把两个钱包余额转到新 create 钱包地址;3. 更新 .env / `wrangler secret put PRIVATE_KEY`;4. 重启/重部署;5. 首轮 worker 会自动给新 commit 钱包(=SHA256(新key))充值。注意:轮换期间 in-flight 的 committed 项的 commitment 是旧 commit 钱包发的——commitment 与钱包无关(纯 keccak 承诺),reveal 由新 create 钱包发送依然有效,无需特殊处理。
