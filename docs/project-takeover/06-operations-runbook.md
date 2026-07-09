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

**当前没有指标系统(Prometheus 等)**。最小监控建议:外部拨测 /api/health 每分钟,`status!="ok"` 连续 3 次告警;Telegram 告警作为兜底通道。

## Telegram 告警(已内建)

5 分钟节流(`ALERT_INTERVAL`),触发项:队列积压 ≥100;DLQ 数量变化;create 钱包余额 <0.01 xDAI;gas 价 >0.1 Gwei(队列暂停);每累计 10 次 tx 失败。发送 5s 超时、best-effort——**Telegram 挂了不影响业务,但也意味着告警会静默丢失**(改进项见 08)。

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

## 密钥轮换流程

1. 生成新 PRIVATE_KEY;2. 用旧 create 钱包把两个钱包余额转到新 create 钱包地址;3. 更新 .env / `wrangler secret put PRIVATE_KEY`;4. 重启/重部署;5. 首轮 worker 会自动给新 commit 钱包(=SHA256(新key))充值。注意:轮换期间 in-flight 的 committed 项的 commitment 是旧 commit 钱包发的——commitment 与钱包无关(纯 keccak 承诺),reveal 由新 create 钱包发送依然有效,无需特殊处理。
