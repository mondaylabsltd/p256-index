# 01 — 系统总览

> 审计基线:commit `113a8c6`(main,2026-07-09),审计人:Claude(接管审计)。
> 本文所有结论均对照源码验证,引用格式 `文件:行号`。

## 项目是什么

**WebAuthn P256 公钥索引服务**:为 WebAuthn P256 凭证提供一个链上公钥索引的 REST 读写代理。数据最终存储在 Gnosis Chain 上的智能合约(V2),本服务代付 gas、异步批量写入,并提供带缓存的查询 API。

- 公网端点:`https://webauthnp256-publickey-index.biubiu.tools`
- 合约:`WebAuthnP256PublicKeyIndex` = `0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3`(Gnosis, chainId 100)
- 批量助手合约:`WebAuthnP256BatchHelper` = `0xc7B0db5d4974abA3EA25780f40Bf369CC013a16E`
- 合约源码在独立仓库 `atshelchin/webauthnp256-publickey-index-contracts`(**不在本仓库,合约行为本审计未验证**)

典型用户是钱包/Passkey 应用(如 VelaWallet,见默认 metadata `"VelaWalletV1"`,`deno/routes/create.ts:83-86`):注册时把 `(rpId, credentialId) → publicKey/walletRef` 写入链上索引,登录/恢复时反查。

## 双运行时架构

同一套业务逻辑,两个独立部署(数据互不相通):

| | Deno(自托管) | Cloudflare Worker(边缘) |
|---|---|---|
| 入口 | `deno/index.ts`(`Deno.serve`,端口 11256) | `worker/index.ts`(`fetch` + `scheduled`) |
| 队列存储 | SQLite(`node:sqlite`,WAL)`deno/queue.ts` | D1 `worker/queue.ts` |
| 后台处理 | `setInterval` 60s 单飞(`deno/queue.ts:258`) | Durable Object alarm 10s + cron 每分钟兜底(`worker/queue-processor.ts:46`, `wrangler.jsonc:33`) |
| 配置 | `.env` → `deno/config.ts` | wrangler secrets → `worker/config.ts` |
| 限流存储 | 进程内 Map(`deno/queue.ts:53`) | D1 `rate_limits` 表(`worker/queue.ts:72`) |
| 部署 | `scripts/deploy.ts`(SSH + systemd + 符号链接发布) | `scripts/cf-setup.sh` + `wrangler deploy` |

共享层 `shared/`(两运行时共用,防止漂移):

- `shared/queue.ts` — 队列类型/常量/DDL/纯逻辑(commitment 构造、毒丸判定、退避、IP 哈希、Telegram)
- `shared/reliability.ts` — 统一错误分类(transient/permanent/poison)、`withRetry`(全抖动、截止时间、Retry-After)、`Deadline`
- `shared/rpc.ts` — RPC 轮询 + 故障转移 + 断路器(半开探测)+ 远端 RPC 列表(带主机白名单防投毒,`shared/rpc.ts:34`)
- `shared/contract-read.ts` — 链读(12s 总预算,合约 revert 不算 RPC 故障)
- `shared/cache.ts` — 内存缓存(5min TTL、100MB 上限、近似 LRU、过期保留作 last-known-good)
- `shared/log.ts` — 结构化 JSON 日志 + `redactSecrets`(擦除 RPC key/Telegram token)
- `shared/validation.ts` — 输入校验(长度/hex/P256 格式/bytes32 对齐)
- `shared/wallet-ref.ts` — publicKey → 确定性 Safe 地址 → bytes32 walletRef
- `shared/cors.ts` — 全开放 CORS(公共无凭证 API,回显任意请求头)
- `shared/routes/` — challenge/stats/health/errors 共享路由

## 技术栈与版本

- Deno 2.7.5(本地验证),CI 用 `v2.x`;`deno task start` 带 `--frozen` 锁定 `deno.lock`
- 运行时依赖仅 **viem 2.47.5**(锁定于 deno.lock / package-lock.json)+ `@std/assert`(测试)+ `marked`(构建时渲染 README)
- CF 侧 devDeps:wrangler 3.x、vitest 2.1 + @cloudflare/vitest-pool-workers(miniflare)
- `npm audit --omit=dev` = 0 漏洞(2026-07-09 验证);dev 链有 10 个漏洞(miniflare/undici,不进运行时)

## 核心数据流

### 写路径(创建记录,commit-reveal 防抢跑)

```
POST /api/create
  → 校验(必填/长度/hex/P256 格式/walletRef 必须与 publicKey 推导一致)
  → 限流(单 IP 5次/分)+ 全局写入上限(120次/分,防 gas 燃烧)+ 队列背压(>10000 拒绝)
  → 链上预查 hasRecord(命中→201 幂等返回;链不可达→跳过,继续入队)
  → 入队(部分唯一索引保证同 (rpId,credentialId) 至多一个活跃行)→ 202 {id}
后台 worker(60s / DO alarm 10s):
  pending → batchCommit(commit 钱包)→ committed
  committed → 等 1 个区块 → reconcile(hasRecord 多播,已在链上→直接 done)
            → batchCreateRecord(create 钱包)→ done
  失败分类:transient→指数退避重试(最多10次,EXHAUSTED 入 DLQ)
           poison→逐项隔离(单项重估/单发),元凶进 DLQ(POISON 前缀),无辜项继续
```

状态机:`pending → committed → done | failed`(`creating` 为滚动升级安全网保留,`deno/queue.ts:353-357`)。

### 读路径

```
GET /api/query?rpId&credentialId | ?walletRef
  → 内存缓存(5min)→ 链读(RPC 轮转重试,12s 预算,断路器快速失败)
  → 链不可达:有陈旧缓存(≤1h)则 200 + X-Served-Stale,否则 503 + Retry-After
  → 链上无记录:回退查队列(脱敏:不返回 credentialId/walletRef/initialCredentialId,防抢跑)
GET /api/stats/*(total/sites/keys)— 同样的缓存+降级策略
```

### 双钱包与 nonce

- create 钱包 = `PRIVATE_KEY`;commit 钱包私钥 = SHA-256(PRIVATE_KEY)(`deno/config.ts:35`)——**泄漏 PRIVATE_KEY 即两个钱包全失守**
- create 钱包自动给 commit 钱包充值(阈值 0.005 xDAI,单次 0.05,`shared/queue.ts:51-52`)
- nonce 本地管理(`deno/nonce.ts` / `worker/nonce.ts`):池内互斥获取;发送成功即消耗,发送失败 `release()` 强制下次从链上重同步 —— 无死锁(互斥只包获取,不包持有)

## API 一览

`GET /`(README 渲染的 HTML 文档)、`GET /api/health`、`GET /api/challenge`、`POST /api/create`、`GET /api/create/:id`、`GET /api/query`、`GET /api/stats/total`、`GET /api/stats/sites`、`GET /api/stats/keys`。详见 README.md(与实现核对基本一致;README 中"69 tests"已过时,实际 141)。

## 关键运营参数(`shared/queue.ts:36-57`)

| 参数 | 值 | 含义 |
|---|---|---|
| MAX_RETRIES | 10 | transient 重试上限,超过→EXHAUSTED 入 DLQ |
| DEFAULT_RATE_LIMIT / RATE_WINDOW | 5 / 60s | 单 IP 创建限流 |
| DEFAULT_GLOBAL_WRITE_LIMIT | 120/60s | 全局创建上限(真正的 gas 花费边界) |
| MAX_GAS_PRICE_GWEI | 0.1 | 超过则整个队列暂停 |
| TX_BATCH_SIZE / CREATE_SUB_BATCH | 50 / 10 | 每轮批量上限 / createRecord 子批 |
| DONE_RETENTION / FAILED_RETENTION | 7天 / 30天 | 完成/DLQ 行保留期 |
| MAX_ACTIVE_QUEUE_DEPTH | 10000 | 背压阈值,超过 503 |
| 降级阈值 | depth≥2000, dlq≥25, oldest≥30min | /api/health 报 degraded |
