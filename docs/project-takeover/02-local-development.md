# 02 — 本地开发

> 以下命令均在 2026-07-09(commit `113a8c6`)实际执行验证过,结果标注于各节。

## 前置

- Deno ≥ 2.x(验证环境 2.7.5)
- Node/npm(仅 CF Worker 测试与部署需要)
- 不需要数据库服务:Deno 侧用本地 SQLite 文件,CF 测试用 miniflare 内置 D1

## 环境变量

复制 `.env.example` → `.env`(Deno)/ `.dev.vars.example` → `.dev.vars`(CF 本地):

| 变量 | 必填 | 说明 |
|---|---|---|
| `PORT` | 否(默认 11256) | Deno HTTP 端口 |
| `QUEUE_DB_PATH` | 否(默认 queue.db) | SQLite 队列文件路径 |
| `PRIVATE_KEY` | 写路径必填 | 服务钱包私钥(需持有 xDAI 付 gas)。**缺失时服务仍能启动**:读接口正常,create 会入队但后台不处理 |
| `ALCHEMY_API_KEY` | 否 | 配置后作为优先写 RPC(Deno 已接线;CF 接线为本次接管补齐) |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | 否 | 告警通道,缺失则静默跳过 |

**警告**:`.env` 含真实私钥,已在 `.gitignore`,不要提交、不要打印。

## 常用命令(全部验证通过)

```bash
# Deno 侧
deno task dev        # 热重载开发(--env 自动加载 .env)
deno task test       # 168 通过 / 0 失败 / 5 忽略(链上 e2e 被 PRIVATE_KEY 门控跳过),约 30s
deno task build      # README→HTML + deno compile → dist/webauthnp256-publickey-index(约 300MB)
deno check deno/index.ts build.ts scripts/deploy.ts   # 类型检查(worker/ 需 CF 类型,由 vitest 侧覆盖)
deno lint            # 目前 3 个 require-await 提示(均在测试文件,无碍)

# CF Worker 侧
npm install
npm test             # vitest + miniflare,28 通过,约 3s
npm run dev          # wrangler dev(需先 npm run setup 生成 wrangler.json)
```

## 无私钥冒烟测试(安全,不花 gas)

```bash
env -u PRIVATE_KEY PORT=21256 QUEUE_DB_PATH=/tmp/smoke.db \
  deno run --allow-net --allow-read=.,/tmp --allow-write=/tmp --allow-env \
  --unstable-node-globals deno/index.ts
```

验证点(2026-07-09 实测):
- `GET /api/health` → `{"status":"ok","rpcCircuit":"closed","queue":{...}}`
- `GET /api/stats/total` → 真实链读(当时返回 845)
- `POST /api/create`(合法体)→ 202 + id;`GET /api/create/:id` → pending 且**不含** credentialId/walletRef(防抢跑脱敏)
- 非法 publicKey → 400;单 IP 第 6 次创建 → 429
- OPTIONS 预检回显任意请求头(`access-control-allow-headers: content-type,x-custom`)

注意:本机若设了 `http_proxy`,curl 本地端口要 `unset http_proxy https_proxy all_proxy` 或 `--noproxy '*'`。

## 链上 E2E(会花真实 gas,谨慎)

`deno/tests/e2e.test.ts` / `stress.test.ts` 以 `ignore: !Deno.env.get("PRIVATE_KEY")` 门控。跑法:

```bash
deno test --allow-net --allow-read --allow-write --allow-env --unstable-node-globals --env deno/tests/e2e.test.ts
```

需要 `.env` 里有已充值的 Gnosis 钱包。单条 create→commit→reveal→query 全程约 20-60s。CI 不跑这些。

## 测试文件地图(deno/tests/,20 个文件)

| 文件 | 覆盖 |
|---|---|
| queue-engine.test.ts(19) | **资金状态机假链套件**:commit-reveal 全流程/毒丸隔离/reconcile/退避/EXHAUSTED/nonce 记账(无网络,注入时钟) |
| reliability.test.ts(25) | 错误分类/withRetry/Deadline |
| validation.test.ts(16) | 输入校验边界 |
| cache.test.ts(13) | TTL/LRU/内存上限/键碰撞 |
| create.test.ts(11) | create 路由(含幂等、背压) |
| rpc.test.ts(11) | 轮转/故障转移/断路器 |
| server.test.ts(9) | 路由集成 |
| queue.test.ts(7)+queue-logic.test.ts(5) | 队列语义/毒丸判定 |
| idempotency.test.ts(6) | 唯一索引/并发入队去重 |
| security.test.ts(5)、cors.test.ts(5)、health.test.ts(5)、stats.test.ts(6)、wallet-ref.test.ts(5)、log.test.ts(4)、query.test.ts(3)、nonce.test.ts(2)、stale-cache.test.ts(2) | 对应模块 |
| e2e.test.ts(5)、stress.test.ts(1) | 链上门控 |

CF 侧 `worker/tests/worker.test.ts`(26):路由、D1 队列幂等、withD1Retry、限流。

## CI

`.github/workflows/ci.yml`:push/PR 到 main 时跑 `deno check deno/index.ts` + `deno task test`。**不含** CF Worker 测试与 lint(改进项,见 08)。
