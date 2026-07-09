# 05 — 部署 Runbook

> 两条独立部署链路。以下步骤依据 `scripts/deploy.ts`、`deploy/systemd/webauthnp256-publickey-index.service`、`scripts/cf-setup.sh` 源码核对;**远端实际执行未在本审计中演练**(需要生产 SSH 凭据)。

## ⚠️ 关键约束:两运行时不能共用同一 PRIVATE_KEY 并发运行

create 钱包 = `PRIVATE_KEY`,commit 钱包 = SHA-256(PRIVATE_KEY)——两个运行时的推导**完全相同**(`deno/config.ts:35`、`worker/config.ts:8`)。但它们各自维护**独立的进程内 nonce 池**(`deno/nonce.ts` / `worker/nonce.ts`)和**独立的队列库**(SQLite vs D1)。

因此:**若 Deno 自托管与 CF Worker 同时运行且配置了相同的 PRIVATE_KEY,两者会从同一对 EOA 用各自独立追踪的 nonce 发交易 → nonce 冲突("nonce too low" / 替换交易 / 交易被顶掉),写路径会持续抖动。**

安全做法(二选一):
1. **只跑一个**部署(另一个作为冷备,切换时确保前者已停);或
2. 两个部署使用**不同的 PRIVATE_KEY**(各自独立钱包,各自充值)。

README 把两者描述为"两个独立部署"但未写明此约束——接管后务必按上面执行。

## A. Deno 自托管(systemd)

### 部署前检查清单

- [ ] `git status` 干净,在 main 最新 commit 上
- [ ] `deno task test` 全绿(141 通过)
- [ ] `deno check deno/index.ts` 通过
- [ ] 目标机可 SSH,`~/.claude` 部署配置存在(或准备好首配)
- [ ] 服务器钱包 xDAI 余额充足(检查 `/api/health` + Telegram 低额告警)

### 发布步骤

```bash
deno task deploy          # 交互式:选目标 → 上传 → 安装 unit → 切换符号链接 → 重启 → 健康轮询
deno task deploy status   # 查看 systemd 状态、当前 release、健康
```

首次部署自动:装 Deno → 建 `webauthn` 用户 → 建目录(`/opt/webauthnp256-publickey-index/{releases,data,current}`)→ 交互式写 `.env`(0600)→ 装 sudoers → 装 systemd unit。

机制(`scripts/deploy.ts:114-243`):上传到 `releases/<tag>` → `current` 符号链接切换 → `systemctl restart` → 最多 60s 轮询 `127.0.0.1:11256/api/health`。

**注意**:健康检查失败**不会自动回滚**,只打印 "inconclusive"(`deploy.ts:235`)。失败时人工执行回滚。

### 回滚

```bash
deno task deploy rollback   # 符号链接切到最新的非当前 release + 重启
```

**边界情形**:`rollback` 选"最新的 ≠ 当前"的 release(`deploy.ts:284`)。若已回滚过一次再执行,会切回新版本(变成前滚)。连续回滚需 SSH 手动 `ln -sfn releases/<旧tag> current && sudo systemctl restart webauthnp256-publickey-index`。

### 数据与迁移

- 队列数据:`/opt/webauthnp256-publickey-index/data/queue.db`(SQLite,WAL)。**发布不动 data 目录**,回滚安全
- Schema 迁移在启动时自动执行且幂等(`deno/queue.ts:89-102`):加列(walletRef/retryAfter)→ 活跃重复行去重(保留最优)→ 建部分唯一索引。**回滚到不认识新列的旧版本是安全的**(SQLite 多余列不报错),但回滚跨过"唯一索引引入"的版本后再前滚,迁移会重新执行(幂等,无害)
- **备份**:代码内无备份逻辑。见 06 运维手册的备份建议(P2 遗留项)

### systemd 单元要点

`Restart=on-failure`(3s,60s 内最多 5 次)、`MemoryMax=256M`、`ProtectSystem=strict`(仅 data/releases 可写)、`EnvironmentFile=data/.env`、`deno task start` 带 `--frozen`(锁文件不符即拒绝启动,防依赖漂移)。

## B. Cloudflare Worker

### 首次

```bash
npm install
npm run setup                          # 幂等:找/建 D1 "webauthnp256-queue",生成 wrangler.json
npx wrangler secret put PRIVATE_KEY
npx wrangler secret put TELEGRAM_BOT_TOKEN   # 可选
npx wrangler secret put TELEGRAM_CHAT_ID     # 可选
npx wrangler secret put ALCHEMY_API_KEY      # 可选(优先写 RPC)
npm run deploy
```

### 日常发布

```bash
npm test          # 26 通过
npm run deploy    # wrangler deploy -c wrangler.json
```

- D1 表结构由 Worker 首个请求惰性建表/迁移(`worker/queue.ts:59`),无独立迁移步骤
- DO(QueueProcessor,单实例 "main")迁移标签 v1 已在 wrangler.json;新增 DO class 需追加 migrations 条目
- 回滚:`npx wrangler rollback`(wrangler 3 支持按版本回滚)或重新 deploy 旧 commit。D1 数据不受部署影响

### 发布后 Smoke Test(两环境通用)

```bash
BASE=https://webauthnp256-publickey-index.biubiu.tools   # 或 CF workers.dev 域名
curl -s $BASE/api/health            # 期望 status:"ok", rpcCircuit:"closed"
curl -s $BASE/api/challenge         # 期望 {"challenge":...}
curl -s "$BASE/api/stats/total"     # 期望链读数字
# 可选完整写路径验证(花少量 gas):POST /api/create + 轮询 /api/create/:id 到 done
```

## 灾难恢复要点

| 场景 | 处置 |
|---|---|
| 私钥泄漏 | 立即向两个钱包地址发起余额转移;换新 PRIVATE_KEY(注意 commit 钱包会随之变化);更新 .env/secret;重启。**链上历史数据不受影响**(数据本身公开) |
| queue.db 丢失 | 未上链的 pending/committed 项丢失(用户可重试,链上幂等);已上链数据无损。重建空库即可启动 |
| D1 故障 | CF 侧读路径仍可用(链读+缓存);create/status 5xx。等待恢复或 DNS 切到 Deno 部署 |
| 合约不可用 | 服务自动降级:读走陈旧缓存(≤1h),写入队积压;恢复后自动收敛 |
