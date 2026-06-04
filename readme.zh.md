# WebAuthn P256 Public Key Index Service

WebAuthn P256 公钥索引服务。数据存储在 Gnosis 链上的智能合约 (V2) 中，本服务作为读写代理，提供 REST API。

合约源码: [webauthnp256-publickey-index-contracts](https://github.com/atshelchin/webauthnp256-publickey-index-contracts)

| 合约 | 地址 (Gnosis Chain) |
|------|---------------------|
| WebAuthnP256PublicKeyIndex | `0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3` |
| WebAuthnP256BatchHelper | `0xc7B0db5d4974abA3EA25780f40Bf369CC013a16E` |

公共端点: `https://webauthnp256-publickey-index.biubiu.tools`

- 运行时: Deno (自托管) 或 Cloudflare Workers (边缘部署), 两套独立部署
- 数据源: Gnosis 链上合约 (通过 viem 读写, RPC 轮询 + 自动故障转移)
- 写入: 异步队列 (Deno: SQLite / CF: D1), 后台批量 commit-reveal 上链
- 批量上链: 通过 BatchHelper 合约, 单笔 tx 处理多条 commit/createRecord
- 双钱包: commit 和 createRecord 使用独立 EOA, nonce 互不干扰
- 默认端口: 11256 (Deno) / 无 (CF Workers)
- CORS: 允许所有来源

## API 参考

Base URL: `https://webauthnp256-publickey-index.biubiu.tools` (或自部署地址)

---

### GET /api/challenge

获取一个随机 challenge (向后兼容)。

**响应** (200):
```json
{
  "challenge": "a1b2c3d4..."
}
```

---

### POST /api/create

创建一条公钥记录。请求立即返回 202, 后台异步执行链上 commit-reveal 流程。

**请求体** (JSON):
| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| rpId | string | 是 | 站点域名 (如 `example.com`) |
| credentialId | string | 是 | 凭证 ID |
| publicKey | string | 是 | P256 公钥 (hex 格式, 含 04 前缀的非压缩格式, 65 字节) |
| name | string | 是 | passkey 的显示名称 |
| walletRef | string | 否 | 钱包标识 (bytes32 hex), 默认从 publicKey 计算确定性 Safe 地址 |
| initialCredentialId | string | 否 | 初始凭证 ID, 默认等于 credentialId (密钥轮换时指向根凭证) |
| metadata | string | 否 | 附加元数据 (hex), 默认 `abi.encode("VelaWalletV1", publicKey)` |

**请求示例**:
```json
{
  "rpId": "example.com",
  "credentialId": "abc123",
  "publicKey": "04a1b2c3...",
  "name": "我的 MacBook"
}
```

**响应** (202 - 已入队):
```json
{
  "id": "uuid",
  "status": "pending"
}
```

**响应** (201 - 已存在, 幂等):
```json
{
  "rpId": "example.com",
  "credentialId": "abc123",
  "walletRef": "0x000...abc",
  "publicKey": "04a1b2c3...",
  "name": "我的 MacBook",
  "status": "done"
}
```

**错误响应**:
- `400` - 参数缺失
- `429` - 超过限流 (每 IP 每分钟 5 次)

---

### GET /api/create/:id

查询异步创建任务的状态。

**响应 - 完成** (200, status=done):
```json
{
  "id": "uuid",
  "status": "done",
  "rpId": "example.com",
  "credentialId": "abc123",
  "walletRef": "0x000...abc",
  "publicKey": "04a1b2c3...",
  "name": "我的 MacBook",
  "txHash": "0x...",
  "createdAt": 1711000000000
}
```

**响应 - 进行中** (200, status≠done):
```json
{
  "id": "uuid",
  "status": "pending | committing | committed | creating",
  "rpId": "example.com",
  "publicKey": "04a1b2c3...",
  "name": "我的 MacBook",
  "createdAt": 1711000000000
}
```

> 进行中时不返回 `credentialId` 和 `walletRef`, 防止 commit-reveal 阶段被抢跑。失败时附带 `error` 字段。

status 状态机: `pending → committing → committed → creating → done`。失败时自动重试最多 3 次。

---

### GET /api/query

查询公钥记录。支持两种查询方式:

**方式一: 按 rpId + credentialId**

`GET /api/query?rpId=example.com&credentialId=abc123`

**方式二: 按 walletRef**

`GET /api/query?walletRef=0x000...abc`

**成功响应** (200):
```json
{
  "rpId": "example.com",
  "credentialId": "abc123",
  "walletRef": "0x000...abc",
  "publicKey": "04a1b2c3...",
  "name": "我的 MacBook",
  "initialCredentialId": "abc123",
  "metadata": "0000...00",
  "createdAt": 1711000000000
}
```

如果链上未找到但队列中有 (正在上链), 会返回队列中的部分数据并附带 `_queue` 字段 (隐去 `credentialId`/`walletRef`/`initialCredentialId` 以防抢跑):
```json
{
  "rpId": "example.com",
  "publicKey": "04a1b2c3...",
  "name": "我的 MacBook",
  "metadata": "0000...00",
  "createdAt": 1711000000000,
  "_queue": { "id": "uuid", "status": "committing" }
}
```

**错误响应**:
- `400` - 参数缺失 (需要 rpId+credentialId 或 walletRef)
- `404` - 未找到

---

### GET /api/stats/total

查询全网凭证总数。

**响应** (200):
```json
{
  "totalCredentials": 1234
}
```

---

### GET /api/stats/sites

分页查询所有站点。

**Query 参数**:
| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| page | number | 否 | 1 | 页码 |
| pageSize | number | 否 | 20 | 每页数量 (最大 100) |
| order | string | 否 | desc | 排序方向: `asc` 或 `desc` |

**响应** (200):
```json
{
  "total": 42,
  "page": 1,
  "pageSize": 20,
  "items": [
    { "rpId": "example.com", "publicKeyCount": 5, "createdAt": 1711000000000 }
  ]
}
```

---

### GET /api/stats/keys

分页查询某站点下的所有公钥。

**Query 参数**:
| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| rpId | string | 是 | - | 站点域名 |
| page | number | 否 | 1 | 页码 |
| pageSize | number | 否 | 20 | 每页数量 (最大 100) |
| order | string | 否 | desc | 排序方向: `asc` 或 `desc` |

**响应** (200):
```json
{
  "total": 5,
  "page": 1,
  "pageSize": 20,
  "items": [
    {
      "rpId": "example.com",
      "credentialId": "abc123",
      "walletRef": "0x000...abc",
      "publicKey": "04a1b2c3...",
      "name": "我的 MacBook",
      "initialCredentialId": "abc123",
      "metadata": "0000...00",
      "createdAt": 1711000000000
    }
  ]
}
```

**错误响应**: `400` - rpId 缺失

---

### GET /api/health

健康检查。

**响应** (200):
```json
{
  "service": "webauthn-p256-publickey-index",
  "version": "1.0.0",
  "chainId": 100,
  "contract": "0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3",
  "status": "ok"
}
```

---

### GET /

返回本文档的 HTML 渲染版本 (GitHub 风格)。

---

## 完整调用流程示例

```
1. POST /api/create                           → 202 { id, status: "pending" }
   Body: { rpId, credentialId, publicKey, name }
2. GET  /api/create/:id                       → { status: "done", txHash: "0x..." }
3. GET  /api/query?rpId=...&credentialId=...  → { publicKey, walletRef, ... }
   或 GET /api/query?walletRef=0x...          → 同上
```

## 隐私与合规

- IP 地址经 SHA-256 哈希后存储, 无法反推原始 IP, 符合 GDPR
- 不收集用户身份信息, 仅存储公钥和站点域名 (公开数据)
- 所有数据上链后不可删除 (区块链特性), 用户应知悉

## 缓存策略

双层缓存:
- 服务端内存缓存: 5 分钟 TTL, 上限 100MB, 满时淘汰最早条目
- CDN 缓存: `Cache-Control: public, max-age=3600` (1 小时)

规则:
- 仅缓存 200 响应, 404 不缓存

## 项目结构

```
shared/                      平台无关的共享代码 (两端直接 import)
  contract.ts                ABI, 合约地址, formatRecord, buildCommitment
  contract-read.ts           链上读操作 (getPublicKey, listRpIds 等)
  queue.ts                   类型, 常量, DDL, hashIp, wallet helpers, sendTelegram
  rpc.ts                     RPC 轮询 + 自动故障转移
  cache.ts                   内存缓存 (TTL + 内存上限 + 淘汰)
  validation.ts              输入长度校验
  wallet-ref.ts              walletRef 计算 (P256 公钥 → Safe 地址 → bytes32)
  routes/
    challenge.ts             GET /api/challenge
    stats.ts                 GET /api/stats/*

deno/                        Deno 运行时专有
  index.ts                   入口 (Deno.serve)
  config.ts                  配置 (Deno.env + node:crypto)
  queue.ts                   SQLite 队列 + setInterval 后台 worker
  nonce.ts                   Nonce 管理
  routes/
    query.ts                 GET /api/query
    create.ts                POST /api/create
  tests/                     Deno 测试

worker/                      Cloudflare Worker 运行时专有
  index.ts                   入口 (fetch + scheduled)
  config.ts                  配置 (crypto.subtle + env bindings)
  queue.ts                   D1 队列 (async)
  nonce.ts                   Nonce 管理 (config 参数注入)
  queue-processor.ts         Durable Object + alarm (替代 setInterval)
  types.ts                   CF 环境类型定义
  routes/
    query.ts                 GET /api/query (async D1)
    create.ts                POST /api/create (async D1)
  tests/                     CF Worker 测试

scripts/                     部署脚本
build.ts                     构建脚本 (readme→HTML + 编译二进制)
```

## 本地开发

```bash
# Deno
deno task dev          # 热重载开发 (自动加载 .env)
deno task test         # 运行测试 (69 tests)

# Cloudflare Worker
npm install            # 安装依赖
npm test               # 运行测试 (vitest + miniflare)
npm run dev            # 本地 wrangler dev
```

## 部署 (Deno - 自托管服务器)

通过 `deno task deploy` 部署到服务器, 交互式选择目标。

```bash
deno task deploy              # 部署: 选目标 → 上传 → 健康检查
deno task deploy status       # 查看远程服务状态
deno task deploy rollback     # 回滚到上一版本
```

首次部署自动: 安装 Deno → 创建用户/目录 → 提示配置 .env → 安装 systemd 服务。

### 服务器环境变量

```env
PORT=11256
QUEUE_DB_PATH=/opt/webauthnp256-publickey-index/data/queue.db
PRIVATE_KEY=0x...
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

## 部署 (Cloudflare Workers)

```bash
npm install                                    # 安装依赖
npm run setup                                  # 自动创建 D1 数据库, 生成 wrangler.json (幂等)
npx wrangler secret put PRIVATE_KEY            # 设置 Secrets
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TELEGRAM_CHAT_ID
npm run deploy                                 # 部署
```

队列处理通过 Durable Object + Alarm 实现 (~10s 间隔), 同时有 Cron Trigger (每 5 分钟) 作为备份确保 DO alarm 运行。
