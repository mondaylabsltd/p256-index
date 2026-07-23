# WebAuthn P256 Public Key Index 服务

面向 Gnosis 链 V2 合约的 REST 服务。现已是单一 Rust 服务；Deno 运行时与
Cloudflare Worker 实现均已移除。

| 合约 | Gnosis 地址 |
| --- | --- |
| WebAuthnP256PublicKeyIndex | 0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3 |
| WebAuthnP256BatchHelper | 0xc7B0db5d4974abA3EA25780f40Bf369CC013a16E |

## 架构

- Rust/Axum 提供公开 API，默认端口 11256。
- Redis 保存共享响应缓存、限流、任务状态、去重索引、队列深度投影与 DLQ 投影。
- Iggy 提供持久化的 p256-index / create 流；共享消费组提供有序、至少一次处理。
- 消费者先把任务持久化到 Redis，再通过 WebAuthnP256BatchHelper 处理批量
  commit-reveal 调用。
- Redis 准入与 Iggy 追加刻意分两阶段：若 Iggy 确认丢失，同一任务 ID 可安全重投，
  消费者保持幂等。
- 合约读取使用有界的 Gnosis RPC 故障转移池；Redis 缓存新鲜命中不触达 RPC。

POST /api/create 保持公开契约：返回 202 与 { id, status: "pending" }，状态读取
会隐藏揭示前的敏感字段，已存在的链上记录返回 201 与 status "done"。

## 配置

把 .env.example 复制为 .env。Redis 与 Iggy 为必需依赖；无法连接任一者时服务
立即失败退出。

~~~dotenv
P256_INDEX_IGGY_URL=iggy+tcp://user:password@iggy.example:5100?reconnection_retries=5&reconnection_interval=1s&reestablish_after=5s&heartbeat_interval=3s&nodelay=true
P256_INDEX_REDIS_URL=redis://redis.example:6379/0
PRIVATE_KEY=0x...
~~~

PRIVATE_KEY 仅在只读运行时可省略。缺失时 HTTP API 仍启动，但 Iggy 消费者被禁用，
新建任务保持 pending。commit 钱包按 SHA-256(PRIVATE_KEY bytes) 确定性推导，以
保持既有链上行为。

首次启动时 Iggy 会创建以下拓扑（provisioner 身份需有创建权限）：

| 资源 | 名称 |
| --- | --- |
| stream | p256-index |
| topic | create |
| partitions | 1 |
| consumer group | p256-index-server-v1 |

生产环境请通过 P256_INDEX_IGGY_CONSUMER_URL 与 P256_INDEX_IGGY_PROVISIONER_URL
使用独立的最小权限消费者/provisioner 身份。

## 本地检查

~~~sh
cd p256-index-server
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run --release
~~~

Rust 二进制在开发时加载本地 .env，在 systemd/容器部署中使用常规进程环境变量。

## 接口兼容

保留以下路由与 JSON 字段名：

| 方法 | 路由 | 用途 |
| --- | --- | --- |
| GET | /api/challenge | Base64url 随机挑战 |
| POST | /api/create | 校验并持久化入队一次公钥注册 |
| GET | /api/create/:id | 注册状态；隐藏未揭示字段 |
| GET | /api/query?rpId=&credentialId= | 按凭证查询记录 |
| GET | /api/query?walletRef= | 按确定性钱包引用查询记录 |
| GET | /api/stats/total | 凭证总数 |
| GET | /api/stats/sites | 分页站点列表 |
| GET | /api/stats/keys?rpId= | 某站点的分页公钥列表 |
| GET | /api/health | 健康、RPC 熔断与队列/DLQ 指标 |

服务保留 CORS（GET, POST, OPTIONS）、请求体与 P-256 校验、walletRef 绑定、
每 IP 每分钟 5 次创建、全局创建预算、缓存未命中的读限流、RPC 故障期间的陈旧
缓存响应，以及 pending → committed → done | failed 状态机。

## 可靠性与告警

队列 worker 旁挂一个维护循环，移植了原 Deno/CF Worker 的运维安全网：

- 每日心跳（队列深度、DLQ、create/commit 钱包余额、可用创建次数、运行时长）
  经 Telegram 发送；
- 运维告警：create 钱包资金不足、RPC 读熔断打开、DLQ 增长、卡死 nonce 无法解卡；
- 卡死 nonce 解卡扫描：用 Redis 广播账本记录在途交易，对确实卡死的 nonce 以
  150% gas 发同 nonce 零值自转覆盖；
- 瞬时链上失败指数退避（5s → 15s → 45s …，上限 60s）；
- commit 批次 poison 隔离：把确定性 revert 的单条 commitment 单独隔离，其余
  继续推进。

配置 TELEGRAM_BOT_TOKEN 与 TELEGRAM_CHAT_ID 后才会真正投递，否则只记日志。
设置 RELEASE 可在心跳中带上构建标签。每日心跳同时是存活信号：若心跳停止到达，
说明进程、链读取或 Telegram 通道出了问题。

## 端到端测试

与已退役实现的契约级与链级一致性由门控集成测试覆盖（不在无基础设施的 CI 中运行）：

~~~sh
# 真实 Redis + Iggy 的 HTTP + 队列契约：
P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
P256_INDEX_TEST_IGGY_URL='iggy+tcp://user:pass@127.0.0.1:5100' \
  cargo test --test e2e -- --ignored

# 完整 create -> 链上 -> confirmed（真实 Gnosis 写入，会花费 gas）：
P256_INDEX_E2E_CHAIN=1 cargo test --lib -- --ignored \
  e2e_chain_tests::create_persists_on_chain_end_to_end
~~~

## 上线切换

本次改动刻意不保留 SQLite、D1、Deno 或 Cloudflare Worker 的兼容层。生产切换前，
先停掉所有使用同一 PRIVATE_KEY 的旧写入进程以避免 nonce 争用；旧队列文件仅作
审计留存。用 Redis 与 Iggy 启动 Rust 服务，确认 /api/health 与一次只读查询后
再开启写入。

## 部署

为目标架构构建 release 二进制并安装到
/opt/webauthnp256-publickey-index/current/p256-index-server。随附的 systemd 单元
读取 /opt/webauthnp256-publickey-index/data/.env；不安装或调用 Deno、Node、npm、
Wrangler、SQLite 或 Cloudflare 服务。

打 v* tag 的发布还会通过 .github/workflows/release.yml 发布各平台二进制归档与
多架构 Docker 镜像。Docker 作业需要仓库变量 DOCKERHUB_USERNAME 与 secret
DOCKERHUB_TOKEN。

## Docker / Compose

仅服务本身在容器中运行（Redis 与 Iggy 仍为外部依赖，与既有部署一致）。
compose.yaml 构建 p256-index-server/Dockerfile 并读取 p256-index-server/.env：

~~~sh
docker compose up --build
~~~

当 Redis 与 Iggy 运行在 Docker 宿主机上时，把 P256_INDEX_REDIS_URL 与
P256_INDEX_IGGY_URL 指向 host.docker.internal（见 compose.yaml 中的说明）。
