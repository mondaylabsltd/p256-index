# WebAuthn P256 Public Key Index 服务

服务已重构为单一 Rust 服务；Deno、Cloudflare Worker、D1 与 SQLite 相关代码均已移除。

- HTTP 服务：Axum，默认端口 11256
- 共享缓存、限流、任务状态、幂等索引、DLQ：Redis
- 持久化创建队列：Iggy（p256-index stream / create topic）
- 链上写入：Gnosis 上的 WebAuthnP256BatchHelper 批量 commit-reveal
- 队列状态：pending → committed → done | failed

接口保持不变：/api/challenge、/api/create、/api/create/:id、
/api/query、/api/stats/*、/api/health 的路径、请求字段和响应字段
均保持兼容；pending/committed 期间仍隐藏 credentialId 与 walletRef。

## 配置

~~~dotenv
P256_INDEX_IGGY_URL=iggy+tcp://user:password@iggy.example:5100?reconnection_retries=5&reconnection_interval=1s&reestablish_after=5s&heartbeat_interval=3s&nodelay=true
P256_INDEX_REDIS_URL=redis://redis.example:6379/0
PRIVATE_KEY=0x...
~~~

Redis 和 Iggy 为必需依赖。PRIVATE_KEY 缺失时只提供读接口，后台 Iggy
消费者不会启动；创建请求会保持 pending。commit 钱包继续按
SHA-256(PRIVATE_KEY bytes) 推导，因此与原链上流程一致。

## 可靠性与告警

队列 worker 旁挂一个维护循环，移植了原 Deno/CF Worker 的运维安全网：

- 每日心跳（队列深度、DLQ、create/commit 钱包余额、可用创建次数、运行时长）经 Telegram 发送；
- 运维告警：create 钱包资金不足、RPC 读熔断打开、DLQ 增长、卡死 nonce 无法解卡；
- 卡死 nonce 解卡扫描：用 Redis 广播账本记录在途交易，对确实卡死的 nonce 以 150% gas 发同 nonce 零值自转覆盖；
- 瞬时链上失败指数退避（5s → 15s → 45s …，上限 60s）；
- commit 批次 poison 隔离：把确定性 revert 的单条 commitment 单独隔离，其余继续推进。

配置 TELEGRAM_BOT_TOKEN 与 TELEGRAM_CHAT_ID 后才会真正投递，否则只记日志。
每日心跳同时是存活信号：若心跳停止到达，说明进程、链读取或 Telegram 通道出了问题。

## 本地检查

~~~sh
cd p256-index-server
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run --release
~~~

上线前必须先停掉所有使用同一 PRIVATE_KEY 的旧 Deno/Cloudflare 写入进程，
避免两个运行时争用同一 EOA nonce。完整架构和上线切换说明见 README.md。
