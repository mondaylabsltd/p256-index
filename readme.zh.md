# WebAuthn P256 Public Key Registry 服务

一个中立、无权限的 P-256 passkey 公钥登记处:任何人都可以把自己持有的密钥
数据存到 Gnosis 链和本服务的数据库。这把钥匙用来干什么——派生钱包、组装
身份、还是别的用途——完全由存储方决定,承载在单元级的不透明 `metadata`
里。由 Vela Wallet 构建;Vela 是它的第一个客户,不是它的主人。

## 信任模型

- **公钥是主键,持有与内容是被验证的东西——在链上验证。**每条存储都要求
  签名者自己的 WebAuthn 格式 P-256 assertion,签在存储授权挑战
  `keccak256(abi.encode(chainid, registry, rpId, publicKey, binding))`
  上,合约通过 EIP-7951/RIP-7212 预编译验签。binding 按角色而定:
  **组密钥**签单元 contentHash(覆盖 rpId、metadata、组公钥、全部成员),
  **成员 passkey** 签 `memberBindingFor(组公钥, 自己的attestation)`。
  合起来每个字节都在签名覆盖之下:没有人能往不持有的钥匙下挂数据,
  也没有人能改动任何字段——抢跑、重放、内容替换在协议层不存在。
- **除此之外零独占、零解释。**一把钥匙可以出现在任意多个注册单元里;
  查询返回列表,读方按自己的 metadata schema 过滤。credentialId、显示
  名、钱包派生前像,全部编码在 `metadata`(≤2048 字节,不透明)里。
- **注册单元** = 一把组密钥 + 1..7 把成员 passkey,共享一个 rpId、一份
  metadata,一笔 `register` 交易原子落地(7 把 passkey = 8 个签名)。
  组密钥是客户端软件密钥,每个单元必有且仅有一把,静默收尾签名、零
  弹窗;成员 passkey 在创建那一刻即可签名,完全乱序、互不等待。没有
  nonce、没有任何可消耗品:相同内容注册天然幂等,不同内容使签名失效。
  单元按组公钥反查(getUnitIdsByGroupKey);组语义归使用方 schema。
- **读取是列表形态且 id 恒定。**entry id 顺序分配、永不变化——记住
  自己的 entry id 就能永远 O(1) 直读。无本地状态时的发现:从任意一次
  登录签名恢复两个候选公钥、各查一次——只有被持有的钥匙才可能有条目,
  所以至多一个桶非空。

## 客户端流程

1. enrollment 开始时客户端生成一次性组密钥(软件 P-256)。每把
   passkey:`create()` 收集公钥,然后一次 `get()`,其挑战 = 成员绑定
   挑战(`POST /api/challenge` 成员模式:`{rpId, groupPublicKey,
   publicKey, attestation?}`)——只依赖组公钥和自己的字段,顺序任意、
   设备任意、互不等待。每把钥匙两次弹窗。
2. 全部钥匙就位后定稿单元,组密钥静默签收尾挑战(`POST /api/challenge`
   组模式:`{rpId, metadata, groupPublicKey, members}` 返回 contentHash
   与组挑战),然后一笔提交。
3. `POST /api/register` 提交单元。服务端逐个验签(合约校验的纯 Rust
   镜像——无效证明永远到不了链上)、双阶段持久化入队(Redis + Iggy),
   worker 一笔交易落链。轮询 `GET /api/task/{id}`。
4. 上链前 `GET /api/query?publicKey=` 已经用 `_queue` 标记应答:交给
   本服务的数据绝不会有不可见窗口。

## 架构

- Cargo workspace 两个 crate:`p256-registrar` 拥有业务词汇与决策规则
  (任务生命周期、验签、准入、查询/缓存策略、提交状态机、gas 策略、
  链错误分类),刻意零 I/O;`p256-index-server` 是 shell,接 Axum、
  Redis、Iggy、Gnosis RPC 与 Telegram。
- Redis:响应缓存、限流、任务状态、内容哈希幂等键与成员公钥占位、
  队列深度/DLQ 投影、广播账本。
- Iggy:持久化注册流(至少一次、有序);Redis 准入与 Iggy 追加两阶段,
  丢确认可安全重投,消费者幂等。
- worker **一单元一交易**(无批量、无 commit-reveal、单资金钱包):
  失败精确归属;revert 回执先按内容哈希对账、再重发一次以取得 revert
  原因用于分类。
- 链读走有界 RPC 故障转移池;缓存新鲜命中不触达 RPC;RPC 故障期间以
  `_stale` 标记服务陈旧副本。

## API

| 方法 | 路由 | 用途 |
| --- | --- | --- |
| POST | /api/register | 验签并持久化入队一个单元(1..7 成员) |
| GET | /api/task/{id} | 任务状态(全量披露;不回显证明) |
| POST | /api/challenge | 成员模式算成员挑战;组模式算 contentHash+组挑战 |
| GET | /api/query?publicKey= | 某公钥的分页条目(上链前带 `_queue` 标记) |
| GET | /api/query?entryId= | 按恒定 id 取单条 |
| GET | /api/stats/total | {totalEntries, totalUnits, totalRpIds} |
| GET | /api/stats/sites | 分页 rpId 列表 |
| GET | /api/stats/keys?rpId= | 某 rpId 下的分页条目 |
| GET | /api/health | 健康、RPC 熔断、队列/DLQ 指标、registry 地址 |

`attestation` 为 20 字节版本化注册期信号(版本、AAGUID、authData flags、
attachment、transports)——形状校验,真实性属存储方声明;展示映射归客户端。

没有 409:内容哈希即身份,同一单元重复提交是幂等的,不同单元互不冲突。
相同内容已上链则回 200 "done"。

## 配置

复制 .env.example 为 .env。Redis 与 Iggy 必需,连不上即快速失败;
`P256_INDEX_CONTRACT_ADDRESS`(已部署的 registry)始终必需。

~~~dotenv
P256_INDEX_IGGY_URL=iggy+tcp://user:password@iggy.example:5100?reconnection_retries=5&reconnection_interval=1s&reestablish_after=5s&heartbeat_interval=3s&nodelay=true
P256_INDEX_REDIS_URL=redis://redis.example:6379/0
P256_INDEX_CONTRACT_ADDRESS=0x…
PRIVATE_KEY=0x…
~~~

PRIVATE_KEY 仅在只读运行时可省略:HTTP 读 API 照常,Iggy 消费者禁用,新
任务保持 pending。gas 由本服务支付;每 IP 5/分钟与全局创建预算是成本闸门。

## 合约

`contracts/src/WebAuthnP256PublicKeyRegistry.sol` ——部署要求目标链在
0x100 有 P256VERIFY 预编译(EIP-7951/RIP-7212,Gnosis 已上线;部署前用
`contracts/script/DeployRegistry.s.sol` 注释里的 cast 一行命令实测)。

~~~sh
cd contracts && forge test
forge script script/DeployRegistry.s.sol --rpc-url $RPC --broadcast
~~~

gas:组+1 成员约 110 万,组+7 成员约 360 万(按成员线性)。

## 本地检查

~~~sh
# 在仓库根执行,p256-registrar crate 才会一并被检查。
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --release -p p256-index-server
~~~

门控集成测试(不进无基础设施的 CI):

~~~sh
# 真实 Redis 上的 HTTP 契约:
P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
  cargo test -p p256-index-server --lib -- --ignored http_contract

# 真实 Redis + Iggy 的 HTTP + 队列契约:
P256_INDEX_TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
P256_INDEX_TEST_IGGY_URL='iggy+tcp://user:pass@127.0.0.1:5100' \
  cargo test --test e2e -- --ignored

# 完整 register -> 链上 -> confirmed(真实 Gnosis 写入,花费 gas):
P256_INDEX_E2E_CHAIN=1 cargo test --lib -- --ignored \
  e2e_chain_tests::register_persists_on_chain_end_to_end
~~~

## 可靠性与告警

- 每日 Telegram 心跳(队列深度、DLQ、钱包余额、可注册次数、运行时长);
- 运维告警:资金 runway 低、RPC 读熔断、DLQ 增长、无法解卡的 nonce;
- 卡死 nonce 解卡扫描(Redis 广播账本 + 单调同 nonce 替换定价);
- 瞬时故障指数退避(5s → 15s → 45s …,上限 60s);
- 单任务 poison 隔离:一单元一交易,确定性 revert 精确进 DLQ。

同一 PRIVATE_KEY 同时只能有一个写入进程。配置 TELEGRAM_BOT_TOKEN 与
TELEGRAM_CHAT_ID 启用告警投递;RELEASE 在心跳中带构建标签。
