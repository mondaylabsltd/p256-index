# WebAuthn P256 Public Key Registry 服务

一个中立、无权限的 P-256 passkey 公钥登记处:任何人都可以把自己持有的密钥
数据存到 Gnosis 链和本服务的数据库。这把钥匙用来干什么——派生钱包、组装
身份、还是别的用途——完全由存储方决定,承载在单元级的不透明 `metadata`
里。由 Vela Wallet 构建;Vela 是它的第一个客户,不是它的主人。

## 信任模型

- **三张表、两个写操作。**ENTRY 是 passkey 的全局档案(一把钥匙恰好
  一行,attestation 首见定格、由钥匙亲签);UNIT 是组(一把一次性组
  密钥恰好一个组,rpId、metadata、成员集创建即冻结——**组成员永不可
  变,也刻意不存在任何能改它的操作**);REFERENCE 是"一把 passkey 指
  向一个既有组"——独立的表、独立的计数,与组永不混淆。
- **持有与内容是被验证的东西——在链上验证。**每个签名者的 WebAuthn 格
  式 P-256 assertion 签在
  `keccak256(abi.encode(chainid, registry, rpId, publicKey, binding))`
  上,由 EIP-7951/RIP-7212 预编译验签。binding 按角色:组密钥签组的
  contentHash;成员签 `memberBindingFor(组公钥, 自己的attestation)`;
  引用者签 `referenceBindingFor(组公钥, attestation, 引用metadata)`。
  每个字节都在签名覆盖之下——抢跑、重放、内容替换在协议层不存在。
- **除此之外零独占、零解释。**一把钥匙可以出现在任意多个注册单元里;
  查询返回列表,读方按自己的 metadata schema 过滤。credentialId、显示
  名、钱包派生前像,全部编码在 `metadata`(≤2048 字节,不透明)里。
- **`register`** 一笔交易原子落地一个组(7 passkey = 8 个签名):组密
  钥静默收尾、用完即弃;成员 passkey 创建即签、乱序、互不等待。
  **`refer`** 让一把 passkey 指向既有组——后加设备的路径:纯发现数据,
  每 (组, 钥匙) 一条,组的冻结记录零触碰。**引用是声明不是授权**:被
  引用的钥匙能做什么,由读取方 schema 对照钱包层裁定。无 nonce、无消
  耗品,一切写入天然幂等。
- **统计是结构性的**:Entry 全局唯一、组密钥一次性,所以
  `getTotalEntries()` 就是 passkey 数,`getTotalUnits()` 就是组数,
  `getTotalReferences()` 独立计引用——没有任何去重逻辑。
- **读取是列表形态且 id 恒定。**entry id 顺序分配、永不变化——记住
  自己的 entry id 就能永远 O(1) 直读。无本地状态时的发现:从任意一次
  登录签名恢复两个候选公钥、各查一次——只有被持有的钥匙才可能有条目,
  所以至多一个桶非空。

## 客户端流程

1. enrollment 开始时客户端生成一次性组密钥(软件 P-256)。每把
   passkey:`create()` 收集公钥,然后一次 `get()`,其挑战 = 成员绑定
   挑战(`POST /api/challenge` 成员模式)——只依赖组公钥和自己的字段,
   顺序任意、设备任意、互不等待。每把钥匙两次弹窗。
2. 全部钥匙就位后,组密钥静默签收尾挑战(组模式返回 contentHash 与组
   挑战),`POST /api/register` 一笔提交,组私钥随即永久销毁。
3. 日后加设备:新 passkey create + 一次 get()(挑战带 `"refer": true`
   的引用模式),`POST /api/refer` 提交——组本体永不被触碰。登录发
   现:签名恢复候选公钥,`GET /api/query?publicKey=` 返回档案 + 组/引
   用 id 列表。
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
| POST | /api/register | 验签并持久化入队一个组(1..7 成员) |
| POST | /api/refer | 验签并持久化入队一条引用 |
| GET | /api/task/{id} | 任务状态(全量披露;不回显证明) |
| POST | /api/challenge | 成员/引用/组三模式,按角色算绑定挑战 |
| GET | /api/query?publicKey= | 该钥匙档案 + 组/引用 id(上链前带 `_queue` 标记) |
| GET | /api/query?entryId= | 按恒定 id 取单条 |
| GET | /api/query?groupPublicKey= | 组详情:冻结记录 + 成员档案 + 引用收件箱(上链前带 `_queue` 标记) |
| GET | /api/query?unitId= | 按恒定 id 取同一份组详情 |
| GET | /api/stats/total | {totalEntries, totalUnits, totalReferences, totalRpIds} |
| GET | /api/stats/sites | 分页 rpId 列表 |
| GET | /api/stats/keys?rpId= | 某 rpId 下的分页组列表 |
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

## 许可证

MIT,见 [LICENSE](LICENSE)。`contracts/src` 中的合约使用同一 SPDX 标识;`contracts/lib`
下的子模块(forge-std、p256-verifier)保留各自的许可证。
