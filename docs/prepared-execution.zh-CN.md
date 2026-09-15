# PreparedExecution 与权限版本实现记录

[English](prepared-execution.md) | 简体中文

日期：2026-09-15。基线：`797b9c5c4e3b0d69a36e5d27619c1aace3d2da01`。承接[授权与执行一致性研究](authorization-execution-binding.zh-CN.md)中的 `BIND-2026-09-15-02` 至 `05`，继续使用该文的一手来源和适用性分析。本次不把外部论文或规范升级为本项目运行证明。

## 1. 已交付与尚未交付

已接入真实 MCP 路径的是不可变 `PreparedExecution`、Permit v2 路由/配置绑定，以及进程内权限 epoch 与批量撤销。资源版本和 lease 已完成独立最终写入方的合成契约实验，**尚未接入 Server、Docker、E2B 或真实文件系统**。完整 M2 持久事务与 M3 外部 broker 仍未完成；没有声称整条重设计路线已经结束。

## 2. 解析结果如何贯穿授权与派发

`internal/semanticaction/prepared.go` 的私有字段保存动作、typed normalized arguments 和上游地址。getter 返回参数副本，调用方改动输入或返回值不会改变快照。Prepare 拒绝 profile 改写可信身份/范围、返回不同路由，或使动作参数与派发参数不一致。

每个内置 profile 在构造时计算 `execution_binding`：对带 schema `aegis.prepared-execution/v2` 的 profile 配置、精确上游 URL 和 `credential_mode=anonymous` 作 canonical JSON/SHA-256 摘要。配置可变 map 后续修改不会改变已构造 profile 的控制或摘要。workspace 的默认大小限制在摘要前归一；其他配置列表的重排仍可能要求重新授权，这是保守的配置身份规则。

授权端和执行端各自生成 PreparedExecution，并用签名动作摘要证明两次解析的绑定相同；不是跨 HTTP 保存同一个 Go 对象，也不持久保存原始参数。`CanonicalAction` 包含 execution binding，Permit claims 也显式绑定它。Proxy 使用同一 PreparedExecution 的 action、arguments 和 route，消费前发现不同绑定返回 `WRONG_EXECUTION_BINDING`。不同 registry 若内容完全匹配可以互操作；不能依靠相同 profile ID/audience 隐藏配置变化。

摘要用的 canonical 数字表示与业务 wire encoding 分开：整数 `100` 可以在摘要中表示为 `1e2`，向上游发送的仍是 profile 的 typed JSON `100`。这样不会让 Go 整数字段解码或已有上游契约发生回退。

当前上游身份明确为匿名：剥离入站凭据；禁止 URL userinfo、query、fragment，以及自带 CookieJar/custom RoundTripper 的 HTTP client；使用私有、无客户端证书的 transport。调用方的 timeout 和不可变 redirect 限制保留。URL 摘要不证明端点归属，也不替代 TLS 服务器身份或宿主/代理网络信任。带凭据的上游需后续显式 credential binding，不能借 custom transport 绕过匿名契约。

Policy 不再只相信客户端声明的 bytes/side_effect。两个编译 profile 从归一参数生成 PolicyFacts：workspace 使用 UTF-8 content 字节数和 logical_workspace_write；payment 使用归一参数字节数和 financial_transaction（金额不当作字节）。保留初次资格检查的拒绝，只有已授权动作在 Prepare 后再以这些事实检查 Policy；客户端较大的字节声明仍保持保守限制。该二次检查不能把第一次拒绝变成允许。

## 3. Permit v2 迁移

真实 MCP 授权现在签发 header `v=2`，要求签名 claims 中同时有非空 `execution_binding` 和正整数 `authority_epoch`。v1 格式继续供旧底层校验/模拟用途使用；当前 MCP 路径总是复算非空 binding，因此旧 v1 execution Permit 无法匹配。签名正确但版本与绑定字段组合错误也拒绝。

客户端应重新授权，并用响应中的 action digest 生成 proof；不能沿用 v1 自行拼接的摘要。没有给客户端增加可决定 binding/epoch 的 JSON 输入字段。安全的 binding/epoch 元数据进入 Permit 响应、verification、envelope 和 receipt；原始 route、秘密和参数不会因此进入正常审计。Workload proof 格式未改变，仍绑定 Permit ID、action digest、HTTP method/path、时间与 nonce。

升级时不尝试把旧 Permit 转换为 v2，也不保留默认策略以外的“临时允许”通道。两个业务 profile ID 保持原名；这是 execution-Permit 格式升级，不是第三个 semantic profile。

## 4. 权限变更与消费的先后

`AuthorityKey` 精确表示 principal、Agent、workload 的授权域。Router 在 Policy 判断前读取 epoch，把它带到签发；Store 注册时在锁内检查 epoch 仍一致且 authority 启用。撤销在 Policy 判断后、注册前发生，旧判断无法注册有效 Permit。

可信 Go 集成可调用 `Router.SetAuthorityEnabled(key, enabled)`。该入口没有未经认证的 HTTP 对应 API。每次调用都会递增 epoch，包括 enabled→enabled 的策略刷新；停用时新的授权结果为 `DENIED/AUTHORITY_REVOKED`，所有未消费的 execution Permit 被撤销。重新启用必须重新授权，不恢复旧 Permit。模拟用途不参与这一 authority 撤销。

消费与权限状态检查使用同一个 Store mutex：撤销先提交，则旧 Permit 不消费；消费先提交，则保留 `CONSUMED` 的在途结果，不能承诺撤销已经发生或将要发生的上游副作用。审计更新发生在控制状态提交之后，审计失败不回滚权限状态。既有 nonce 验证与此 Store 仍是两个进程内组件，未实现 nonce/Permit/dispatch intent 的持久原子事务。

**持久化边界：**epoch 和禁用状态目前只存在内存；重启后旧 Permit 因未注册而拒绝，但“该 authority 禁用”的管理状态不会自行恢复。真实部署必须由可信身份/策略系统重新建立决定；在持久 Store 完成前不能把这个 API 当作跨重启 IAM 封禁。签发 key、权限版本和 intent 的持久恢复仍属于 M2。

## 5. 可重复证据

| 实验 | 对照/验收与结果 | 范围 |
|---|---|---|
| 修改同 audience/profile 的上游路径或币种限额 | 在基线两组均 HTTP 200、调用 1 次、Permit CONSUMED；修复后均 403、调用 0 次、Permit ISSUED | 真实 MCP 测试，合成策略仅去掉附加义务；默认禁网策略未改 |
| 低报实际字节/副作用 | 此分支加入二次 Policy 检查前，6 UTF-8 字节申报 0、workspace/payment 申报 none 三组均 AUTHORIZED；修复后均 DENIED、无 Permit | 同一 MCP 授权集成测试；精确规则分别为 max_bytes_exceeded 和 side_effect_not_granted |
| 参数快照、错误 profile 与 v2 降级 | 修改 getter/input 缓冲区不改快照；身份/资源/route/派发参数不一致拒绝；正确重签但版本不配套的 token 拒绝 | 核心 unit/contract tests |
| authority 停用/重启用 | 旧 token 与停用后的新请求拒绝；重新启用只允许 epoch 3 的新 Permit | MCP 集成，进程内 |
| 权限变化发生在判断后/注册前；并发消费/撤销 | 旧 epoch 注册拒绝；64 轮并发只允许 CONSUMED 或 REVOKED 的单一先后结果，撤销完成后不能再次消费 | Store 原子性；没有跨进程证明 |
| 撤销后审计故障 | 临时审计文件被目录替换导致持久化失败；authority 仍停用、Permit 仍 REVOKED、上游调用 0 次 | 本地故障注入，不访问真实审计数据 |
| 最终执行方的资源与 lease 契约 | 八组：同名对象替换、资源 generation、namespace、lease generation、executor、scope、环境 policy、到期；只验动作的对照各写 1 次，最终比较后各写 0 次；合法调用写 1 次，32 个竞争写入也仅一次 | `experiments/executionbinding/contract_test.go`，独立签名 controller grant 和内存 writer，未使用真实 Permit/文件系统/runtime |

命令：`go test ./internal/adapters/mcp ./internal/semanticaction ./internal/permit -count=1` 和 `go test ./experiments/executionbinding -count=1 -v`。所有这些检查已运行并通过。旧的成功派发 fixture 现在在签发前配置正确上游，消除授权/执行两份测试配置不一致；没有放宽生产策略来修复测试。

本机全量 Go 测试、vet、项目契约检查通过；完整前端、race、Docker 与 Linux CI 结果在此次 PR 中记录。Windows 的 cgo 和 Docker daemon 限制不得记成通过。

## 6. 下一阶段外部 broker 的验收入口

| research_id | 当前处置 / 状态 | 下一步 |
|---|---|---|
| `BIND-2026-09-15-02` | `implement` / `completed`，本地 `S1/V2` | 跨进程、有凭据传输模式另行验证 |
| `BIND-2026-09-15-04` | `implement` / `completed`，仅进程内 epoch 子集 `S1/V2` | 持久 store、nonce 与 dispatch intent 仍 planned，不能将父里程碑 M2/M4 标完成 |
| `BIND-2026-09-15-03` | `experiment` / `completed`，仅合成契约 `V2` | 对现有 workspace profile 接入服务端获得的稳定 ID/version，并由最终写入方原子验证 |
| `BIND-2026-09-15-05` | `experiment` / `completed`，仅合成契约 `V2` | 选择外部 runtime 后，由可信 controller 发 lease；真实控制测量仍 `V1`，未部署 |

优先考虑本地 Docker 参考集成，但本次不把平台选择当作安全证明。接入前必须固定 controller 身份、container/lease generation、workspace 所有权、最终写入的条件提交、可信凭据模式与失败恢复。Guest 可绕过 broker 写同一资源、只在 Router 查一次版本、或仅比较 Agent 自报的 lease，都不满足验收。仍保持 MCP 作为唯一执行 Adapter，不扩展为通用 IAM、调度器或自研沙箱。
