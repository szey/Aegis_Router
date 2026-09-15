# 授权与执行必须指向同一件事

[English](authorization-execution-binding.md) | 简体中文

复核日期：2026-09-15。代码基线：`6e4d77197668afe91ddcd53527c9ce4f97b17641`。使用 `research-to-product` 从一手资料、当前代码和合成实验形成决策。

后续交付：本文保留 `797b9c5` 之前的研究/首次修复快照；下方 planned 状态是当时决策。最新状态见 [PreparedExecution 与权限版本实现记录](prepared-execution.zh-CN.md)：02 已实现、04 的进程内 epoch 子集已实现、03/05 的合成契约实验完成；真实资源/broker 和持久事务仍未交付。

## 1. 结论与当前交付

用户提出的“检查的对象、范围或身份，和最后真正执行的不是同一个东西”，适合成为 Aegis 的设计原则；这里没有证据为“最危险、往往”作发生频率或严重性排名，也未确认这句话的原始出处。

这次找到了一个实际缺口：MCP 顶层 JSON-RPC 字段通过 Go 的大小写宽松匹配解析，而无需 Permit 的协议请求会转发原始正文。一个请求可以被 Aegis 判断为 `tools/list`，被严格按字段名读取的上游判断为 `tools/call`。原有重复键检查无法识别 `method` 与 `METHOD`，因为它们确实是两个不同的 JSON key。

本轮已修复这个入口，增加负向集成测试及合法调用对照。路由配置、对象版本、权限撤销时序和环境 lease 仍是下面明确标记的设计工作；没有把它们算作已实现，也没有修改 Permit v1、默认禁网策略或增加沙箱。

## 2. 证据与适用范围

以下来源均于 2026-09-15 检索；全文可访问，审阅范围以 locator 为准。来源权威性与本项目验证状态分开记录。

| 证据 | 版本、日期、locator | 可迁移机制与限制 |
|---|---|---|
| JSON-RPC 工作组规范，`S1/V1` | [JSON-RPC 2.0](https://www.jsonrpc.org/specification)，2013-01-04 更新，§2、§4 | 成员名匹配区分大小写。Aegis 的 envelope 分类必须遵守这个规则；并非要求拒绝所有等价 JSON 编码。 |
| Go 标准库维护者文档，`S1/V1` | [encoding/json.Unmarshal](https://pkg.go.dev/encoding/json#Unmarshal)，滚动文档；本机实测 Go `1.26.0 windows/amd64` | struct 解码接受大小写不敏感的字段匹配，未知成员默认忽略。单独使用 `DisallowUnknownFields` 不能解决大小写别名。与上一行构成同一 parser-differential 证据家族；本项目复现另记为 `V2`。 |
| MITRE CWE，`S1/V1` | [CWE-367](https://cwe.mitre.org/data/definitions/367.html)，页面更新 2026-04-30，Description、Example 2 | 通过名称检查后再打开，名称可能已经指向另一个对象。映射到未来 workspace 执行方：路径摘要不能替代稳定对象句柄或原子条件写入。当前 Aegis 不打开文件，未在本项目复现文件竞态。 |
| IETF，`S1/V1` | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)，2019-09，§2、§3 | audience 可以是抽象标识，客户端仍要独立确认实际网络端点与该标识对应。Aegis 的 audience 字符串绑定不会自动证明上游归属；这里借用约束设计，不声称实现 OAuth。 |
| MCP 维护者指导，`S1/V1` | [Security Best Practices](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices#token-passthrough)，检索时 draft，Token Passthrough | 错误 audience 与原样透传凭据可能使代理借自己的信任关系执行请求。Aegis 已剥离入站授权/Cookie，不能据此声称完成下游身份认证；draft 不替代项目固定协议版本。 |
| Google 系统论文，`S1/V1`（作者自身系统记录） | [Zanzibar](https://storage.googleapis.com/gweb-research2023-media/pubtools/5068.pdf)，USENIX ATC 2019，§2.2，PDF 第 2–3 页 | “new enemy” 问题说明权限更新与内容更新需要满足因果顺序。可借鉴权限 revision 和资源版本的关联；没有理由为这个单节点原型引入完整 Zanzibar/Spanner，也未验证其性能结论可迁移。 |

## 3. 沿现有执行链审查

| “同一个”维度 | 已有保障与代码定位 | 仍缺什么；证据级别 |
|---|---|---|
| 同一条 RPC | `adapters/mcp/proxy.go` 的 canonical JSON、Header/body 比对、Tool params 白名单；本轮增加精确 envelope key 检查并重建协议正文 | 修复前顶层大小写别名可绕过 Permit；本地 `V2`，见 §4。没有声称完整 MCP conformance。 |
| 同一身份与执行者 | `intake/trusted_proxy.go` 用可信上下文覆盖 proposal；`verifier/verifier.go:verifyExecutionProof/actionBindingOutcome` 比对 principal、Agent、workload、delegation 和 key thumbprint | 证明持钥，不证明代码完整性；下游连接使用谁的身份仍由可信部署方负责。当前不增加 IAM。 |
| 同一业务动作 | 两个内置 semantic profile 归一参数，`canonicalaction.Action` 绑定 tool、capability、resource、operation、profile、audience、参数摘要 | `workspace.write` 的逻辑路径没有 inode/对象 generation；支付 recipient 标识没有上游账户目录版本。属于外部执行方契约缺口，`V1`。 |
| 同一服务与配置 | `cmd/server/main.go` 将 `r.SemanticRegistry()` 交给代理；M1 禁止全部 HTTP 重定向 | `mcp.New` 可传另一 registry，`Action` 不包含 `UpstreamURL`/配置摘要。同 audience 不同路由无法仅靠 v1 摘要区分。默认共享配置是反证：尚未证明部署中的远程路由利用；本轮仅代码审查 `V1`。 |
| 同一授权状态 | 签名短期 Permit、注册 claims 比对、内存原子消费/撤销、消费时再次检查有效期 | `policy_version` 记录签发版本，不是当前权限 epoch 检查；没有 run 级撤销或持久事务。当前无热重载，重启未知 Permit 会拒绝；不能误报为现有重启 replay。 |
| 同一执行环境 | M1 在消费前拒绝缺乏实施方的五类 obligations | 没有独立 runtime、lease/generation 或环境证明。Agent 自报不能填补这个缺口。 |
| 同一次业务提交 | 消费在调用前，上游失败不恢复 Permit | 本地一次消费不等于上游业务恰好一次；响应丢失时，业务可能已经提交。需要 intent、去重和查询协议，不能自动重发。 |

上述路径相对 `internal/`，除显式写出的 `cmd/server/main.go`。现有身份、参数、replay、obligation、redirect 用例继续作为回归对照。

## 4. 已完成的对照实验与修复

**假设与预先验收：**顶层字段精确匹配，并仅转发已分类的 envelope，应令所有别名输入在上游前以 HTTP 400 拒绝，调用数为 0；合法协议和合法 Permit 调用继续通过。错误 envelope 不应消耗有效 Permit 或 nonce。

**环境：**只使用 `httptest` 本地模拟上游，无外部目标、真实账户或生产数据。攻击用例保留原始禁网策略，授权端与代理共享同一个 registry；只将服务端 route 指向本地接收器。模拟接收器用 `map[string]json.RawMessage` 精确读取 `method`，独立计数总请求与工具调用。测试没有提供 Permit、proof 或身份。

| 实验 | 修复前 `6e4d771` | 修复后 |
|---|---|---|
| `method=tools/call` 后添加大小写别名为 `tools/list`：`METHOD`、`MeThOd`、转义大写首字符；旧兼容/现代协议共 6 组 | 全部 HTTP 200；每组 upstream request=1、tool call=1 | 全部 HTTP 400；每组两个计数均为 0 |
| 初始探针使用别名 `ping` | 旧兼容 3 组到达工具；现代协议 3 组被拒绝，因为现代白名单无 ping | 用两种协议都允许的 `tools/list` 校正对照；没有把现代 ping 的拒绝当成漏洞复现 |
| 其他 envelope 别名、逆序字段、未知扩展共 7 组 | 未单独执行，不追认基线结果 | 全部 HTTP 400 / RPC `-32600`，upstream=0 |
| 正确小写键的 Unicode 转义，旧/现代协议共 2 组 | 未单独执行 | 合法 `tools/list` 各调用一次，method/id 一致 |
| 有效 Permit/proof 遇到错误 envelope，然后原样 proof 重试合法工具调用 | 未单独执行 | 第一次不消费；第二次成功消费且上游仅调用一次。成功对照使用明确无附加约束的合成策略。 |

生产改动只在 `internal/adapters/mcp/proxy.go`：canonicalizer 先拒绝重复键和有损 JSON；`parseRPCEnvelope` 再限定顶层精确字段 `jsonrpc/id/method/params`；路由分类后，协议分支重新编码同一 envelope。`tools/call` 继续使用现有语义参数归一和核心 verifier，没有第二套摘要或许可逻辑。

**兼容影响：**以前被忽略的未知顶层成员和大小写别名现在被拒绝。顶层扩展必须先有显式绑定契约；合法小写字段、等价 Unicode 转义、两个业务 profile 均保留。参数/schema 的未来扩展另审，不顺带切换 JSON 库或修改 token 格式。

重复命令：`go test ./internal/adapters/mcp -run 'TestEnvelope|TestExactProtocolEnvelope|TestInvalidEnvelope' -count=1 -v`。Windows 本机全量 `go test ./...`、`go vet ./...`、前端类型检查/构建、项目契约校验均退出 0。`go test -race ./...` 因 cgo 未启用退出 1；`docker build .` 因 Linux engine named pipe 不存在退出 1。Linux CI 的最终证据以本次 PR 对应 head 为准。本地 `V2` 只证明上述解析与派发属性，不证明某个生产上游受影响或真实隔离成立。

## 5. 下一步按什么顺序迭代

| 优先级 / research_id | 处置 / 交付状态 | 设计、依赖与迁移 | 可证伪验收 |
|---|---|---|---|
| P0 `BIND-2026-09-15-01` | `implement` / `completed`，`S1/V2` | 本轮 envelope 修复与回归；不改 v1 | §4 的负向零调用、合法对照与 nonce 保留 |
| P1 `BIND-2026-09-15-02` | `experiment` / `planned`，`S1/V1` | 在 M2 前验证服务端 `PreparedExecution`：同一个不可变结果携带 action、归一正文、profile revision、route binding、credential binding。构造接口禁止随意拼接不同 registry；若需跨进程/热重载，设计显式 Permit v2 | 同 profile/audience 但不同 route/config/凭据映射：消费前拒绝；正确共享配置正常。仅改端点地址的合法运维迁移必须重新授权或有受控映射。 |
| P1 `BIND-2026-09-15-03` | `experiment` / `planned`，`S1/V1` | 在已有 `workspace.write` profile 的模拟执行方验证稳定 object ID、workspace namespace、expected generation；最终写入方执行原子条件写入。连接真实文件系统再考虑安全句柄/路径解析；不增加新 Adapter | 授权后替换同名对象或改变 generation，实际写入数为 0；原对象正确版本仅写一次。只在 Router 再读一次不算通过。 |
| P2 `BIND-2026-09-15-04` | `experiment` / `planned`，`S1/V1` | 承接 M2 持久事务、M4 生命周期；持久 store 中把当前 authority epoch、Permit 状态、nonce、dispatch intent 放在同一准入事务。需要定义撤销线性化点 | 撤销先提交则旧 epoch 不消费/不派发；消费先提交则记录在途，不能承诺撤销已经发生的副作用；崩溃和响应丢失保留 unknown，不自动重发。 |
| P3 `BIND-2026-09-15-05` | `defer` / `planned`，`S1/V1` | 承接 M3：可信 broker 验证 lease generation、环境 policy digest、执行者身份与 action 共同绑定；依赖外部实施方 | 旧 lease、错 executor、错 scope、缺失控制均拒绝；真实隔离需要独立目标环境验证，mock 不升级为 V3。 |

这些实验归 Aegis 维护者所有；在对应实现启动或引入新 semantic profile、配置热重载、外部 runtime 时复核。当前不引入完整 IAM、多租户平台、调度器或任意工具插件。

## 6. 目标契约及停止条件

下一版的候选结构是：

```text
trusted identity + caller proposal
  → strict parse → server-owned PreparedExecution
  → policy decision over the same resolved action
  → versioned Permit binds action + route/profile/credential binding
    + stable resource/version + authority epoch + lease/obligations
  → transactional admission + durable intent
  → dispatch the prepared request through a bound executor
  → upstream conditional commit + receipt (or explicit unknown)
```

这是设计目标，不是当前运行顺序的描述。现有 Policy 先判断资格，再做语义解析；未来重排必须证明语义解析不会放宽先前拒绝，所有依赖的 side-effect/destination/size 字段来自同一已解析对象。

`PreparedExecution` 必须是服务端构造的不可变值，不把客户端传入 digest 当权威。credential binding 只保留安全标识或指纹，不存秘密；路由 hash 不能代替 TLS/端点认证；签名资源版本只有最终执行方原子验证才有效。v2 若必需字段缺失即拒绝，不让 v1 静默获得 v2 的保证；升级需显式切换并重新授权。

采用下一阶段方案的条件是其负向实验通过且原有合法流程不回退；若收益仅依赖自报状态、不能约束实际副作用或引入大量误拒绝，就缩小方案或延期。不要为了“检查更多字段”而扩大承诺。
