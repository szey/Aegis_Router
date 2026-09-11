# Aegis_Router MCP 执行许可试点

[English](enterprise-agent-pilot.md) | 简体中文

状态：**此前 Discovery 探索已结束；新的受控 MCP execution-permit 试点尚未开始。**

旧公司端点试用只证明限定目录扫描可产生配置证据，并暴露了权限错误、cache 噪声和 UI 刷新问题。它没有验证签名 Permit、MCP 执行前阻断或 replay defense，因此不是本试点的成功基线，也没有达到 `V3 pilot_verified`。

## 本试点只证明一件事

> 获得授权的 MCP 动作，必须与实际转发给上游的动作完全一致。

```text
受控 MCP client 提议 tools/call
  → Aegis 生成 CanonicalAction
  → Policy 授权精确动作
  → 签发短时 Ed25519 Permit
  → MCP boundary 在副作用前 verify + consume
  → VERIFIED 才转发给受控 upstream
  → 写入脱敏 Audit Receipt
```

本试点不评估通用 Agent 管理、Shadow discovery、sandbox、EDR、IAM 或全端点可见性。若公司 Agent 没有获准 MCP/工具代理入口，就不能用目录扫描或 Agent 自报日志替代真实执行边界；试点应暂停。

## 必须回答的问题

1. Principal、Agent、workload、delegation fingerprint、tool、capability、resource、operation 与安全参数是否进入同一规范动作？
2. 等价 JSON 键顺序是否产生同一 digest，金额/资源/工具/操作变化是否产生不同 digest？
3. Permit 是否验证签名、issuer、TTL 和所有绑定字段？
4. `permit_id` 能否始终与 `permit_token` 分离，前者绝不单独授权？
5. valid Permit 是否恰好调用一次 upstream 并转为 `CONSUMED`？
6. invalid signature、expired、revoked、wrong binding、action mismatch 或 replay 是否都使 upstream 调用次数为零？
7. 两个并发 replay 是否恰好一个成功？
8. UI、audit、errors 和 upstream metadata 是否都不泄漏 `permit_token`、raw delegated token 或原始敏感参数？
9. Demo 是否始终标记 `simulated_demo`，RuntimeEvent 是否明确只是辅助证据？
10. CPU、内存、延迟和审计增长是否在预先批准范围？
11. Side-effecting upstream 是否提供独立业务幂等机制，并且试点报告是否没有把单次 Permit 误写成 exactly-once 业务执行？

## 单次 Permit 与业务幂等

本试点只能证明同一个 Execution Permit 至多成功消费一次，不能证明任意上游业务副作用恰好发生一次。若 upstream 已完成动作但响应丢失，Aegis 仍保持原 Permit 为 `CONSUMED`；任何重试都需要新授权和新 Permit。付款、订单、账户变更、消息发送等有副作用工具必须使用 upstream 自己的业务幂等键或去重机制。试点不实现也不模拟 Aegis 业务幂等引擎。

## 授权与禁止范围

开始前必须取得设备负责人、IT/安全和数据负责人的书面批准，明确设备、操作者、MCP client/Agent、Proxy、upstream、测试工具、参数类别、时间窗、网络目标、保留时间、回滚和负责人。

只允许 synthetic 参数、测试凭据、无害本地工具和批准的 loopback/内网测试目标。禁止：

- 使用生产 Token、真实密钥、客户数据、员工数据或真实付款/删除/发布动作；
- 捕获其他员工会话、扫描未批准目录或监控公司全网流量；
- 绕过 EDR、DLP、防病毒、代理、证书策略或应用白名单；
- 将公司日志、路径、设备标识或 Permit token 上传到个人 GitHub、云盘或外部 AI 服务；
- 把 `isolation_required` 或旧 `SANDBOX` 字段当作 Aegis 已提供隔离；
- 将 Aegis 当作生产唯一阻断点。

项目契约中的 `allow_deploy=false` 与 company-device 显式授权要求保持不变；本协议不自行授予部署权限。

## Gate 0：本地 P0 回归

任何公司设备工作前，开发环境必须通过：

- valid Permit；
- invalid signature；
- expired 与 revoked Permit；
- wrong principal/agent/workload/tool/resource/operation；
- argument digest mismatch；
- sequential 与 concurrent replay；
- audit/token privacy；
- failed verification 后 MCP upstream 调用次数为零；
- MCP `2026-07-28` Header/body/version mismatch、重复 JSON key、任意 Header/Session 上下文、未绑定 Tool `_meta`、MRTR 或 `Mcp-Param-*` 输入在上游前 fail closed 或被剥离；
- Permit 含尚未满足的隔离或人工批准 obligation 时，产生 `EXECUTION_OBLIGATION_UNSATISFIED`，上游调用次数为 0；
- Demo telemetry 始终为 `simulated_demo`；
- `go test ./...`、`go test -race ./...`、`go vet ./...` 与前端检查/构建。

Race 工具链缺失必须作为未关闭门槛报告，不能写成通过。

## Gate 1：公司端点最小基线

- 再次确认书面范围；
- 按公司批准方式传输源码/二进制并核对 SHA-256；
- Server/Proxy 只监听获准接口，默认优先 `127.0.0.1`；
- 使用临时测试签名密钥，不复用生产/个人长期密钥；
- 使用本地无害 upstream MCP fixture；
- 记录空闲 CPU、内存、端口和审计目录；
- 不启用 `--enable-experimental-inventory`，除非另有独立书面需要。

Discovery 不属于这个 Gate 的验收内容。

## Gate 2：四个 focused Demo

| 场景 | 操作 | 预期结果 |
|---|---|---|
| Valid Permit | 授权并原样执行 `config.read` | `VERIFIED`；upstream 调用一次；Permit `CONSUMED` |
| Action Mutation / TOCTOU | 授权 `amount=100`，执行改为 `10000` | `PERMIT_ACTION_MISMATCH`；upstream 调用零次 |
| Permit Replay | 同一 token 使用两次 | 第一次 `VERIFIED`，第二次 `PERMIT_REPLAY` |
| Expired Permit | 过 TTL 后执行 | `PERMIT_EXPIRED`；upstream 调用零次 |

这些服务端 fixture 是 `simulated_demo`，只能证明本地确定性路径。

## Gate 3：真实 MCP 边界的受控接入

仅当公司 Agent/工具系统支持批准的 MCP client 或 Proxy 配置时进行。当前可执行子集只支持 `payment.send/v1`；必须使用 synthetic 金额和本地 mock upstream，绝不能连接真实支付服务商或凭据：

1. 把 `semantic_actions.payment_send_v1.upstream_url` 设为一个无害、可计数调用次数的本地 MCP mock，并使用完全相同的 `--mcp-upstream` 值启动 Aegis；
2. 由获准的认证中间件通过 Trusted Intake 建立 principal、Agent/workload 与 delegated authority；不要使用 `development_only` body intake 作为公司身份保证；
3. 对一次 `tools/call` 生成规范动作并调用授权 API，保存脱敏的 `authorization_context_provenance` 与 `signing_key_id`；
4. 将 `permit_token` 仅放在受控 client→Proxy 执行通道，不写入命令历史或截图；
5. Proxy 在转发前复用核心 verifier 并原子消费；
6. 使用 `2026-07-28` 时同时验证 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 与正文一致，并只在 `VERIFIED` 后转发；
7. 保存脱敏 receipt 和 upstream call counter；
8. 对每种负向结果重复验证 counter 为零；
9. 让一次已验证调用在 upstream 返回失败或 timeout，确认 Permit 仍为 `CONSUMED`；随后只有重新授权取得新 Permit 才允许重试。
10. 对有副作用的测试 Tool 使用 upstream 自己的幂等键；模拟“副作用成功但响应丢失”，确认记录明确区分 Permit 单次消费与业务 exactly-once，且不复用原 Permit。

若 WorkBuddy 或其他 Agent 无法配置获准 MCP 边界，本 Gate 不通过。不能通过修改公司 Agent、绕过策略或采集全机行为“补齐”测试。

## Gate 4：证据复核与退出

审计必须按 trust context、action、deterministic policy、obligations、Permit、verification、execution 的顺序回答 request/decision/permit ID、`signing_key_id`、`permit_class`、profile ID、audience、principal、Agent/workload、authorization-context provenance、tool、resource、operation、action digest、policy version、authorization decision、Permit state、verification outcome、upstream attempted、execution outcome、timestamp、evidence source 与 upstream call count；risk/detection 只能位于 advisory signals，且审计不得含 token 或原始敏感参数。

结束后停止 Aegis、Proxy 和测试 upstream，撤销所有未消费 Permit，删除临时私钥与 synthetic payload，并由公司负责人决定本地审计保留/删除。只有脱敏结论与 synthetic 最小复现可以返回公开仓库。

## 证据信任

| 来源 | 能证明 | 不能证明 |
|---|---|---|
| `gateway_enforced` / MCP Proxy receipt | 某次调用经过验证边界及其结果 | 公司 Agent 的所有动作都经过 Aegis |
| upstream call counter | 受控 test server 是否被调用 | 真实业务系统或任意 MCP Server 都安全 |
| `instrumented_adapter` | Adapter 报告的测试 metadata | OS 独立观察或全端点覆盖 |
| `simulated_demo` | Demo fixture 走过代码路径 | 真实 Agent、执行器或生产遥测 |
| `agent_self_reported` | Agent 声称发生某动作 | 完整、不可伪造事实 |

未接入能力保持 `UNKNOWN / not instrumented`。`UNKNOWN != SAFE`，也不等于零事件。

## 性能与通过门槛

以下是需要在授权前确认的试点目标，不是当前承诺：

| 指标 | 初始目标 |
|---|---:|
| Aegis 空闲平均 CPU | < 2% |
| Aegis 进程内存 | < 100 MB |
| Permit verify+consume 中位增量 | < 10 ms |
| Proxy 端到端中位延迟增量 | < 10% |
| 单次试点审计文件 | < 50 MB |

只有书面范围一致、P0/race 回归通过、真实 MCP 边界确实位于副作用前、所有负向结果 upstream 调用为零、并发 replay 只有一次成功、无 Token/敏感参数泄漏、性能/隐私数据留在批准边界且清理完成时，才可标为 `V3 pilot_verified`。
