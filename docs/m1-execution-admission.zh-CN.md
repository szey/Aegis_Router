# M1：消费前执行约束检查与固定 MCP 路由

[English](m1-execution-admission.md) | 简体中文

实施日期：2026-09-14。研究与代码基线：`11451c58d583041e4009d8799bfd07b17199b481`。按新版 `$research-to-product` 执行[重设计提案](manus-redesign.zh-CN.md)的 M1，处置 `implement`，交付状态 `completed`。本文说明已实现的本地边界；M2 持久事务、M3 外部沙箱和 M4 生命周期仍待实施。

## 研究如何改变代码

提案中的 R1/R3 提醒我们区分环境配置、Agent 自报与可信执行事实；M1/M3/M4 说明任务环境和生命周期需要独立控制。它们仍是外部 `V1` 资料，并未在本项目复现实验或沙箱逃逸。具体代码改动由本地 `REDESIGN-2026-09-13-06` 的 E02/E07 对照实验支持，其代码层证据升级为 `S1/V2`。

| 假设与实验 | 改动前观察 | 改动后验收 |
|---|---|---|
| E02：要求没有受信任的实施方时，应在消费前拒绝 | 核心验证器对五类要求都返回 `VERIFIED` 并消费；MCP 测试中的禁网要求仍产生一次上游调用 | 五类要求逐项拒绝；Permit 保持 `ISSUED`；相同 proof 再次请求仍返回约束拒绝，说明未消费 nonce；上游调用为零 |
| E07：服务端固定 URL 不允许 HTTP 重定向扩大目标 | 默认及自定义 client 对 301/302/303/307/308 都访问第二个 receiver | 返回 502；原目标一次、第二个目标零次；不转发 Location 或响应正文；Permit 保持 `CONSUMED`，重试不再发送 |
| 回归：合法动作、伪造身份、参数替换与 replay | 原有正负向测试 | 两项 profile 的合成无附加约束调用仍成功；并发 replay 至多一次；未知签名要求、审计失败和原有绑定失败不产生未经许可的调用 |

全部使用临时目录、合成身份与本机 mock HTTP 服务。测试日志保存在本地忽略目录 `tmp/m1-validation/`；仓库保留可重复运行的 fixture 和此处脱敏结论，不提交临时 token 或原始日志。

## 现在的执行顺序

```text
签名、issuer、用途、有效期与 Permit 状态
  → workload 持钥证明、精确动作绑定
  → executionconstraints：逐项解释并拒绝不支持的要求
  → proof nonce + 原子消费 Permit
  → Router 记录验证结果
  → MCP 向固定目标发送，禁止重定向
  → 记录边界结果；失败后不恢复 Permit
```

统一逻辑位于 `internal/executionconstraints`，由核心 verifier 在 nonce 和 Permit 消费之前调用，MCP 不再另写消费后的部分约束判断。签名未知字段仍由严格 Token parser 拒绝，不会在反序列化时被忽略。HTTP `POST /api/permits/verify` 仍是非消费诊断；`VALID_NOT_CONSUMED` 不验证环境要求，也不授权执行。

`constraint_checks` 是响应及 Audit Receipt 的新增安全元数据，包含 `requirement`、`status`、`scope`、`reason` 和 `checked_at`。时间表示 Aegis 判定时间，不表示外部控制已经安装。当前没有可信实施方，因此不会伪造 `enforcer_id` 或 `config_digest`，也没有接收 Agent 自报 `SATISFIED` 的接口。

| 要求 | 检查范围 | M1 结果 |
|---|---|---|
| `network_egress_denied` | 上游工具运行环境的直接出站 | `UNSUPPORTED`：未接入网络实施方；broker 连接 URL 固定不等于上游工具禁网 |
| `read_only` | 动作目标资源 | `UNSUPPORTED`：没有资源实施方；write/append/delete/transfer 另给出修改目标资源的冲突原因 |
| `isolation_required` | 上游运行环境 | `UNSUPPORTED`：未接入 runtime controller |
| `human_approval_required` | 同一规范动作 | `UNSUPPORTED`：没有审批完成链 |
| `enhanced_audit_required` | 调度意图 | `UNSUPPORTED`：本地 JSONL 不能证明持久的消费与调度事务 |

只在签名要求全部为空、其余许可检查通过时允许当前真实执行路径。未执行的 evaluator 零值为拒绝；未来新增要求也不能因缺少映射而放行。`SATISFIED / UNSUPPORTED / UNKNOWN` 是结果词汇，M1 没有能返回真实 `SATISFIED` 的外部控制集成。下一阶段添加实施方时必须验证作用范围、来源、配置版本和新鲜度；一个 `enabled: true` 开关不足以通过准入。

约束拒绝返回 `UNSATISFIED_OBLIGATION`，最终判定为 `EXECUTION_OBLIGATION_UNSATISFIED`；Permit 不消费。重定向拒绝的 execution outcome 为 `UPSTREAM_REDIRECT_BLOCKED`，最终判定为 `EXECUTION_REDIRECT_BLOCKED`；原目标已尝试，因此 Permit 保持已消费。重定向响应不能证明原目标是否已完成业务副作用。

## 兼容与迁移

这是对现有 signed obligations 的执行修正，不添加或改变 Token 字段，保留 v1 格式和现有两个语义 profile。以后引入 run/lease/epoch 绑定时仍需新契约版本。

**行为变化：默认示例策略对 payment 和 workspace 都要求禁网，真实 MCP 执行现在会被拒绝。** 原配置及项目安全字段保持原样。不能为了恢复旧行为自动删除要求或提供虚假“已满足”配置。部署方需要等候受信任的控制集成，或在明确理解实际工具权限后独立调整自己的策略。测试中的成功路径只对合成 mock 使用明确不要求上游禁网的策略，不能据此宣称隔离有效。

Server-owned simulation 保留为用途隔离的演示路径，不进行真实 MCP 转发。固定 URL 和禁止重定向只覆盖本次 HTTP 调度；不提供宿主防火墙、DNS/IP 固定、代理隔离、沙箱完整性、持久重放保护或业务 exactly-once。

## 验证记录

- 基线新增 fixture 按预期失败；修复后的核心、MCP 和 HTTP 集成测试通过。
- `go test ./...`、`go vet ./...` 通过；前端类型检查和构建通过，生成资源无变化。
- Windows 本机 `go test -race ./...` 因缺少 cgo 工具链未执行；`docker build .` 因 Docker Linux daemon 未运行未完成。Linux CI 的最终结果以本次提交对应的工作流记录为准。
- 本地 npm 启动脚本指向缺失文件，改用已有 npm CLI 运行相同 package scripts；esbuild 需要当前用户权限读取解析路径。未修改全局环境、依赖版本或项目脚本。
- 生命周期、真实网络隔离、崩溃恢复与端到端性能指标不属于本轮已验证能力；E03/E05/E06/E08–E11 和完整 E12 性能实验保留在后续阶段。
