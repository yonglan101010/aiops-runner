# Trusted Claude 修复会话 v1 协议契约

> 状态：CURRENT（AIOps 控制面、runner 私有接口、飞书卡片与 UI 使用同一份 v1 契约）
>
> Schema：[`trusted-repair-contract-v1.schema.json`](./trusted-repair-contract-v1.schema.json)

> 阅读提示：这是 AIOps 控制面与 Runner 之间的接口规范，不是部署教程。它刻意写得严格：当会话、审批、回调或事件顺序出现歧义时，系统必须停下来交给人处理，而不是尝试“智能补救”。日常安装和运维请先看仓库根目录的 [README](../../README.md)。

## 1. 协议边界

- `trusted_claude_session` 使用独立 `RepairSession`、本契约的 `proposal_hash` 和 `/aiops/repair-sessions/*`。
- 同一个 `claude_session_id` 贯穿诊断、审批、执行、高风险确认和验证。
- 功能须由 AIOps Provider、runner 开关和目标 allowlist 同时启用。
- `repair_id` 是保留的可空关联字段；新会话固定传 `null`。
- 本文冻结跨仓 v1 wire contract；任何不兼容变更必须发布新 schema 版本。

## 2. 版本与未知字段

- 所有 v1 wire 对象携带 `schema_version: "1.0"` 和唯一 `kind`。JSON Schema draft 2020-12 是结构权威。
- 已知 v1 对象在所有安全相关层级均为 closed object（`additionalProperties: false`）；未知字段返回 `TRUSTED_REPAIR_VALIDATION_FAILED`，不能被静默忽略。
- 任意 wire 对象（包括 runner 事件与终态回调）遇到未知、缺失或格式错误的 `schema_version` 均 fail-closed，返回 HTTP 422 / `TRUSTED_REPAIR_UNSUPPORTED_SCHEMA_VERSION`；AIOps 不保存 payload、不推进状态，runner 只保留本地 journal。不存在 202 隔离或最小 envelope 兼容路径。
- 新增、删除或改变字段语义必须发布新 schema 版本；改变 hash 覆盖字段或 canonical bytes 还必须发布新 algorithm ID。

## 3. RepairProposal 与 proposal_hash

`RepairProposal` 冻结诊断结论、根因、证据、目标、完整初始命令、影响范围、回滚指引、验证步骤和风险摘要。`confidence` 使用 0 到 1 的十进制定点字符串，禁止跨语言 float 漂移。命令与验证步骤的 `sequence` 必须由业务校验保证从 1 连续递增且不重复。

算法 ID：`aiops-trusted-repair-proposalhash-v1`。

覆盖字段（顺序仅用于说明）：

```text
schema_version, proposal_revision, diagnosis_summary, root_cause, evidence,
confidence, target, initial_commands, expected_impact, affected_scope,
rollback_instructions, verification_steps, risk_summary
```

`kind`、`proposal_hash_algorithm_id` 和 `proposal_hash` 不进入自身摘要。除这三项外，v1 proposal 的所有字段均进入摘要；因此未知字段必须先拒绝，绝不能出现“展示了但未摘要”的字段。

唯一合法入口顺序固定为：完整 JSON Schema（含所有嵌套 closed object）→ 语义校验（kind、algorithm ID、连续 sequence）→ canonicalize → hash 比对。任一步失败即停止；禁止先摘字段求 hash 后再做 Schema 校验。所有层级的未知字段、任意 float、错误 kind、错误 algorithm ID 和未知 schema version 均 fail-closed。

Canonical 规则采用可验证的确定性序列化：递归 Unicode NFC、对象 key 升序、数组保序、紧凑 JSON（UTF-8、`ensure_ascii=false`）、禁止 float，最后 `sha256:` + 64 位小写 hex。v1 不采用 RFC 8785 数字序列化，跨语言实现必须以黄金向量为准。

首次审批必须同时精确匹配 `session_id + proposal_revision + proposal_hash_algorithm_id + proposal_hash`。proposal 修改必须递增 revision、生成新 hash，并使所有旧审批失效。

## 4. RepairSession 状态机

非终态：`PREPARING`、`DIAGNOSING`、`PENDING_APPROVAL`、`EXECUTING`、`AWAITING_RISK_CONFIRMATION`。

终态：`DISPATCH_FAILED`、`DIAGNOSIS_ONLY`、`DIAGNOSIS_FAILED`、`SUCCEEDED`、`FAILED`、`REJECTED`、`EXPIRED`、`CANCELLED`、`MANUAL_INTERVENTION`。终态不可覆盖。

| from | event | to |
| --- | --- | --- |
| PREPARING | runner_accepted | DIAGNOSING |
| PREPARING | dispatch_failed_definitive | DISPATCH_FAILED |
| PREPARING | dispatch_uncertain | MANUAL_INTERVENTION |
| PREPARING | cancel_confirmed | CANCELLED |
| DIAGNOSING | diagnosis_completed_no_repair | DIAGNOSIS_ONLY |
| DIAGNOSING | diagnosis_failed | DIAGNOSIS_FAILED |
| DIAGNOSING | diagnosis_uncertain | MANUAL_INTERVENTION |
| DIAGNOSING | proposal_created | PENDING_APPROVAL |
| DIAGNOSING | cancel_confirmed | CANCELLED |
| DIAGNOSING | cancel_uncertain | MANUAL_INTERVENTION |
| PENDING_APPROVAL | approval_granted | EXECUTING |
| PENDING_APPROVAL | approval_rejected | REJECTED |
| PENDING_APPROVAL | approval_expired | EXPIRED |
| PENDING_APPROVAL | cancel_confirmed | CANCELLED |
| EXECUTING | execution_succeeded | SUCCEEDED |
| EXECUTING | execution_failed | FAILED |
| EXECUTING | execution_uncertain | MANUAL_INTERVENTION |
| EXECUTING | cancel_confirmed | CANCELLED |
| EXECUTING | cancel_uncertain | MANUAL_INTERVENTION |
| EXECUTING | risk_confirmation_requested | AWAITING_RISK_CONFIRMATION |
| AWAITING_RISK_CONFIRMATION | risk_confirmation_granted | EXECUTING |
| AWAITING_RISK_CONFIRMATION | risk_confirmation_rejected | REJECTED |
| AWAITING_RISK_CONFIRMATION | risk_confirmation_expired | EXPIRED |
| AWAITING_RISK_CONFIRMATION | cancel_confirmed | CANCELLED |
| AWAITING_RISK_CONFIRMATION | execution_uncertain | MANUAL_INTERVENTION |

未列出的转换均返回 `TRUSTED_REPAIR_STATE_TRANSITION_INVALID`。`diagnosis_uncertain` 仅表示诊断是否完整结束无法确认；确定性诊断失败仍使用 `diagnosis_failed`。只有 runner 能确认本地 Claude 已停止且命令结果确定时才可发 `cancel_confirmed`；否则必须发 `execution_uncertain`。runner 重启发现未完成诊断使用 `diagnosis_uncertain`，发现未完成执行使用 `execution_uncertain`；等待审批或高风险确认且 journal 完整时保持原状态。任何不确定分支都不得自动 resume、重试或创建新的 Claude 会话。

AIOps 在派发诊断前创建初始 `PREPARING` snapshot；此时 `claude_session_id` 与 `proposal_revision + proposal_hash_algorithm_id + proposal_hash` 三元组必须全部为 `null`。runner 明确受理时，`runner_accepted` 必须在一个原子语义中绑定非空 `claude_session_id` 并转入 `DIAGNOSING`。从 `DIAGNOSING` 起，所有状态（包括诊断、取消和执行终态）都必须保留同一个不可变 Claude session ID。

只有三个派发前分支可在没有 Claude ID 时终结，且必须用 previous snapshot 证明直接来自 `PREPARING`：`dispatch_failed_definitive → DISPATCH_FAILED`、`cancel_confirmed → CANCELLED`、`dispatch_uncertain → MANUAL_INTERVENTION`。`claude_session_id` 从 `null` 首次变为非空只有两个合法入口：`PREPARING → DIAGNOSING` 的 runner 受理，或 runner 迟到回调对 `MANUAL_INTERVENTION → MANUAL_INTERVENTION` 的原状态补绑定。其他状态、终态或状态保持均不得补绑，包括 `CANCELLED`、`DISPATCH_FAILED`，以及从无绑定的 `MANUAL_INTERVENTION` 转入诊断或成功。迟到回调只补录 Claude binding 和审计，禁止自动 resume、改变状态或业务重试。`DIAGNOSIS_FAILED` 专指 runner 已受理并绑定 Claude 后的诊断失败，不能表示派发失败。

RepairSession 状态转换事件和 ExecutionEvent 审计事件是两个命名空间：`runner_accepted` 是唯一的 `PREPARING → DIAGNOSING` 状态事件，并对应第一条 runner 审计事件 `session_created`；`diagnosis_started` 只表示 Claude 诊断进程已经启动，是 `DIAGNOSING` 内的审计事件，不触发第二次状态转换。

API 和数据库持久化继续使用上表英文稳定码。所有前端与飞书展示必须使用共享 `STATUS_DISPLAY_ZH_CN` 映射，禁止直接显示英文状态码或各自维护中文文案。

## 5. ExecutionEvent 与批次

- 序号从 1 开始，严格等于 AIOps 已接受的最后序号 + 1；批内也必须连续，且 `first_sequence`/`last_sequence` 与首尾事件一致。
- `event_fingerprint` 为该事件移除 `event_fingerprint` 后，按 §3 canonical 规则计算的 SHA-256。
- 重放同一 `event_id` 且 fingerprint 与完整规范化内容相同，幂等成功；同 `event_id` 内容不同返回 `TRUSTED_REPAIR_EVENT_CONTENT_CONFLICT`。
- 已占用的 sequence 内容不同、gap、倒序或批内重复返回 `TRUSTED_REPAIR_EVENT_SEQUENCE_CONFLICT`。服务端不缓存乱序事件等待补洞。
- 一个 batch 在同一事务内完整校验、完整写入；任何事件失败则整批不落库。
- 纯 ingest 判定器输入为 `last_accepted_sequence`、`event_id → (sequence, fingerprint)` 与 `sequence → (event_id, fingerprint)` 两份历史索引。全量重放返回 `idempotent`；连续新批或“幂等前缀 + 连续新后缀”返回 `new` 并只列出新事件；同 ID 不同 fingerprint 返回 `TRUSTED_REPAIR_EVENT_CONTENT_CONFLICT`；sequence 已占用、gap、倒序、新事件后再出现重放或历史索引互相矛盾均返回 `TRUSTED_REPAIR_EVENT_SEQUENCE_CONFLICT`。
- 判定任何 incoming event 前，必须全量校验历史快照：sequence 索引恰好覆盖 `1..last_accepted_sequence`，ID 索引条目数等于 last，两份索引逐项双向一致，且每个 sequence 都落在已接受范围。即使矛盾历史未被本批触及，也必须返回 `TRUSTED_REPAIR_EVENT_SEQUENCE_CONFLICT`，不得继续分类本批。
- 回调必须精确匹配 `tenant_id + run_id + repair_id + session_id + runner_provider_id`。任何不匹配返回 `TRUSTED_REPAIR_BINDING_MISMATCH`，并产生安全审计。
- `metadata` 只允许最多 32 个标量值；秘密和原始输出禁止进入 metadata。AIOps 只保存脱敏命令、摘要、指纹和退出码。

## 6. 审批、高风险确认与身份

- 首次审批：`POST /aiops/repair-sessions/{session_id}/approve`；拒绝与取消分别为 `/reject`、`/cancel`。
- 高风险决定：`POST /aiops/repair-sessions/{session_id}/risk-confirmations/{risk_confirmation_id}/grant` 或 `/reject`。请求 body 不含 `decision`；路由是动作的唯一权威，夹带 `decision` 按未知字段以 422 拒绝。
- 两类操作使用不同的随机 UUID `idempotency_key` 命名空间，不得复用。
- AIOps Web 审批只接受 DB 交互用户会话；runner 回调使用独立 API key/scope。`NO_AUTH` 恒拒绝所有建单、审批、确认、取消和 resume。
- 飞书入口先校验签名/时效和目标会话；首版不做 AIOps 用户映射或 `open_id` allowlist，任何通过飞书回调验签且来自已配置会话的用户均可操作。审计记录可信回调中的 `open_id`；body 中身份字段永不可信。
- 首次审批 TTL 1800 秒，执行 TTL 1800 秒，高风险确认 TTL 600 秒。判断以持久化 `expires_at` 为准；过期审批不可恢复。

### 6.1 ControlIntent 与 ControlReceipt

- AIOps 的拒绝、过期与取消裁决和 Runner 控制回执使用独立持久模型；ControlReceipt 不属于 ExecutionEvent，也不消耗事件序号。终态后仍可接收匹配的 ControlReceipt，但不得追加 ExecutionEvent 或改变既有终态。
- ControlIntent 只支持 `CLOSE_WAITING_SESSION` 和 `STOP_ACTIVE_SESSION`。等待态先由 AIOps 写入 `REJECTED`、`EXPIRED` 或 `CANCELLED`；`DIAGNOSING`/`EXECUTING` 在停止确认前保持原状态。
- hash 算法 ID 固定为 `aiops-trusted-repair-control-intent-hash-v1`。preimage 为 UTF-8 `algorithm_id + "\n" + canonical_json`；canonical 字段顺序集合固定为 `schema_version/kind/command_id/tenant_id/run_id/repair_id/session_id/runner_provider_id/runner_instance_id/logical_target_id/platform/action/desired_terminal/reason_code/requested_at/expires_at`。`requested_by` 仅供 AIOps 审计，不进入 wire 或 hash。
- UUID 必须为小写连字符 canonical 形式，`repair_id` 只能为 canonical UUID 或 null；字符串与 key NFC 规范化、key 排序、紧凑 UTF-8 JSON，禁止 float、重复 key、unknown 字段和别名字段。
- ControlIntent TTL 必须在 `(0, 600]` 秒，时钟偏差窗口为 60 秒。Runner 对首次收到的过期 Intent 返回 `INVALID_INTENT + INTENT_EXPIRED`；相同 `command_id + intent_hash` 已有最终回执时，即使此后过期也只重放原回执。相同 command 不同 hash 返回 `INVALID_INTENT + INTENT_CONFLICT`，不得执行。
- `CLOSED` 只确认等待态本地会话已封存；`STOPPED_CONFIRMED` 且 `command_result_certain=true` 才能把活动态归约为 `CANCELLED`。`STOP_UNCERTAIN`、过期或冲突使活动态进入 `MANUAL_INTERVENTION`。`ALREADY_APPLIED` 必须携带先前 outcome 与 certainty，不能单独证明安全停止。
- 回执使用独立 `receipt_fingerprint` 幂等：完全相同回执重复成功；同 command 的不同回执或 receipt ID 冲突进入安全冲突。认证身份必须同时绑定 tenant、provider 与 runner instance；payload 身份只做一致性校验。

## 7. 终态回调、鉴权与接口

CURRENT v1 路由族：

```text
POST /aiops/repair-sessions
GET  /aiops/repair-sessions/{session_id}
GET  /aiops/repair-sessions/{session_id}/proposal
GET  /aiops/repair-sessions/{session_id}/events
POST /aiops/repair-sessions/{session_id}/approve|reject|cancel
POST /aiops/repair-sessions/{session_id}/risk-confirmations/{id}/grant|reject
POST /aiops/repair-sessions/{session_id}/proposal
POST /aiops/repair-sessions/{session_id}/control-receipts
POST /aiops/repair-sessions/callbacks/events
POST /aiops/repair-sessions/callbacks/terminal
```

Proposal、事件与终态回调使用独立 runner API key/scope；不能使用批准人的凭据。Proposal callback 使用闭合 envelope 携带 tenant/run/repair/session/provider 五重绑定与完整 `repair_proposal`，不得把 Proposal 塞进 ExecutionEvent metadata。终态 callback 的 `last_event_sequence` 必须等于 AIOps 已原子接受的最后事件，否则拒绝推进终态。重复相同终态幂等成功；不同终态或终态后新事件冲突并告警。

## 8. 错误信封

沿用 `{error_code, message, retriable, details}`，不得包含 token、密钥、完整原始 transcript 或未脱敏输出。

| error_code | HTTP | retriable |
| --- | ---: | --- |
| TRUSTED_REPAIR_VALIDATION_FAILED | 422 | false |
| TRUSTED_REPAIR_UNSUPPORTED_SCHEMA_VERSION | 422 | false |
| TRUSTED_REPAIR_PROPOSAL_HASH_MISMATCH | 422 | false |
| TRUSTED_REPAIR_IDEMPOTENCY_CONFLICT | 409 | false |
| TRUSTED_REPAIR_EVENT_SEQUENCE_CONFLICT | 409 | false |
| TRUSTED_REPAIR_EVENT_CONTENT_CONFLICT | 409 | false |
| TRUSTED_REPAIR_BINDING_MISMATCH | 409 | false |
| TRUSTED_REPAIR_STATE_TRANSITION_INVALID | 409 | false |
| TRUSTED_REPAIR_APPROVAL_EXPIRED | 410 | false |
| TRUSTED_REPAIR_RISK_CONFIRMATION_EXPIRED | 410 | false |
| TRUSTED_REPAIR_SESSION_NOT_FOUND | 404 | false |
| TRUSTED_REPAIR_SESSION_BUSY | 409 | true |
| TRUSTED_REPAIR_SESSION_RESUME_FAILED | 409 | false |
| TRUSTED_REPAIR_FEATURE_DISABLED | 503 | true |
| TRUSTED_REPAIR_TARGET_NOT_ALLOWED | 403 | false |
| TRUSTED_REPAIR_AUTHENTICATION_REQUIRED | 401 | false |
| TRUSTED_REPAIR_AUTHORIZATION_DENIED | 403 | false |

`SESSION_RESUME_FAILED` 返回后业务状态必须收敛到 `MANUAL_INTERVENTION`。`FEATURE_DISABLED` 包含 AIOps/runner 任一 Kill Switch、灰度门控不满足或 runner 本地 `trusted_session.enabled=false`；不得因此回退到新的 Claude 会话。

## 9. 非 wire 安全约束

- 首版仅 Linux runner/Linux target；必须使用独立 Claude project、固定 OS user/cwd/config/session store，以及 `--permission-mode bypassPermissions`。
- 同一 `claude_session_id` 同时最多一个进程。不得跨 runner、OS user 或 project resume。
- AIOps 与 runner 双 Kill Switch 均阻止创建、批准、确认和 resume；runner 尝试终止本地 Claude。远程进程状态未知时进入 `MANUAL_INTERVENTION`。
- runner 原始 transcript 使用 AES-256-GCM；密钥仅来自本地环境变量或权限受限文件，ciphertext 记录 `key_id` 以轮换，保留 30 天。AIOps 脱敏事件保留 180 天。
- 高风险二次确认属于 Claude 应遵循的流程约束；直接终端模式不提供命令网关级技术阻断。
