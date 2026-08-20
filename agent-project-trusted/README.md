# Trusted Claude 会话项目

这里是 Runner 启动 Claude Code 时使用的专用项目空间。它的目标很简单：让 Claude 在受控边界内完成一次诊断，并在人工批准后回到**同一个原生会话**继续修复；它不是通用的 Claude 工作目录。

## 运行方式

Linux `trusted_claude_session` 核心会以最小化子进程环境启动 Claude，并固定：

- 独立的 `CLAUDE_CONFIG_DIR` 与项目目录；
- Runner 的服务用户和工作目录；
- `bypassPermissions` 权限模式；
- 持久化的 Claude session ID。

同一个 session 同时最多运行一个进程。恢复时必须仍在同一 Runner、同一 OS 用户和同一项目空间内；任何条件不满足都会失败关闭，不会创建“看起来相似”的新会话。

## 数据与保留

Runner 自己产生的原始流式 transcript 使用 AES-256-GCM 加密。Claude 的原生会话存储属于上游格式，**不会由 Runner 再次加密**；该目录会以 `0700` 权限创建，部署时仍应同时做到：

1. 使用加密磁盘或加密卷；
2. 严格限制 Runner 的 Linux 服务用户；
3. 将会话存储纳入 30 天保留与清理流程。

原生会话存储一旦丢失或被替换，Runner 会拒绝恢复。请先处理原因和审计记录，而不是尝试重建会话。

## 操作边界

- 目标命令应只通过本项目的 `bin/target-exec` 执行。
- 不要将目标私钥、连接串或真实 token 放入本项目、提示词或 Skill 内容。
- 需要理解跨系统的会话状态、审批和回调规则时，请阅读 [`references/trusted-repair-contract-v1.md`](./references/trusted-repair-contract-v1.md)。
