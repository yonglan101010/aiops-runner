# 配置向导与本机文件

配置向导以事务方式处理本机差异：`Runner → 环境 → Kubernetes/VKE → 资产 → SSH → 预检 → 提交`。
在最终确认前只写候选文件；取消时清理候选状态。

公共 `config/runner.yaml` 默认关闭 Trusted Session 与巡检，避免未设置回调地址时产生无效或外发
任务。向导只有在回调、身份、本机存储与凭据检查通过后才启用对应能力。

```bash
./scripts/configure.sh
```

应以运行 systemd 服务的同一用户执行向导，确保 Claude 会话、文件所有者和 Runner 实例身份一致。

## Runner 与回调

本机监听地址和 AIOps 回调 URL 写入 `config/runner.local.yaml`。可信事件回调必须是绝对 HTTP(S)
地址，以 `/aiops/repair-sessions/callbacks/events` 结尾，不得包含用户信息、查询参数或片段。向导会
从该地址派生巡检回调地址。

## 环境与 Token

`.env` 至少包含：

- `RUNNER_SHARED_TOKEN`：AIOps 调用 Runner，也保护本机管理接口。
- `RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN`：Runner 回调 AIOps。

两者必须不同。Claude API 兼容网关可选使用 `ANTHROPIC_AUTH_TOKEN`、`ANTHROPIC_BASE_URL` 和
`ANTHROPIC_MODEL`，三项应成组配置，只会传给 Claude 子进程。

## Kubernetes / VKE

集群目录写入 `config/kubernetes.local.yaml`，kubeconfig 复制到 `config/keys/`。向导会检查：

- 文件不是符号链接、大小不超过 2 MiB、权限和所有者正确；
- context 存在，证书有效，API 可达，集群 UID 与版本可读取；
- 拒绝带 `exec` 认证插件的 kubeconfig；
- Namespace 白名单和可选 VMP/TLS 参数结构有效。

生产环境建议设置 Namespace 白名单，并使用最小权限 ServiceAccount 或云子账号。

## 资产与 SSH

主机资产写入 `config/inventory.local.yaml`。每个主机 ID 唯一，一个地址只能配置一个 SSH 账号，
逻辑目标 ID 用于映射 AIOps 中的巡检目标。

SSH 配置与材料保存在 `config/connection.local.yaml` 和 `config/keys/`：

- 仅接受 Ed25519 私钥；
- 首次连接必须通过可信渠道核对 host key 指纹；
- 密码只用于建立免密连接，不写入配置或日志；
- 更换密钥时不会自动删除旧公钥，确认新连接后需人工撤销旧项。

## 预检与提交

最终确认前会检查 YAML、双向 Token、Runner 身份、transcript 密钥来源、SSH、Kubernetes 和
Claude CLI，并显示脱敏变更计划。提交顺序为远端公钥安装与复验、本地原子写入、可选主机上下文
初始化。若远端操作结果不确定，向导会停止并提示人工检查，不会假定成功。
