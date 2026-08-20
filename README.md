# AIOps Trusted Runner

> 技术预览版：把 AI 诊断带到受控目标附近，同时把权限、审批与审计留在你的环境中。

**English summary:** A Linux execution node for the
[AIOps control plane](https://github.com/yonglan101010/aiops). It performs read-only
inspection and diagnosis in an allowlisted environment, then resumes the same Claude
session only after a human approves a bound repair proposal. Credentials and encrypted
session records remain local to the Runner.

## 它解决什么问题

- **凭据留在本地**：SSH、kubeconfig、云凭据和目标清单不进入控制面或浏览器。
- **巡检只读**：诊断命令只能通过 `target-exec` 到达已绑定目标。
- **修复需审批**：方案、版本、hash、Runner 身份和原 Claude 会话必须一致。
- **不确定就停止**：会话丢失、身份漂移、回调顺序错误或执行结果不确定时进入人工介入。
- **支持 Kubernetes / VKE**：通过 Kubernetes API 采集允许范围内的资源、指标、事件与日志。

```text
AIOps 控制面 ──受控请求──► Trusted Runner ──► Claude 同一会话诊断
      ▲                              │
      │◄──── 报告与修复方案 ─────────┘
      │
      ├── 人工审批 / 高风险二次确认
      ▼
Trusted Runner ──► 原会话执行 ──► 验证与鉴权回调
```

Runner 不是通用 SSH 跳板机，也不支持无审批的自动修复。

## 开始之前

- Linux 与 Python `3.11`–`3.13`
- 可由专用服务用户调用的 `claude` CLI，并已完成认证
- 可访问的 AIOps 控制面和由其签发的双向鉴权信息
- 如需主机观测：Ed25519 SSH 私钥与已核验的 `known_hosts`
- 如需集群观测：最小权限 kubeconfig；运行时不依赖 `kubectl`

所有 Token、私钥、kubeconfig 和本机覆盖配置必须留在被 Git 忽略的受限文件中。

## 快速部署

```bash
git clone https://github.com/yonglan101010/aiops-runner.git
cd aiops-runner

cp .env.example .env
chmod 600 .env
# 编辑 .env，填写 AIOps 分发的两个不同 Token。

RUNNER_SERVICE_USER=claude ./scripts/install.sh
```

安装脚本会创建虚拟环境、初始化不可替换的 Runner 实例 ID，并验证 Claude CLI 与 Trusted Skill。
将实例 ID 登记到 AIOps 后，以服务用户运行配置向导：

```bash
runuser -u claude -- env HOME=/home/claude \
  PATH=/home/claude/.npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  ./scripts/configure.sh
```

向导按事务处理 Runner、环境、Kubernetes/VKE、资产、SSH、预检和提交。取消或失败时不会提交候选
配置；可能发生的远端公钥操作会尽力回滚。详细字段见[配置向导说明](docs/configuration.md)。

安装并启动 systemd 服务：

```bash
sudo install -m 0644 deploy/aiops-trusted-runner.service.example \
  /etc/systemd/system/aiops-trusted-runner.service
sudoedit /etc/systemd/system/aiops-trusted-runner.service
sudo systemctl daemon-reload
sudo systemctl enable --now aiops-trusted-runner.service

./scripts/health.sh
```

示例 unit 默认使用 `/opt/aiops-runner` 和服务用户 `claude`，安装前应按实际路径与用户核对
`User`、`Group`、`WorkingDirectory`、`EnvironmentFile` 和 `ExecStart`。

## 最小配置边界

| 文件或目录 | 用途 | 是否提交 |
| --- | --- | --- |
| `config/runner.yaml` | 公共策略、功能开关和环境变量名 | 是 |
| `config/*.local.yaml` | 回调地址、目标、SSH 与集群差异 | 否 |
| `config/keys/` | SSH 私钥、known_hosts、kubeconfig | 否 |
| `.env` | 双向 Token 与可选模型/云凭据 | 否 |
| `state/` | 实例 ID、journal、加密 transcript 与重试状态 | 否 |

`RUNNER_SHARED_TOKEN` 用于 AIOps 调用 Runner；`RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN` 用于
Runner 回调 AIOps。两者必须不同，不得写进公共 YAML。

## 巡检预算与可靠回调

巡检命令预算默认为 20。第 21 次目标命令会被拦截，Runner 随后在原 Claude 会话中禁用工具，
只依据已收集证据生成受限报告；证据不足的部分为 `UNKNOWN`。收口再次失败时返回合法的全
`UNKNOWN` 报告，认证、连接、超时和 Provider 错误仍按真实失败处理。

终态回调先即时尝试 3 次。可重试错误会保存当前终态快照，由后台线程和下次启动继续按指数退避
投递，间隔从 5 秒增长并封顶 300 秒；重放不会重新巡检。HTTP 401、403、422 等确定性拒绝不会
持续重试。诊断信息只保留有界、脱敏字段，不记录 Token、Provider 原文或原始回调 body。

## 文档

- [配置向导与本机文件](docs/configuration.md)
- [部署、升级与日常运维](docs/operations.md)
- [Trusted 会话与安全边界](agent-project-trusted/README.md)
- [跨仓修复协议](agent-project-trusted/references/trusted-repair-contract-v1.md)
- [AIOps 控制面](https://github.com/yonglan101010/aiops)

## 开发与验证

```bash
python3 -m venv .venv
.venv/bin/pip install -e "./runner[dev]"
PYTHONPATH=runner .venv/bin/python -m pytest runner/tests

# 安装后主命令
aiops-runner
```

从旧的内部预览构建迁移时请注意：公开版 Python 分发名与命令已统一为 `aiops-runner`，不再提供
旧命令别名。Python import 包仍为 `runner`，HTTP/回调协议和 systemd 服务名保持不变。

## 安全与社区

- 安全问题请通过 GitHub Private Vulnerability Reporting 私密提交，详见 [SECURITY.md](SECURITY.md)。
- 参与开发前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 与
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- 项目采用 [Apache License 2.0](LICENSE)。

本项目不是 Anthropic、火山引擎或其他集成服务的官方项目。相关名称仅用于说明兼容能力，使用者
需自行遵守对应服务条款和最小权限要求。
