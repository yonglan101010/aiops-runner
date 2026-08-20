# 部署、升级与日常运维

## systemd 边界

Runner 仅支持 Linux，并应使用专用非特权账号运行。示例服务为
`deploy/aiops-trusted-runner.service.example`，安装前必须核对路径、用户、组和环境文件权限。

```bash
systemctl status aiops-trusted-runner.service
./scripts/health.sh
journalctl -u aiops-trusted-runner.service -f
```

健康检查默认访问 `http://127.0.0.1:8002/healthz`。日志不得包含 Token、模型/Provider 错误原文、
私钥、kubeconfig 或原始回调 body。

## 升级

1. 确认没有正在执行的修复；备份 `.env`、`config/*.local.yaml`、`config/keys/` 和 `state/`。
2. 更新代码并重新执行 `RUNNER_SERVICE_USER=<user> ./scripts/install.sh`。
3. 核对公共配置与本机覆盖配置，运行向导预检。
4. 重启 systemd 服务并检查 `/healthz`。
5. 执行一次只读巡检，验证终态回调与 Runner 实例绑定。

不要删除或替换 `state/runner-instance-id`，也不要在会话进行中移动 `state/`。原会话恢复依赖相同
Runner 身份、Linux 用户、项目目录和加密会话存储。

## 回调失败

终态回调先即时尝试 3 次。网络错误、超时和可恢复服务端错误会保存终态快照并按 5、10、20 秒
等指数间隔继续投递，最大间隔 300 秒；服务重启后会继续处理到期快照。重试只重放同一终态，
不会重新连接目标或重新调用 Claude。

HTTP 401、403、422 表示鉴权或契约被确定性拒绝，不会无限重试。修正配置后应发起新的受控任务，
不要手工伪造回调或修改 journal。

## 主机信任与密钥轮换

- host key 变化必须先通过独立渠道核实，禁止关闭严格校验绕过。
- 安装新公钥并复验后，人工从目标 `authorized_keys` 移除旧公钥。
- 双向 Token 轮换需要同步控制面与 Runner，并执行健康检查和只读巡检。
- kubeconfig 和云凭据按最小权限创建，轮换后复验集群 UID 与允许范围。

## 故障边界

以下情况必须停止自动推进并由人工确认：Runner 实例不匹配、Claude 会话无法确定恢复、目标身份
变化、审批方案 hash 漂移、执行结果不确定、回调顺序或签名不合法。不得通过创建替代会话、固定
动作回退或跳过验证来恢复任务。
