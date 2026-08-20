# 参与贡献

感谢你改进 AIOps Trusted Runner。Runner 位于凭据和目标附近，任何变更都应优先保持最小权限、
确定性状态和可审计性。涉及协议、会话恢复、远程执行或凭据处理的较大变更，应先通过 Issue 讨论。

## 本地开发

```bash
python3 -m venv .venv
.venv/bin/pip install -e "./runner[dev]"
PYTHONPATH=runner .venv/bin/python -m pytest runner/tests
```

## 不可破坏的安全边界

- 诊断和修复只能经 `target-exec` 到达 allowlist 中的绑定目标。
- 巡检只读；修复必须绑定方案和人工审批，并恢复原 Claude 会话。
- 会话、身份、审批、目标或执行结果不确定时 fail-closed，不创建替代会话或固定动作回退。
- Token、私钥、kubeconfig、Provider 错误和原始回调 body 不得进入 Git、日志或审计正文。
- AIOps 与 Runner 的协议变更必须同步 Schema、golden vector、hash 和两仓测试。

改变上述边界的 Pull Request 不会被接受。

## 提交要求

1. 保持修改聚焦，避免无关格式化和生成文件。
2. 为鉴权、重试、状态机、会话恢复和失败分类变化补充回归测试。
3. 新增依赖前说明必要性、许可证和供应链影响。
4. 协议或行为变化同步更新 README、配置样例和跨仓契约。
5. 提交前运行完整 pytest、构建 wheel，并确认 `git diff --check` 通过。

安全漏洞不要提交公开 Issue，请遵循 [SECURITY.md](SECURITY.md)。参与项目即表示同意
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
