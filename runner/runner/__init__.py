"""aiops-runner —— AIOps 受控执行节点。

AIOps 远程调用的就是它；skill 不被外部直接调。runner 只做：
鉴权 / alert-schema 校验 / 去重 / 限流 / token 预算熔断 / 拉起 headless 诊断 skill /
result-schema 校验（不合规→needs_human+死信），以及回调、凭据和自监控。

HTTP 层是薄壳；核心逻辑在可注入的纯类里，便于不起服务器、不跑真 claude 即可单测。
"""

__version__ = "0.1.0"
