# Contract reference

冻结 schema 位于：

`../../../../references/trusted-repair-contract-v1.schema.json`

runner 和 AIOps 共用该字节一致契约工件。文件缺失或契约校验失败时必须拒绝可信会话，不得降级为
无 schema 输出。
