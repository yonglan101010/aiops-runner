import copy
import json
import os
from datetime import datetime, timezone

import pytest

from runner.trusted_proposal_draft import (
    DIAGNOSIS_DRAFT_SCHEMA,
    DIAGNOSIS_DRAFT_TOP_LEVEL_KEYS,
    TrustedProposalDraftError,
    command_is_high_risk,
    diagnosis_draft_schema_json,
    expand_diagnosis_draft_to_v1,
    validate_diagnosis_draft,
)
from runner.trusted_repair_contract import validate_and_hash_proposal


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(
    os.path.join(
        ROOT,
        "agent-project-trusted",
        "references",
        "trusted-repair-contract-v1.schema.json",
    ),
    encoding="utf-8",
) as stream:
    PUBLIC_SCHEMA = json.load(stream)


def valid_draft():
    return {
        "diagnosis_conclusion": {
            "summary": "根分区空间不足",
            "root_cause": "应用缓存文件异常增长",
            "evidence": [
                {
                    "summary": "/var/lib/example/cache 占用 18 GiB",
                    "source": "command",
                    "reference": "target-exec 'du -x -d 2 /var/lib/example'",
                }
            ],
            "confidence_percent": 95,
        },
        "repair_commands": [
            {
                "command": "systemctl restart example.service",
                "reason": "释放进程持有的已删除缓存文件",
                "expected_result": "服务恢复且根分区可用空间增加",
            },
            {
                "command": "stat -- /var/lib/example/cache",
                "reason": "确认修复后的缓存目录状态",
                "expected_result": "目录仍存在且权限未改变",
            },
        ],
        "impact_scope": {
            "expected_impact": "example.service 短暂重启",
            "affected_scope": "单台目标主机上的 example.service",
            "risk_summary": "重启期间服务可能短暂不可用",
        },
        "rollback_and_verification": {
            "rollback_instructions": "若服务未恢复，使用原配置重新启动并人工介入",
            "verification_steps": [
                {
                    "command": "systemctl is-active example.service",
                    "success_criteria": "输出 active",
                }
            ],
        },
    }


def test_schema_has_exact_four_top_level_sections_and_is_inline_draft7():
    assert set(DIAGNOSIS_DRAFT_SCHEMA["required"]) == DIAGNOSIS_DRAFT_TOP_LEVEL_KEYS
    assert set(DIAGNOSIS_DRAFT_SCHEMA["properties"]) == DIAGNOSIS_DRAFT_TOP_LEVEL_KEYS
    assert DIAGNOSIS_DRAFT_SCHEMA["additionalProperties"] is False
    assert DIAGNOSIS_DRAFT_SCHEMA["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert json.loads(diagnosis_draft_schema_json()) == DIAGNOSIS_DRAFT_SCHEMA


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("impact_scope"),
        lambda value: value.update({"kind": "repair_proposal"}),
        lambda value: value.__setitem__("repair_commands", []),
        lambda value: value["rollback_and_verification"].__setitem__(
            "verification_steps", []
        ),
        lambda value: value["diagnosis_conclusion"].update({"target": "attacker"}),
    ],
)
def test_draft_rejects_missing_extra_and_empty_required_sections(mutate):
    value = valid_draft()
    mutate(value)
    with pytest.raises(TrustedProposalDraftError):
        validate_diagnosis_draft(value)


def test_draft_to_v1_mapping_is_total_runner_owned_and_hash_valid():
    observed = datetime(2026, 7, 24, 8, 30, tzinfo=timezone.utc)
    first = expand_diagnosis_draft_to_v1(
        valid_draft(),
        runner_provider_id="11111111-1111-4111-8111-111111111111",
        logical_target_id="prod-example-001",
        observed_at=observed,
        command_timeout_seconds=47,
    )
    second = expand_diagnosis_draft_to_v1(
        valid_draft(),
        runner_provider_id="11111111-1111-4111-8111-111111111111",
        logical_target_id="prod-example-001",
        observed_at=observed,
        command_timeout_seconds=47,
    )

    assert first == second
    assert first["kind"] == "repair_proposal"
    assert first["schema_version"] == "1.0"
    assert first["proposal_revision"] == 1
    assert first["target"] == {
        "runner_provider_id": "11111111-1111-4111-8111-111111111111",
        "logical_target_id": "prod-example-001",
        "platform": "linux",
    }
    assert first["confidence"] == "0.95"
    assert first["evidence"][0]["observed_at"] == "2026-07-24T08:30:00Z"
    assert [item["sequence"] for item in first["initial_commands"]] == [1, 2]
    assert all(item["cwd"] == "/" for item in first["initial_commands"])
    assert all(item["timeout_seconds"] == 47 for item in first["initial_commands"])
    assert all(
        item["on_failure"] == "stop_and_reassess"
        for item in first["initial_commands"]
    )
    assert first["initial_commands"][0]["high_risk"] is True
    assert first["initial_commands"][1]["high_risk"] is False
    assert first["verification_steps"] == [
        {
            "sequence": 1,
            "command": "systemctl is-active example.service",
            "success_criteria": "输出 active",
            "timeout_seconds": 47,
        }
    ]
    assert validate_and_hash_proposal(first, PUBLIC_SCHEMA) == first["proposal_hash"]

    changed = copy.deepcopy(valid_draft())
    changed["repair_commands"][0]["command"] = "systemctl stop example.service"
    changed_proposal = expand_diagnosis_draft_to_v1(
        changed,
        runner_provider_id="11111111-1111-4111-8111-111111111111",
        logical_target_id="prod-example-001",
        observed_at=observed,
        command_timeout_seconds=47,
    )
    assert changed_proposal["proposal_hash"] != first["proposal_hash"]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("stat -- /var/lib/example/cache", False),
        ("systemctl is-active example.service", False),
        ("systemctl restart example.service", True),
        ("custom-fix --apply", True),
        ("stat /tmp/x && rm /tmp/x", True),
    ],
)
def test_high_risk_classifier_is_conservative(command, expected):
    assert command_is_high_risk(command) is expected
