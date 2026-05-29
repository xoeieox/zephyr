"""Tests for zephyr.attribution.AttributionLog."""

import json

from zephyr.attribution import AttributionLog


def _prov(mh: str, **kw) -> dict:
    d = {
        "schema_version": "lapis-provenance-v0",
        "agent_id": "test-agent",
        "tool": "unit-test",
        "timestamp": "2026-05-29T20:00:00+00:00",
        "manifest_hash": mh,
        "model": None,
    }
    d.update(kw)
    return d


def test_record_then_dedup(tmp_path):
    log = AttributionLog(tmp_path / "attr.db")
    assert log.count() == 0
    assert log.already_recorded("sha256:aaa") is False

    # first record -> newly recorded
    assert log.record(_prov("sha256:aaa"), store_kind="mem", key="pm/x") is True
    assert log.already_recorded("sha256:aaa") is True
    assert log.count() == 1

    # identical re-deposit (retry-identical-bytes) -> no-op duplicate
    assert log.record(_prov("sha256:aaa"), store_kind="mem", key="pm/x") is False
    assert log.count() == 1

    # a different manifest_hash -> new row
    assert log.record(_prov("sha256:bbb"), store_kind="weaver", key=None) is True
    assert log.count() == 2


def test_get_roundtrip_and_provenance_preserved(tmp_path):
    log = AttributionLog(tmp_path / "attr.db")
    prov = _prov("sha256:ccc", model="qwen3.6-35b-a3b")
    log.record(prov, store_kind="weaver", key="thread-1")
    row = log.get("sha256:ccc")
    assert row is not None
    assert row["agent_id"] == "test-agent"
    assert row["store_kind"] == "weaver"
    assert row["target_key"] == "thread-1"
    assert json.loads(row["provenance_json"])["model"] == "qwen3.6-35b-a3b"


def test_missing_manifest_hash_raises(tmp_path):
    log = AttributionLog(tmp_path / "attr.db")
    bad = _prov("")
    bad["manifest_hash"] = ""
    try:
        log.record(bad)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_recent_ordering(tmp_path):
    log = AttributionLog(tmp_path / "attr.db")
    for i in range(3):
        log.record(_prov(f"sha256:{i}"), store_kind="mem", key=f"k{i}")
    recent = log.recent(limit=2)
    assert len(recent) == 2
    assert log.recent(limit=10, store_kind="mem") and all(
        r["store_kind"] == "mem" for r in log.recent(limit=10, store_kind="mem")
    )
