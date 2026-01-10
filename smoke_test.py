import json
import gzip
from unittest import mock
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from pickaxe_app.vendor_edge_collector.cgminer_collector import CloudUploader, MinerData, CommandExecutor


class DummyResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"success": True}

    def json(self):
        return self._payload


def _decompress_json(blob: bytes):
    return json.loads(gzip.decompress(blob).decode("utf-8"))


def test_payload_strips_ip_and_creds():
    md = MinerData(
        miner_id="m1",
        ip_address="10.0.0.1",
        timestamp="2026-01-10T00:00:00Z",
        online=True,
        hashrate_ghs=123.4,
        power_consumption=3500.0,
    )
    uploader = CloudUploader(api_url="https://example.com", api_key="t", site_id="S", include_ip=False)
    blob = uploader.build_payload([md])
    rows = _decompress_json(blob)
    assert isinstance(rows, list) and len(rows) == 1
    assert "ip_address" not in rows[0], "ip_address leaked in payload"


def test_scrub_cached_payload():
    raw = [{"miner_id": "m1", "ip_address": "10.0.0.1", "credentials": {"u": "x"}, "hashrate_ghs": 1.0}]
    compressed = gzip.compress(json.dumps(raw).encode("utf-8"))
    uploader = CloudUploader(api_url="https://example.com", api_key="t", site_id="S", include_ip=False)
    scrubbed = uploader.scrub_compressed_payload(compressed)
    rows = _decompress_json(scrubbed)
    assert "ip_address" not in rows[0]
    assert "credentials" not in rows[0]


def test_upload_compressed_posts_scrubbed_bytes():
    raw = [{"miner_id": "m1", "ip_address": "10.0.0.1", "hashrate_ghs": 1.0}]
    compressed = gzip.compress(json.dumps(raw).encode("utf-8"))
    uploader = CloudUploader(api_url="https://example.com", api_key="t", site_id="S", include_ip=False, telemetry_api_mode="legacy")

    captured = {}

    def fake_post(url, data=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        captured["timeout"] = timeout
        return DummyResp(200, {"success": True})

    with mock.patch.object(uploader.session, "post", side_effect=fake_post):
        ok = uploader.upload_compressed(compressed, mode="raw")

    assert ok is True
    posted_rows = _decompress_json(captured["data"])
    assert "ip_address" not in posted_rows[0]


def test_command_executor_rejects_http_control():
    miner_map = {
        "mhttp": {
            "ip": "10.0.0.2",
            "port": 80,
            "protocol": "http",
            "type": "whatsminer",
            "zone_id": "",
        }
    }
    ex = CommandExecutor(api_url="https://example.com", api_key="t", site_id="S", miner_map=miner_map, zone_id="")
    status, code, message, *_ = ex.execute_command({"id": "c1", "miner_id": "mhttp", "command": "reboot", "site_id": "S"})
    assert status == "failed" and message == "CONTROL_NOT_SUPPORTED_OVER_HTTP"


if __name__ == "__main__":
    tests = [
        test_payload_strips_ip_and_creds,
        test_scrub_cached_payload,
        test_upload_compressed_posts_scrubbed_bytes,
        test_command_executor_rejects_http_control,
    ]
    for t in tests:
        t()
    print("SMOKE_TEST_OK")
