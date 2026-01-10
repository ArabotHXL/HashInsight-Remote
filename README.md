# HashInsight Remote (Edge Agent)

A lightweight local collector app for mining farms:
- Connect to miners by IP (CGMiner API, default port 4028)
- Pull telemetry continuously
- Upload to your HashInsight cloud app over HTTPS

## Quick start
- Windows: run `run_local.bat`
- macOS/Linux: run `./run_local.sh`

Then open `http://127.0.0.1:8711`.

## Documentation
See `docs/README_END_TO_END.md`.


## Security (IP handling)

- By default, HashInsight Remote keeps miner IPs **local** and does **not** upload them to the cloud.

## Security (local config encryption)

- Local miner list encryption is **optional**. This build defaults to plaintext local config for reliability.
- To encrypt the local miners list at rest, set an environment variable `PICKAXE_LOCAL_KEY` (32-byte key, base64 or hex).

Example (PowerShell):

```powershell
# generate a random 32-byte key and set env var for this session
python - <<'PY'
import os,base64,secrets
print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))
PY
$env:PICKAXE_LOCAL_KEY = "<paste key>"
```



## 2026-01 Collector Upgrade (v1 command protocol + resiliency)

### What's improved
- **Command channel v1 support (recommended)**: `GET /api/edge/v1/commands/poll` + `POST /api/edge/v1/commands/{id}/ack`
- **Legacy command channel still supported** for migration (`/api/collector/commands/*`)
- **ACK offline spool**: when the WAN/cloud is down, command results are cached locally and replayed later
- **Stable Device ID**: generated once and persisted under `data/cache/device_id.txt` (used for audit attribution)
- **Cloud API mode switches**:
  - Telemetry: `telemetry_api_mode = legacy | v1 | auto`
  - Commands: `command_api_mode = legacy | v1 | auto`
- **Better upload error classification** (auth vs http vs network) exposed via status

### Recommended config (most deployments)
- `telemetry_api_mode = legacy` (keep current `/api/collector/upload`)
- `command_api_mode = auto` (try v1 first, fall back to legacy)

### Security note
By default the collector **does not upload internal miner IPs** to the cloud. Miner IPs stay on the edge device only (HashInsight Remote UI/config).