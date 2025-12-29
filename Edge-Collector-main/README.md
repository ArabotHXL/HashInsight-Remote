# HashInsight Pickaxe Collector (v0.3.8)

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

- By default, Pickaxe keeps miner IPs **local** and does **not** upload them to the cloud.

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
