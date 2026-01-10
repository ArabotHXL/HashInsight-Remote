# HashInsight Pickaxe Collector (MVP)

This project is a **local collector app** (runs on a laptop/PC inside the mining farm LAN) that:
1) connects to miners by IP (CGMiner-compatible API on port `4028`),
2) continuously pulls telemetry, and
3) uploads batches to your cloud app over HTTPS.

## What you get
- A local web UI (runs on `http://127.0.0.1:8711`) to configure a site + miners and start/stop collection.
- A collector engine (vendored from your `edge_collector`) that:
  - polls miners concurrently,
  - parses Antminer/Whatsminer/Avalon-style stats,
  - uploads gzip-compressed JSON to the cloud endpoint `/api/collector/upload`,
  - caches offline batches locally and retries.

## 0) Preconditions
- You must be **on the mining farm LAN** (Wi-Fi or Ethernet) where miner IPs are reachable.
- Miner CGMiner API port `4028` must be reachable from your laptop/PC.
- Your cloud app must expose an HTTPS endpoint: `POST /api/collector/upload`.

## 1) Run locally (fastest)
### Windows
1. Download and unzip the project.
2. Open **Command Prompt** in the unzipped folder.
3. Run:
   ```bat
   run_local.bat
   ```
4. A browser window should open to `http://127.0.0.1:8711`.

### macOS/Linux
1. Download and unzip.
2. In Terminal:
   ```bash
   ./run_local.sh
   ```

## 2) Configure in the UI
In the browser:
1. **Site ID**: e.g., `tx_midland_001`
2. **Cloud API Base URL**: e.g., `https://YOUR_HASHINSIGHT_DOMAIN`
3. **Collector Token**: a per-site token you generate in your cloud app
4. Configure collection cadence:
   - **Latest Interval (sec)**: fast loop for near real-time “latest” updates (guardrail: >= 5s)
   - **Raw Interval (sec)**: slower loop for 24h monitor / history (guardrail: >= 30s)
   - **Timeout (sec)**: per-miner socket timeout
   - **Max Workers**: concurrent polling threads (start small and tune)
   - **Batch Size**: upload chunk size per request (smaller = less server latency; larger = fewer requests)
   - **Upload Read Timeout (sec)**: how long we wait for the cloud to respond (increase if batches are large)
   - **Latest Max Miners**: for large sites, “latest” polls a rolling window to keep site-level freshness
   - **Shard Total / Shard Index**: run multiple Pickaxe instances, each handling a subset of miners
5. Add miners:
   - Miner ID (optional but recommended): `S21_0001`
   - IP: `192.168.1.100`
   - Port: `4028`
   - Type: `antminer`
6. Click **Test Connection** to validate LAN connectivity.
7. Click **Start**.

## 3) What gets uploaded
The collector sends:
- Headers:
  - `X-Collector-Key: <collector_token>`
  - `X-Site-ID: <site_id>`
  - `Content-Type: application/octet-stream`
  - `Content-Encoding: gzip`
- Body:
  - Gzip-compressed JSON array of miner records.

Your cloud app should return:
```json
{ "success": true }
```

## 4) Cloud endpoint (minimal Flask example)
See: `docs/cloud_ingest_flask_blueprint.py`

## 5) Build a standalone desktop app (optional)
See: `docs/BUILD.md`

## Edge Collector configuration notes

### Inventory sources

Edge Collector supports multiple inventory inputs. Use `inventory_sources` to choose which sources are enabled and how they are merged:

- `miners`: static miner list from `collector_config.json` (useful for small, fixed fleets)
- `binding`: local binding store (CSV/SQLite) that maps **miner_id → local IP/port** plus optional local credentials
- `ip_ranges`: local CIDR discovery (CGMiner API scan + optional Whatsminer HTTP telemetry fallback)

If `inventory_sources` is omitted, the collector defaults to enabling all three for backward compatibility.

Example (binding + discovery only):

```json
{
  "inventory_sources": ["binding", "ip_ranges"]
}
```

### Privacy and control safety

- Miner IP addresses and credentials are **edge-local only**: they are never uploaded to the cloud and are scrubbed from cached offline batches as well.
- Whatsminer HTTP is **telemetry-only**. Remote control commands are rejected for `protocol=http/https/whatsminer_http` to prevent unintended actions and credential exposure.

