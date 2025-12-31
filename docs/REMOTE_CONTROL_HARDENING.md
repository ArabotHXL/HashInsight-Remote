# Remote Control Hardening (miner_id + site_id)

This build hardens remote control execution for HashInsight Edge Collector.

## Key changes
- Commands are executed **by miner_id only**. Cloud-provided `ip_address` fields are ignored.
- miner_id must exist in the local `miner_map` whitelist (from `miners` or expanded `ip_ranges`).
- Optional defense-in-depth: if the command payload contains `site_id`, the collector enforces
  `cmd.site_id == collector.site_id` (`enforce_site_id_in_commands`, default `true`).
- Idempotency: executed command_ids are stored in SQLite (`cache_dir/offline_cache.db`, table `executed_commands`).
- Stable edge identity: `device_id` is generated in `cache_dir/device_id` and reported with command results.

## New/updated config fields
- enable_commands: true|false
- enforce_site_id_in_commands: true|false (default true)
- cache_dir: directory for offline cache and device_id

## Cloud API expectations
Pending command payload should include at minimum:
- command_id
- miner_id
- command
- params (object)
Optional:
- site_id
- issued_at / expires_at / ttl_sec

Result payload includes:
- status (completed|failed|skipped|rejected)
- result_code (0 success, 1 failure, 2 skipped, 3 rejected)
- result_message
- site_id, miner_id, device_id, executed_at, duration_ms, command
