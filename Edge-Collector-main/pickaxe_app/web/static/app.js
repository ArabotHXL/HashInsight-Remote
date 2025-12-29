// Pickaxe Collector UI
// Keep UI resilient to config schema changes.

let LOADED_CONFIG = null;
let LIMITS = null;

function el(id){ return document.getElementById(id); }
function has(id){ return !!el(id); }

function setVal(id, v){
  const e = el(id);
  if(!e) return;
  e.value = (v ?? "");
}

function setMin(id, v){
  const e = el(id);
  if(!e) return;
  try { e.min = String(v); } catch (_) {}
}


function setBoolSelect(id, v){
  const e = el(id);
  if(!e) return;
  const s = (v === true || v === 'true') ? 'true' : 'false';
  try { e.value = s; } catch (_) {}
}

function getBoolSelect(id, def=false){
  const e = el(id);
  if(!e) return def;
  const v = (e.value ?? '').toString().trim().toLowerCase();
  if(v === 'true') return true;
  if(v === 'false') return false;
  return def;
}


function getStr(id, def=""){
  const e = el(id);
  if(!e) return def;
  const v = (e.value ?? "").toString().trim();
  return v.length ? v : def;
}

function getNum(id, def){
  const e = el(id);
  if(!e) return def;
  const n = Number(e.value);
  return Number.isFinite(n) ? n : def;
}

function getInt(id, def){
  const e = el(id);
  if(!e) return def;
  const n = parseInt(e.value, 10);
  return Number.isFinite(n) ? n : def;
}

function msg(id, text){
  // Keep backward compatibility across UI revisions.
  const direct = el(id);
  if(direct){ direct.innerText = text; return; }

  // Alias mapping between earlier UI ids and current ids.
  const aliases = {
    "save_msg": "save_status",
    "run_msg": "pill_err",
  };
  const alt = aliases[id] ? el(aliases[id]) : null;
  if(alt){
    // For pills, keep a stable prefix.
    if(aliases[id] === "pill_err") {
      alt.innerText = `error: ${text}`;
    } else {
      alt.innerText = text;
    }
  }
}

function openDialog(id){
  const d = el(id);
  if(!d) return;
  try {
    if(typeof d.showModal === "function") d.showModal();
    else d.setAttribute("open", "");
  } catch (_) {
    d.setAttribute("open", "");
  }
}

function closeDialog(id){
  const d = el(id);
  if(!d) return;
  try {
    if(typeof d.close === "function") d.close();
    else d.removeAttribute("open");
  } catch (_) {
    d.removeAttribute("open");
  }
}

function parseBulkMiners(text, defaults){
  const lines = (text || "").split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const out = [];
  let autoN = 0;

  // Skip a simple header row if present (CSV or TSV).
  if(lines.length){
    const h = lines[0].toLowerCase();
    if(h.includes("ip") && (h.includes(",") || h.includes("\t"))){
      lines.shift();
    }
  }

  for(const line of lines){
    // TSV (Excel copy/paste): miner_id\tip\tport\ttype  OR  ip\tport\ttype
    if(line.includes("\t")){
      const parts = line.split("\t").map(s => s.trim()).filter(Boolean);
      if(parts.length === 1){
        // fall through
      } else if(parts.length === 2){
        const a = parts[0];
        const b = parts[1];
        // If second column looks like port, treat as ip,port
        if(/^[0-9]+$/.test(b)){
          autoN += 1;
          const miner_id = `${defaults.id_prefix}${String(autoN).padStart(6, "0")}`;
          out.push({ miner_id, ip: a, port: parseInt(b, 10), miner_type: defaults.type });
        } else {
          out.push({ miner_id: a, ip: b, port: defaults.port, miner_type: defaults.type });
        }
        continue;
      } else {
        // 3+ columns: either miner_id\tip\tport\ttype  OR  ip\tport\ttype
        const a = parts[0];
        const b = parts[1];
        const c = parts[2];
        const d = parts[3];

        let miner_id;
        let ip;
        let port;
        let miner_type;

        // If 2nd column is numeric, assume: ip,port,type (no miner_id)
        if(/^[0-9]+$/.test(b)){
          autoN += 1;
          miner_id = `${defaults.id_prefix}${String(autoN).padStart(6, "0")}`;
          ip = a;
          port = parseInt(b, 10);
          miner_type = c || defaults.type;
        } else {
          miner_id = a;
          ip = b;
          port = c ? parseInt(c, 10) : defaults.port;
          miner_type = d || defaults.type;
        }

        out.push({ miner_id, ip, port: (Number.isFinite(port) ? port : defaults.port), miner_type });
        continue;
      }
    }

    // CSV: miner_id,ip,port,type
    if(line.includes(",")){
      const parts = line.split(",").map(s => s.trim()).filter(Boolean);
      if(parts.length >= 2){
        const miner_id = parts[0];
        const ip = parts[1];
        const port = parts[2] ? parseInt(parts[2], 10) : defaults.port;
        const miner_type = parts[3] ? parts[3] : defaults.type;
        out.push({ miner_id, ip, port: (Number.isFinite(port) ? port : defaults.port), miner_type });
        continue;
      }
    }

    // IP or IP:port
    let ip = line;
    let port = defaults.port;
    if(line.includes(":")){
      const [a, b] = line.split(":");
      ip = (a || "").trim();
      const p = parseInt((b || "").trim(), 10);
      if(Number.isFinite(p)) port = p;
    }
    if(!ip) continue;
    autoN += 1;
    const miner_id = `${defaults.id_prefix}${String(autoN).padStart(6, "0")}`;
    out.push({ miner_id, ip, port, miner_type: defaults.type });
  }
  return out;
}

function dedupeMiners(candidates, existing){
  const seen = new Set();
  for(const m of existing || []){
    const key = `${(m.ip||"").trim()}:${m.port || 4028}`;
    if(m.ip) seen.add(key);
  }

  const unique = [];
  for(const c of candidates || []){
    const key = `${(c.ip||"").trim()}:${c.port || 4028}`;
    if(!c.ip) continue;
    if(seen.has(key)) continue;
    seen.add(key);
    unique.push(c);
  }
  return unique;
}

function bulkAddPreview(){
  const text = el("bulk_text")?.value || "";
  const defaults = {
    port: parseInt(el("bulk_default_port")?.value || "4028", 10) || 4028,
    type: (el("bulk_default_type")?.value || "antminer").trim() || "antminer",
    id_prefix: (el("bulk_id_prefix")?.value || "AUTO_").trim() || "AUTO_",
  };
  const parsed = parseBulkMiners(text, defaults);
  const unique = dedupeMiners(parsed, readMinersTable());

  const sample = unique.slice(0, 12);
  const summary = {
    parsed: parsed.length,
    added: unique.length,
    skipped_duplicates: parsed.length - unique.length,
    sample
  };
  if(el("bulk_preview_out")) el("bulk_preview_out").innerText = JSON.stringify(summary, null, 2);
  if(el("bulk_hint")) el("bulk_hint").innerText = `Parsed ${parsed.length} lines. Will add ${unique.length}. Skipped ${parsed.length - unique.length} duplicates by IP:Port.`;

  return unique;
}

function bulkAddApply(){
  const unique = bulkAddPreview();
  for(const m of unique) addMinerRow(m);
  closeDialog("bulk_add_dialog");
  // Help users: remember to Save Config after bulk add.
  msg("save_msg", `Added ${unique.length} miners to table. Click 'Save Config' to persist.`);
}

async function bulkImportFile(){
  const f = el("bulk_file")?.files?.[0];
  if(!f) return;

  const default_port = parseInt(el("bulk_default_port")?.value || "4028", 10) || 4028;
  const default_type = (el("bulk_default_type")?.value || "antminer").trim() || "antminer";
  const id_prefix = (el("bulk_id_prefix")?.value || "AUTO_").trim() || "AUTO_";

  try {
    if(el("bulk_hint")) el("bulk_hint").innerText = `Importing ${f.name}...`;

    const fd = new FormData();
    fd.append("file", f);

    const qs = new URLSearchParams({
      default_port: String(default_port),
      default_type: default_type,
      id_prefix: id_prefix,
    });

    const resp = await fetch(`/api/miners/import_file?${qs.toString()}`, { method: "POST", body: fd });
    const j = await resp.json();
    if(!resp.ok || !j.success){
      throw new Error(j.detail || j.error || `HTTP ${resp.status}`);
    }

    const miners = j.miners || [];
    // Convert to CSV lines so existing Preview/Apply workflow works.
    const lines = miners.map(m => `${m.miner_id},${m.ip},${m.port},${m.miner_type || m.type || "antminer"}`);
    if(el("bulk_text")) el("bulk_text").value = lines.join("\n");
    bulkAddPreview();
  } catch (e) {
    if(el("bulk_hint")) el("bulk_hint").innerText = `Import failed: ${String(e)}`;
  }
}

function readMinersTable(){
  const table = el("miners_table");
  if(!table) return [];
  const rows = Array.from(table.querySelectorAll("tbody tr"));
  const miners = [];
  for (const r of rows){
    const miner_id = (r.querySelector(".m_id")?.value ?? "").trim();
    const ip = (r.querySelector(".m_ip")?.value ?? "").trim();
    const port = parseInt(r.querySelector(".m_port")?.value ?? "4028", 10) || 4028;
    const miner_type = (r.querySelector(".m_type")?.value ?? "antminer").trim() || "antminer";
    if(!miner_id && !ip) continue;
    miners.push({ miner_id, ip, port, miner_type });
  }
  return miners;
}

function clearMinersTable(){
  const tbody = el("miners_table")?.querySelector("tbody");
  if(tbody) tbody.innerHTML = "";
}

function addMinerRow(miner){
  const tbody = el("miners_table")?.querySelector("tbody");
  if(!tbody) return;
  const m = miner || { miner_id: "", ip: "", port: 4028, miner_type: "antminer" };

  const tr = document.createElement("tr");

  const tdId = document.createElement("td");
  const inId = document.createElement("input");
  inId.className = "m_id";
  inId.value = m.miner_id || "";
  tdId.appendChild(inId);

  const tdIp = document.createElement("td");
  const inIp = document.createElement("input");
  inIp.className = "m_ip";
  inIp.value = m.ip || "";
  tdIp.appendChild(inIp);

  const tdPort = document.createElement("td");
  const inPort = document.createElement("input");
  inPort.className = "m_port";
  inPort.type = "number";
  inPort.min = "1";
  inPort.max = "65535";
  inPort.value = String(m.port ?? 4028);
  tdPort.appendChild(inPort);

  const tdType = document.createElement("td");
  const sel = document.createElement("select");
  sel.className = "m_type";
  const opts = ["antminer", "whatsminer", "avalon", "innosilicon", "goldshell", "other"];
  for(const o of opts){
    const opt = document.createElement("option");
    opt.value = o;
    opt.innerText = o;
    sel.appendChild(opt);
  }
  sel.value = (m.miner_type || "antminer");
  tdType.appendChild(sel);

  const tdTest = document.createElement("td");
  tdTest.className = "test_result";
  tdTest.innerText = "";

  const tdAction = document.createElement("td");
  const btnDel = document.createElement("button");
  btnDel.innerText = "Del";
  btnDel.addEventListener("click", () => tr.remove());
  tdAction.appendChild(btnDel);

  tr.appendChild(tdId);
  tr.appendChild(tdIp);
  tr.appendChild(tdPort);
  tr.appendChild(tdType);
  tr.appendChild(tdTest);
  tr.appendChild(tdAction);

  tbody.appendChild(tr);
}

function renderMiners(miners){
  clearMinersTable();
  const list = miners || [];
  for(const m of list) addMinerRow(m);
}

function writeFormConfig(cfg){
  const c = cfg || {};

  // Core fields (current UI names)
  setVal("site_id", c.site_id ?? "site_001");
  setVal("site_name", c.site_name ?? "");
  setVal("cloud_api_base", c.cloud_api_base ?? "");
  setVal("collector_token", c.collector_token ?? "");

  // Intervals
  setVal("latest_interval_sec", c.latest_interval_sec ?? 10);
  setVal("raw_interval_sec", c.raw_interval_sec ?? (c.poll_interval_sec ?? 60));

  // Concurrency/timeouts
  setVal("timeout_sec", c.timeout_sec ?? 5);
  setVal("max_workers", c.max_workers ?? 50);

  // Batch/upload & retries
  setVal("batch_size", c.batch_size ?? 500);
  setVal("upload_read_timeout_sec", c.upload_read_timeout_sec ?? 30);
  setVal("max_retries", c.max_retries ?? 5);

  // Miner timeouts
  setVal("miner_timeout_fast_sec", c.miner_timeout_fast_sec ?? 1.5);
  setVal("miner_timeout_slow_sec", c.miner_timeout_slow_sec ?? 5.0);

  // Sharding
  setVal("shard_total", c.shard_total ?? 1);
  setVal("shard_index", c.shard_index ?? 0);

  // Latest table cap
  setVal("latest_max_miners", c.latest_max_miners ?? 500);

  // Upload tuning
  setVal("upload_connect_timeout_sec", c.upload_connect_timeout_sec ?? 2);
  setVal("upload_workers", c.upload_workers ?? 4);

  // Offline backoff
  setVal("offline_backoff_base_sec", c.offline_backoff_base_sec ?? 30);
  setVal("offline_backoff_max_sec", c.offline_backoff_max_sec ?? 300);

  // Privacy / security
  setBoolSelect("upload_ip_to_cloud", c.upload_ip_to_cloud ?? false);
  setBoolSelect("encrypt_miners_config", c.encrypt_miners_config ?? false);
  setVal("local_key_env", c.local_key_env ?? 'PICKAXE_LOCAL_KEY');

  // Server-advertised limits -> HTML min attributes
  if(LIMITS){
    if(typeof LIMITS.min_latest_interval_sec === "number") setMin("latest_interval_sec", LIMITS.min_latest_interval_sec);
    if(typeof LIMITS.min_raw_interval_sec === "number") setMin("raw_interval_sec", LIMITS.min_raw_interval_sec);
    if(typeof LIMITS.min_poll_interval_sec === "number") setMin("raw_interval_sec", LIMITS.min_poll_interval_sec);
  }

  renderMiners(c.miners || []);
}

function readFormConfigPartial(){
  const cfg = {};

  if(has("site_id")) cfg.site_id = getStr("site_id", "site_001");
  if(has("site_name")) cfg.site_name = getStr("site_name", "");
  if(has("cloud_api_base")) cfg.cloud_api_base = getStr("cloud_api_base", "");
  if(has("collector_token")) cfg.collector_token = getStr("collector_token", "");

  if(has("latest_interval_sec")) cfg.latest_interval_sec = getInt("latest_interval_sec", 10);
  if(has("raw_interval_sec")) cfg.raw_interval_sec = getInt("raw_interval_sec", 60);

  if(has("timeout_sec")) cfg.timeout_sec = getNum("timeout_sec", 5);
  if(has("max_workers")) cfg.max_workers = getInt("max_workers", 50);

  if(has("batch_size")) cfg.batch_size = getInt("batch_size", 500);
  if(has("upload_read_timeout_sec")) cfg.upload_read_timeout_sec = getInt("upload_read_timeout_sec", 30);
  if(has("max_retries")) cfg.max_retries = getInt("max_retries", 5);

  if(has("miner_timeout_fast_sec")) cfg.miner_timeout_fast_sec = getNum("miner_timeout_fast_sec", 1.5);
  if(has("miner_timeout_slow_sec")) cfg.miner_timeout_slow_sec = getNum("miner_timeout_slow_sec", 5.0);

  if(has("shard_total")) cfg.shard_total = getInt("shard_total", 1);
  if(has("shard_index")) cfg.shard_index = getInt("shard_index", 0);

  if(has("latest_max_miners")) cfg.latest_max_miners = getInt("latest_max_miners", 500);

  if(has("upload_connect_timeout_sec")) cfg.upload_connect_timeout_sec = getInt("upload_connect_timeout_sec", 2);
  if(has("upload_workers")) cfg.upload_workers = getInt("upload_workers", 4);

  if(has("offline_backoff_base_sec")) cfg.offline_backoff_base_sec = getInt("offline_backoff_base_sec", 30);
  if(has("offline_backoff_max_sec")) cfg.offline_backoff_max_sec = getInt("offline_backoff_max_sec", 300);

  if(has("upload_ip_to_cloud")) cfg.upload_ip_to_cloud = getBoolSelect("upload_ip_to_cloud", false);
  if(has("encrypt_miners_config")) cfg.encrypt_miners_config = getBoolSelect("encrypt_miners_config", false);
  if(has("local_key_env")) cfg.local_key_env = getStr("local_key_env", 'PICKAXE_LOCAL_KEY');

  cfg.miners = readMinersTable();
  return cfg;
}

async function loadConfig(){
  msg("save_msg", "Loading config...");
  try {
    const res = await apiFetch("/api/config");
    const data = await res.json();

    LIMITS = data.limits || null;

    // Prefer wrapper {config: {...}} but keep backward compatibility.
    const cfg = data.config || data || {};
    LOADED_CONFIG = cfg;

    writeFormConfig(cfg);
	    // Render miners from persisted config into the table.
	    try {
	      renderMiners(Array.isArray(cfg.miners) ? cfg.miners : []);
	    } catch (e) {
	      console.warn("Failed to render miners", e);
	    }

    const minersCount = (data.miners_count != null) ? data.miners_count : (cfg.miners?.length || 0);
    const warns = Array.isArray(data.warnings) ? data.warnings : [];
    if(warns.length){
      msg('save_msg', `Loaded: ${minersCount} miners (warnings: ${warns.length})`);
      console.warn('Config warnings', warns);
    } else {
      msg('save_msg', `Loaded: ${minersCount} miners`);
    }
  } catch (e) {
    msg("save_msg", `Load failed: ${String(e)}`);
  }
}

async function saveConfig(){
  msg("save_msg", "Saving...");
  try {
    const partial = readFormConfigPartial();

    // Merge to avoid dropping non-exposed fields (e.g., ip_ranges).
    const merged = Object.assign({}, (LOADED_CONFIG || {}), partial);
    merged.miners = partial.miners;

    const res = await apiFetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config: merged })
    });

    if(!res.ok){
      const t = await res.text();
      throw new Error(t);
    }

    const data = await res.json();
    LOADED_CONFIG = merged;
    const minersCount = (data.miners_count != null) ? data.miners_count : (merged.miners?.length || 0);
    msg("save_msg", `Saved. ${minersCount} miners`);
    return true;
  } catch (e) {
    msg("save_msg", `Save failed: ${String(e)}`);
    return false;
  }
}

async function startCollector(){
  msg("run_msg", "Starting...");
  try {
    // Common UX pitfall: user bulk-adds miners but forgets to click Save Config.
    // Start uses the persisted config, so auto-save before starting.
    const ok = await saveConfig();
    if(!ok) {
      msg("run_msg", "Start blocked: Save Config failed.");
      await refreshStatus();
      return;
    }

    const res = await apiFetch("/api/collector/start", { method: "POST" });
    const t = await res.text();
    msg("run_msg", res.ok ? "Started" : `Start failed: ${t}`);
  } catch (e) {
    msg("run_msg", `Start failed: ${String(e)}`);
  }
  await refreshStatus();
}

async function stopCollector(){
  msg("run_msg", "Stopping...");
  try {
    const res = await apiFetch("/api/collector/stop", { method: "POST" });
    const t = await res.text();
    msg("run_msg", res.ok ? "Stopped" : `Stop failed: ${t}`);
  } catch (e) {
    msg("run_msg", `Stop failed: ${String(e)}`);
  }
  await refreshStatus();
}

async function refreshStatus(){
  try {
    const status = await apiFetch("/api/status");
    const j = await status.json();
    if(el("status_json")) el("status_json").innerText = JSON.stringify(j, null, 2);
  } catch (e) {
    if(el("status_json")) el("status_json").innerText = String(e);
  }

  // Tail logs
  try {
    const logs = await apiFetch("/api/logs?lines=220");
    // UI compatibility: some versions used id="log_tail" instead of id="logs"
    const lp = el("logs") || el("log_tail");
    if(lp) {
      lp.innerText = await logs.text();
      // Keep tail visible
      try { lp.scrollTop = lp.scrollHeight; } catch (_) {}
    }
  } catch (_) {}
}

async function testConnections(){
  const minersAll = readMinersTable().map(m => ({ ip: m.ip, port: m.port }));
  const defaultLimit = 50;
  const limit = (minersAll.length > defaultLimit) ? defaultLimit : minersAll.length;
  const miners = minersAll.slice(0, limit);
  if(miners.length === 0){
    msg("run_msg", "No miners to test.");
    return;
  }

  if(minersAll.length > miners.length){
    msg("run_msg", `Testing first ${miners.length} of ${minersAll.length} miners...`);
  } else {
    msg("run_msg", `Testing ${miners.length} miners...`);
  }
  try {
    const res = await apiFetch("/api/miners/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        miners,
        timeout_sec: getNum("timeout_sec", 5),
        concurrency: Math.min(getInt("max_workers", 50), 100)
      })
    });

    if(!res.ok){
      const t = await res.text();
      throw new Error(t);
    }

    const data = await res.json();
    const results = Array.isArray(data.results) ? data.results : [];
    const map = new Map();
    for(const r of results){
      map.set(`${r.ip}:${r.port}`, r);
    }

    const tbody = el("miners_table")?.querySelector("tbody");
    if(tbody){
      const rows = Array.from(tbody.querySelectorAll("tr"));
      for(const row of rows){
        const cell = row.querySelector(".test_result");
        if(!cell) continue;
        const ip = (row.querySelector(".m_ip")?.value ?? "").trim();
        const port = parseInt(row.querySelector(".m_port")?.value ?? "4028", 10) || 4028;
        const r = map.get(`${ip}:${port}`);
        if(!r){ cell.innerText = "n/a"; continue; }

        if(r.alive){
          const latency = (r.latency_ms != null) ? `${r.latency_ms}ms` : "n/a";
          const ths = (r.hashrate_ths != null && Number.isFinite(Number(r.hashrate_ths))) ? Number(r.hashrate_ths).toFixed(2) : null;
          const hr = ths ? `${ths} TH/s` : "n/a";
          cell.innerText = `OK | ${latency} | ${hr}`;
        } else {
          cell.innerText = `FAIL | ${r.error || "offline"}`;
        }
      }
    }

    msg("run_msg", "Test complete.");
  } catch (e) {
    msg("run_msg", `Test failed: ${String(e)}`);
  }
}

// ----- Local API Secret handling (required for Save/Start/Stop) -----
const LOCAL_SECRET_STORAGE_KEY = "pickaxe_local_api_secret";

function getLocalSecret(){
  try { return (localStorage.getItem(LOCAL_SECRET_STORAGE_KEY) || "").trim(); } catch(e){ return ""; }
}

function setLocalSecret(val){
  const v = (val || "").trim();
  try{
    if(v) localStorage.setItem(LOCAL_SECRET_STORAGE_KEY, v);
    else localStorage.removeItem(LOCAL_SECRET_STORAGE_KEY);
  }catch(e){}
}

async function apiFetch(path, opts){
  const o = opts ? {...opts} : {};
  o.headers = o.headers ? {...o.headers} : {};
  const sec = getLocalSecret();
  if(sec){
    o.headers["X-Local-API-Secret"] = sec;
  }
  return fetch(path, o);
}

function setHint(text){
  const h = el("local_secret_hint");
  if(h) h.innerText = text || "";
}

async function refreshLocalSecretStatus(){
  const input = el("local_api_secret");
  const stored = getLocalSecret();
  if(input && !input.value && stored) input.value = stored;

  try{
    const res = await fetch("/api/local-secret");
    if(!res.ok){
      const t = await res.text();
      setHint(`Local secret status check failed: HTTP ${res.status} ${t}`);
      return;
    }
    const data = await res.json();
    const configured = !!data.configured;

    if(!configured){
      setHint("Local API Secret is not configured yet. Click Generate (recommended) or paste one and click Set.");
      return;
    }

    if(stored){
      setHint("Local API Secret is configured. This browser has a copy, so Save/Start/Stop will work.");
    } else {
      setHint("Local API Secret is configured on this machine, but this browser has no copy. Paste the current secret and click Set (store only) so Save/Start/Stop can work.");
    }
  }catch(e){
    setHint(`Local secret status check failed: ${String(e)}`);
  }
}

async function onSetSecret(){
  const input = el("local_api_secret");
  const entered = (input?.value || "").trim();
  if(!entered){
    setHint("Please enter a secret first (or click Generate).");
    return;
  }

  // Always store locally first.
  setLocalSecret(entered);

  try{
    // If server is not configured yet, bootstrap it (no auth required for first-time set).
    const stRes = await fetch("/api/local-secret");
    const st = stRes.ok ? await stRes.json() : {configured: true};

    if(!st.configured){
      const res = await fetch("/api/local-secret", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({secret: entered})
      });
      if(!res.ok){
        const t = await res.text();
        setHint(`Set failed: HTTP ${res.status} ${t}`);
        return;
      }
      const data = await res.json();
      if(data.secret){
        setLocalSecret(data.secret);
        if(input) input.value = data.secret;
      }
      setHint("Local API Secret configured. You can now Save Config and Start.");
      return;
    }

    // Otherwise, just validate the stored secret against a protected endpoint.
    const check = await apiFetch("/api/status");
    if(check.ok){
      setHint("Local API Secret saved in this browser (validated). You can now Save Config / Start.");
    }else{
      const t = await check.text();
      setHint(`Secret saved locally, but validation failed: HTTP ${check.status} ${t}`);
    }
  }catch(e){
    setHint(`Secret saved locally, but validation failed: ${String(e)}`);
  }
}

async function onGenerateSecret(){
  try{
    setHint("Generating secret...");
    const res = await apiFetch("/api/local-secret", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({generate: true})
    });
    if(!res.ok){
      const t = await res.text();
      setHint(`Generate failed: HTTP ${res.status} ${t}`);
      return;
    }
    const data = await res.json();
    const sec = (data.secret || "").trim();
    if(!sec){
      setHint("Generate failed: server did not return a secret.");
      return;
    }
    setLocalSecret(sec);
    const input = el("local_api_secret");
    if(input) input.value = sec;
    setHint("Local API Secret generated and configured. You can now Save Config and Start.");
  }catch(e){
    setHint(`Generate failed: ${String(e)}`);
  }
}

function bind(){
  el("btn_save")?.addEventListener("click", saveConfig);
  el("btn_set_secret")?.addEventListener("click", onSetSecret);
  el("btn_gen_secret")?.addEventListener("click", onGenerateSecret);
  el("btn_start")?.addEventListener("click", startCollector);
  el("btn_stop")?.addEventListener("click", stopCollector);
  el("btn_add_miner")?.addEventListener("click", () => addMinerRow(null));
  el("btn_bulk_add")?.addEventListener("click", () => {
    // Reset preview output for clarity.
    if(el("bulk_preview_out")) el("bulk_preview_out").innerText = "";
    if(el("bulk_hint")) el("bulk_hint").innerText = "Tip: You can paste 500–10,000 lines; duplicates are skipped by IP:Port.";
    openDialog("bulk_add_dialog");
  });
  el("bulk_close")?.addEventListener("click", () => closeDialog("bulk_add_dialog"));
  el("bulk_preview")?.addEventListener("click", bulkAddPreview);
  el("bulk_apply")?.addEventListener("click", bulkAddApply);
  el("bulk_file")?.addEventListener("change", bulkImportFile);
  el("btn_test_all")?.addEventListener("click", testConnections);
}

window.addEventListener("DOMContentLoaded", async () => {
  bind();
  await refreshLocalSecretStatus();
  await loadConfig();
  await refreshStatus();
  setInterval(refreshStatus, 2500);
});
