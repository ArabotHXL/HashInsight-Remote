# HashInsight Remote — 现场部署与运维 SOP（v1）

> 适用对象：矿场 Owner / Ops Manager / NOC / 现场 Technician / Hosting 客户经理  
> 目标：标准化部署 HashInsight Remote（边缘代理），实现 **矿机遥测上云 + 云端受控遥控（经由 Edge 执行）**，同时满足 **矿机 IP/凭据永不上传云端** 的安全边界。

---

## 1. 范围与原则（Scope & Principles）

### 1.1 范围
本 SOP 覆盖：
- 站点/Zone 规划与容量拆分（多实例水平扩展）
- 资产导入（CSV Binding）与网段发现（IP Ranges）并用的配置方法
- 部署安装（Linux 为主，Windows 可选）
- 遥测上云（Telemetry）与命令闭环（v1 poll/ack）
- 离线 24h spool（断网续跑 + 恢复补传）
- 运维巡检、故障排查、升级回滚、审计留痕

### 1.2 不可突破的安全边界（Hard Guardrails）
- **矿机 IP 地址永不上传云端**（在线上传与离线补传均强制剥离）
- **矿机凭据永不上传云端**（凭据仅本地存储；可选加密）
- 云端控制必须经由 Remote 执行（Cloud 不直连 Miner LAN）
- HTTP 协议默认仅用于遥测兜底（**默认不允许通过 HTTP 发控制命令**）

---

## 2. 角色与职责（RACI）

| 角色 | 责任 |
|---|---|
| Owner/投资人 | 审批 Remote 覆盖范围、控制策略与风险边界；确认 PoC KPI |
| Ops Manager | 站点/Zone 拆分、部署计划、运维指标、容量与可用性 |
| Shift Lead / NOC | 告警处理、命令审批流（若启用）、交接班摘要 |
| Technician | 现场网络接入、矿机可达性验证、替换/维修、PDU 操作 |
| Hosting 客户经理 | SLA/对账争议证据链导出、客户透明度报表 |
| 安全/IT | 出站策略、凭据/密钥管理、日志与审计要求 |

---

## 3. 部署规划（Planning）

### 3.1 分片原则（Sharding by Site/Zone）
建议按 **site_id + zone_id** 或 **VLAN/子网** 拆分 Remote 实例：
- 每个 Remote 仅负责一个 Zone（或一组明确的网段），避免跨区误控
- 大规模场景采用水平扩展：多 Remote 并行采集与执行

**容量经验值（起步规划）**  
- 采集间隔 60s：单 Remote 先按 **1,000–3,000 台** 规划；超出则增加实例
- 异常 burst（10s）必须受控并发，否则会形成失败风暴

### 3.2 网络要求（Network Requirements）
- Remote → Cloud：**仅需出站 HTTPS**（建议 443/TCP）
- Remote → Miner LAN：需要可达矿机接口端口（典型 4028/TCP；HTTP 端口按机型）
- 强烈建议：Remote 所在主机与矿机处于同一 VLAN/路由域（减少跨网段延迟与 ACL 风险）

### 3.3 主机规格建议（Host Sizing）
- 小型（<=1,000 台）：2 vCPU / 4–8GB RAM / 50GB SSD
- 中型（1,000–3,000 台）：4–8 vCPU / 8–16GB RAM / 100GB SSD
- 大型（>3,000 台）：多实例水平扩展优先；单机扩容只作为补充

---

## 4. 资产来源与隔离（Inventory & Isolation）

### 4.1 默认：两者并用（binding + ip_ranges）
默认配置：
```json
"inventory_sources": ["binding", "ip_ranges"]
```
合并规则（推荐）：
- 先加载 binding（有台账优先）
- 再加载 ip_ranges（补齐缺口）
- 去重策略：优先以 miner_id（或 asset_id）为主；无 ID 时使用 ip:port 作为去重键
- **无论资产来源如何，上传云端时均剥离 IP**

### 4.2 CSV Binding（推荐作为主台账）
文件：`./bindings.csv`（示例已随包提供）  
建议字段（最小集）：
- `miner_id`（或 `asset_id`）
- `vendor`（antminer/whatsminer）
- `protocol`（cgminer 或 whatsminer_http）
- `ip`、`port`
- `site_id`、`zone_id`

可选字段：
- `username`、`password`（仅本地；建议启用加密存储）
- `notes`、`rack`、`row`

操作规范：
- 每次导入 CSV 属于一次“变更”（建议在变更记录里留痕：谁导入、何时导入、差异摘要）
- 生产环境建议将 bindings.csv 纳入版本控制或变更审批（避免误导入导致大面积误控）

### 4.3 IP Ranges 扫描（作为辅助发现）
配置示例：
```json
"ip_ranges": [
  {"cidr": "192.168.10.0/24", "ports": [4028]},
  {"cidr": "192.168.11.0/24", "ports": [4028]}
]
```

护栏建议：
- 扫描仅在 Remote 所属 zone 的子网范围内配置
- 对失败主机采用指数退避（防止失败风暴）
- 建议“发现后落库”：将新发现资产写入本地 binding（形成可审计台账）

---

## 5. 安装与启动（Install & Run）

### 5.1 获取与解压
- 从 GitHub 拉取或下载 ZIP 后解压到服务器目录，例如：
  - `/opt/hashinsight-remote/`

### 5.2 Python 环境
Linux：
```bash
cd /opt/hashinsight-remote
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 5.3 配置文件
默认配置文件：`collector_config.json`

必须配置：
- `cloud_api_base`：云端 API Base URL
- `collector_token`：Remote 认证 token
- `site_id`、`zone_id`
- `inventory_sources`、`binding_csv_path`、`ip_ranges`（按你的场景）

安全配置（强烈建议）：
- `mask_ip_in_logs: true`
- `binding_encrypt_credentials: true`（若 CSV 存储凭据）

离线 spool：
- `offline_spool_max_age_hours: 24`
- `offline_spool_max_total_bytes: 10737418240`（10GB）

### 5.4 启动（本地模式）
```bash
./run_local.sh
```
或：
```bash
python -m pickaxe_app.main
```
本地 UI 默认：
- `http://127.0.0.1:8711`

---

## 6. 上线前验收（Go-Live Checks）

### 6.1 基础连通性
- Remote 能出站访问 `cloud_api_base`
- Remote 能访问矿机端口（4028/TCP；HTTP 端口按需）

### 6.2 资产加载正确性
- UI/日志中确认：
  - binding 导入成功
  - ip_ranges 扫描范围正确
  - 资产数量符合预期（过大/过小都要复核）

### 6.3 遥测上传验收
- 云端能看到：
  - miner_id 维度的 hashrate/temp/fan/status 等
- 云端**不应看到**：
  - `ip_address`
  - `username/password`
  - 任何可反推出 LAN 地址的字段

### 6.4 命令闭环验收（v1 poll/ack）
- 云端下发 1 个单机低风险命令（例如：读取/换池/软重启，按 capability 允许）
- Remote 拉取命令并执行
- 云端收到 ack（包含状态、错误分类、可选 before/after 快照）

---

## 7. 日常运维（Day-2 Operations）

### 7.1 NOC 每班必看指标（建议做成看板）
- 资产在线率（online %）
- 采集延迟（p50/p95）
- `pending_uploads`（离线积压数）
- `pending_acks`（命令回执积压数）
- 磁盘水位（spool 占用/上限）
- 失败分类占比（network/auth/timeout/unsupported）

### 7.2 断网与恢复
- 断网期间：Remote 继续采集并本地缓存（不阻塞现场）
- 恢复后：自动补传
- 若补传失败：检查 token、cloud 可达性、证书/代理

### 7.3 日志与审计
- 建议开启 log rotation（按天/按大小）
- 默认脱敏输出（mask_ip_in_logs=true）
- 关键事件建议写入审计流（命令执行、批量变更、CSV 导入）

---

## 8. 变更、升级与回滚（Change Management）

### 8.1 配置变更
- 配置变更建议走审批：谁改、改什么、影响范围（多少台/多少 kW）
- 变更前导出旧配置（保留回滚点）

### 8.2 版本升级
推荐流程：
1) 在测试 Remote 上先升级（Canary）
2) 观察 24h：在线率、延迟、失败分类是否异常
3) 分批推广到更多 Remote

回滚策略：
- 保留上一版目录或 Docker 镜像
- 配置与 binding DB 分离存储（避免升级覆盖数据）

---

## 9. 大规模实践（Scale Playbook）

### 9.1 多实例部署模板
- 每个 Zone 至少 1 个 Remote
- 超过 3,000 台/Zone：增加 Remote，按 shard 切分（例如按 rack/子网/矿机编号段）
- 云端以 `site_id + zone_id + remote_id` 建立路由表（不含 IP）

### 9.2 性能参数建议
- 默认采样：60s
- 超时：3–5s（按网络质量调）
- 并发 worker：从 200 起步，按 CPU/网络压测调整
- 失败退避：指数 + jitter（避免齐步重试）

---

## 10. 常见故障排查（Troubleshooting）

| 现象 | 可能原因 | 处理步骤 |
|---|---|---|
| 云端无数据 | 出站被阻断 / token 错 / cloud_api_base 错 | curl 测试 cloud endpoint；核对 token；检查代理/证书 |
| 大量矿机离线 | VLAN/路由问题 / ACL / 4028 被封 | 现场抓包；确认端口可达；分 Zone 验证 |
| pending_uploads 持续增长 | 云端不可达或返回 5xx | 检查云端健康；看失败分类；扩容带宽/调低频率 |
| 命令不执行 | 资产不在本 zone/remote / capability 不支持 | 检查 miner_id 路由；查看 ack 的拒绝原因 |
| CPU/磁盘飙升 | 并发过高 / burst 频繁 / spool 清理未生效 | 下调并发与频率；确认 cleanup 执行；增加实例 |

---

## 11. 附录：最小配置模板（示例）

```json
{
  "cloud_api_base": "https://YOUR-CLOUD/api",
  "collector_token": "REDACTED",
  "site_id": "TX1",
  "zone_id": "Z1",

  "inventory_sources": ["binding", "ip_ranges"],
  "binding_enable": true,
  "binding_csv_path": "./bindings.csv",
  "binding_db_path": "./data/binding_store.db",
  "binding_encrypt_credentials": true,

  "ip_ranges": [{"cidr": "192.168.10.0/24", "ports": [4028]}],

  "mask_ip_in_logs": true,

  "offline_spool_max_age_hours": 24,
  "offline_spool_max_total_bytes": 10737418240,

  "enable_commands": true,
  "command_poll_interval_sec": 5
}
```

---
