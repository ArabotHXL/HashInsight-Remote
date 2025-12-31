# Edge Collector 快速启动指南

## 5分钟快速部署

### 第1步：下载文件

将以下文件复制到矿场本地服务器：
- `cgminer_collector.py` - 主程序
- `collector_config_example.json` - 配置模板

### 第2步：安装Python依赖

```bash
pip install requests
```

### 第3步：获取API密钥

1. 登录 HashInsight 平台
2. 进入 **托管管理 → 站点运营 → Edge Collectors**
3. 点击 **"生成密钥"**
4. 选择你的矿场站点
5. **立即复制密钥**（只显示一次！）

### 第4步：配置采集器

1. 复制配置模板：
```bash
cp collector_config_example.json collector_config.json
```

2. 编辑 `collector_config.json`：
```json
{
    "api_url": "https://calc.hashinsight.net/api/collector/upload",
    "api_key": "粘贴你的API密钥",
    "site_id": "site_001",
    "collection_interval": 60,
    "ip_ranges": [
        {
            "range": "192.168.1.1-192.168.1.254",
            "prefix": "MINER_",
            "type": "antminer"
        }
    ]
}
```

**重要配置项：**
- `api_key`: 替换为你从平台获取的密钥
- `ip_ranges.range`: 改为你矿场矿机的实际IP范围

### 第5步：测试连接

```bash
# 测试单个矿机
python cgminer_collector.py --test 192.168.1.100

# 单次采集测试
python cgminer_collector.py --once
```

### 第6步：启动采集

```bash
# 前台运行（测试用）
python cgminer_collector.py

# 后台运行（生产用）
nohup python cgminer_collector.py > collector.log 2>&1 &
```

---

## 验证数据上传

1. 回到 HashInsight 平台
2. 进入 **设备管理** 页面
3. 查看矿机列表中 **CGMiner** 列
4. 绿色 = 在线，灰色 = 离线

---

## 常见问题

### Q: 连接超时怎么办？
确保矿机开启了 CGMiner API：
- Antminer: 在矿机web界面开启API
- Whatsminer: 默认开启

### Q: 提示 "Invalid API key"？
1. 确认密钥复制完整（无多余空格）
2. 重新生成密钥

### Q: 数据没有更新？
1. 检查 collector.log 日志
2. 确认网络能访问 calc.hashinsight.net
3. 确认矿机IP范围正确

---

## 支持的矿机型号

| 品牌 | 型号 | 类型标识 |
|------|------|----------|
| Bitmain | S19/S21/T19 | antminer |
| MicroBT | M30/M50/M60 | whatsminer |
| Canaan | A12/A13 | avalon |

---

## 联系支持

如有问题，请提交工单或联系技术支持。


### Remote control notes

- Enable commands with `enable_commands: true`.
- Commands are executed **by miner_id**; cloud `ip_address` fields (if any) are ignored.
- A stable `device_id` is generated at `cache_dir/device_id`.
