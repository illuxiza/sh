# IP Quality Check Script

IP质量检测脚本 - 基于开源项目修改的个人定制版本

## 项目简介

本项目基于 [xykt/IPQuality](https://github.com/xykt/IPQuality) 项目进行修改，主要自用。该脚本用于检测IP地址的质量，包括IP地理位置、风险评分、流媒体解锁情况等多个维度的综合检测。

直接使用: 
```
bash <(curl -fsSL https://github.com/illuxiza/sh/raw/main/ip/ip-quality.sh)
```

## 主要修改内容

### 新增功能
- ✅ **Instagram检测** - 添加了Instagram流媒体解锁状态检测

### 移除功能
- ❌ **Disney+检测** - 移除了Disney+流媒体检测
- ❌ **Spotify检测** - 移除了Spotify流媒体检测
- ❌ **Reddit检测** - 使用Instagram检测代替
- ❌ 邮件连通性检测、广告和在线报告上传

默认检测IPv4，报告中的IPv4地址隐藏最后一段（`A.B.C.*`）；使用`-f`显示完整IP。

## 2026-10-08 更新

选择性同步上游`xykt/IPQuality`的`v2026-09-16`修复，保留上述定制内容：

- 增加出口IP查询来源，校验IP格式及请求是否成功。
- 更新ipapi接口，支持原接口回退；拒绝错误响应和异常数据结构，避免`jq`及`awk`报错。
- 更新DB-IP JSON接口，保留指定网卡、代理和IP协议；返回IP与检测IP不一致时不显示该数据源结果。
- 修复DNS解锁误判、TikTok无效请求参数和DNS黑名单错误码处理。
- 修复Amazon地区提取导致网页内容混入报告的问题；Instagram语言信息不再当作IP所在国家。
- 补充JSON中的IP2Location公司类型，修正中文报告时间和连续生成报告时的状态隔离。

第三方接口被限流或返回错误时，对应数据可能缺失；更新无法保证第三方接口始终可用。

## 支持的检测项目

### IP信息检测
- MaxMind
- IPinfo
- Scamalytics
- IPregistry
- IPapi
- AbuseIPDB
- IP2Location
- DBIP
- IPwhois
- IPdata
- IPQS

### 流媒体检测
- ✅ TikTok
- ✅ YouTube
- ✅ Amazon Prime Video
- ✅ Instagram (新增)
- ✅ ChatGPT

## 使用方法

### 基本用法
```bash
bash ip-quality.sh
```

### 参数说明
```bash
bash [-4] [-6] [-f] [-h] [-j] [-i iface] [-l language] [-n] [-o output] [-x proxy] [-y] [-E]
```

- `-4` 测试IPv4
- `-6` 测试IPv6
- `-f` 报告中显示完整IP地址
- `-h` 显示帮助信息
- `-j` JSON格式输出
- `-i iface` 指定网络接口
- `-l language` 指定语言
- `-n` 跳过系统检测及依赖安装
- `-o output` 指定输出文件
- `-x proxy` 指定代理
- `-y` 自动安装依赖
- `-E` 使用英文输出

## 回归检查

使用Bash 4.0+和jq执行离线测试，不会运行完整检测、安装依赖或访问外部接口：

```bash
bash ip/tests/regression.sh
```

## 系统要求

- Bash 4.0+
- 必要依赖：jq, curl, bc, netcat, dnsutils, iproute

脚本会自动检测并安装缺失的依赖项。

## 免责声明

本项目仅用于学习和个人研究目的。使用者需遵守当地法律法规，不得将本脚本用于任何非法用途。

## 致谢

感谢原始项目 [xykt/IPQuality](https://github.com/xykt/IPQuality) 提供的优秀基础代码。
