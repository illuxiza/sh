# IP Quality Check Script

IP质量检测脚本 - 基于开源项目修改的个人定制版本

## 项目简介

本项目基于 [xykt/IPQuality](https://github.com/xykt/IPQuality) 项目进行修改，主要自用。该脚本用于检测IP地址的质量，包括IP地理位置、风险评分、流媒体解锁情况等多个维度的综合检测。

## 主要修改内容

### 新增功能
- ✅ **Instagram检测** - 添加了Instagram流媒体解锁状态检测

### 移除功能
- ❌ **Disney+检测** - 移除了Disney+流媒体检测
- ❌ **Spotify检测** - 移除了Spotify流媒体检测

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
- `-n` 无交互模式
- `-o output` 指定输出文件
- `-x proxy` 指定代理
- `-y` 轻量模式
- `-E` 跳过依赖安装

## 系统要求

- Bash 4.0+
- 必要依赖：jq, curl, bc, netcat, dnsutils, iproute

脚本会自动检测并安装缺失的依赖项。

## 免责声明

本项目仅用于学习和个人研究目的。使用者需遵守当地法律法规，不得将本脚本用于任何非法用途。

## 致谢

感谢原始项目 [xykt/IPQuality](https://github.com/xykt/IPQuality) 提供的优秀基础代码。