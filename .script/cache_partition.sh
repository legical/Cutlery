#!/bin/bash

# 检查是否以sudo或root权限运行，否则退出并报错
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root or with sudo." >&2
    exit 1
fi

# 设置LLC分配策略
# -R: 重置所有LLC分配配置
# -e "llc:1=0x00f0;llc:0=0x000f": 将LLC(最后一级缓存)的第0个和第1个分配给指定的CPU集合
# -a "llc:0=1;llc:1=2": 将第0个LLC分配给CPU集合1，将第1个LLC分配给CPU集合2
# -s: 显示LLC分配配置
pqos -R
pqos -e "llc:1=0x00f0;llc:0=0x000f"
pqos -a "llc:0=1;llc:1=2"
pqos -s
