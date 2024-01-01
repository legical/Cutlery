#!/bin/bash

# 使用方法
# source init.sh

# 获取脚本所在目录的绝对路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 设置环境变量PTATM的值为脚本所在目录
export PTATM="$SCRIPT_DIR"

echo "PTATM已设置为：$PTATM"

# 设置CPU频率为最高
sudo su <<HERE
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor > /dev/null

echo "CPU频率已设置为最高"

# 将 coredump 输出到文件
echo core >/proc/sys/kernel/core_pattern
# 退出特权用户环境
HERE