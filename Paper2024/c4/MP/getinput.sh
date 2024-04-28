#!/bin/bash

# 检查参数是否正确
if [ $# -lt 2 ]; then
    echo "Usage: $0 <binfile> <case.txt> [<output_file>]"
    exit 1
fi

binfile="$1"
case_file="$2"

# 检查是否提供了自定义输出文件名
if [ $# -eq 3 ]; then
    output_file="$3"
else
    output_file="casein.txt"
fi

# 确保输入文件存在
if [ ! -f "$binfile" ]; then
    echo "Error: $binfile does not exist."
    exit 1
fi

if [ ! -f "$case_file" ]; then
    echo "Error: $case_file does not exist."
    exit 1
fi

# 清空输出文件
> "$output_file"

# 逐行读取case.txt并执行命令
while IFS= read -r line; do
    # 执行binfile并捕获输出
    outstr=$(echo "$line" | ./"$binfile")
    # 将line和outstr写入输出文件
    echo "$line,$outstr" >> "$output_file"
done < "$case_file"

echo "Execution completed. Results written to $output_file."
