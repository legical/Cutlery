#!/bin/bash

# This script is used to test the coverage of a C program
# It takes two arguments:
# 1. The source code file (.c file)
# 2. The input file to be used for testing
# 3. The mode to choose use binfile|cmdargs or not

# Check if the correct number of arguments is provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 <source_code_.c_file> <case_file> <mode>"
    echo "     mode: C for use cmd args, B for use exist binfile"
    exit 1
fi

# 检查文件是否存在，如果不存在则报错并退出
check_file_exists() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found."
        exit 1
    fi
}

# Assigning arguments to variables
src_file=$(readlink -f "$1")
case_file=$(readlink -f "$2")
check_file_exists "$src_file"
check_file_exists "$case_file"

# check mode
# 设置默认值
usecmdargs=false
usebinfile=false
# 获取最后一个参数
# 获取最后一个命令行参数
last_arg="${!#}"

# 判断最后一个命令行参数中是否存在C字符
if [[ "$last_arg" == *"C"* ]]; then
    usecmdargs=true
    echo "use cmd args to run program"
fi

# 判断最后一个命令行参数中是否存在B字符
if [[ "$last_arg" == *"B"* ]]; then
    usebinfile=true
    echo "use exist binfile: $usebinfile"
fi

# 获取 src_file 所在目录
program_dir=$(dirname "$src_file")
if ! cd "$program_dir"; then
    echo "Error: Failed to change directory to $program_dir"
    exit 1
fi

# 获取 src_file 相对于 program_dir 的路径
src_file=$(basename "$src_file")
# 获取二进制文件名
binfile=${src_file%.*}

if [ "$usebinfile" = false ]; then
    # Compile the source code file with coverage flags
    gcc --coverage "$src_file" -o "$binfile"
    # Check if compilation was successful
    if [ $? -ne 0 ]; then
        echo "Compilation failed"
        exit 1
    fi
fi

# Run the compiled program with input from input.txt
while IFS= read -r line; do
    # 检查是否为空行或者只包含空格
    if [ -z "$(echo "$line" | sed 's/ *//g')" ]; then
        continue
    fi
    if [ "$usecmdargs" = true ]; then
        ./${binfile} $line
    else
        echo "$line" | "./${binfile}"
    fi
done < "$case_file"

# Generate coverage report
outjson="${binfile}_coverage.json"
gcovr --json-summary "$outjson"

# Clean up generated files
rm -f "${binfile}.gcda" "${binfile}.gcno"
if [ "$usebinfile" = false ]; then
    rm -f "${binfile}"
fi

echo "Coverage report of [$program_dir/${src_file}] generated successfully to [$program_dir/$outjson]"

# 检查 jq 是否安装
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq."
    exit 1
fi

# 提取指定 key 的值
line_percent=$(jq -r '.line_percent' "$outjson")
function_percent=$(jq -r '.function_percent' "$outjson")
branch_percent=$(jq -r '.branch_percent' "$outjson")

# 输出结果
echo "line_percent: $line_percent"
echo "function_percent: $function_percent"
echo "branch_percent: $branch_percent"