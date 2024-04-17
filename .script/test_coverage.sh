#!/bin/bash

# This script is used to test the coverage of a C program
# It takes two arguments:
# 1. The source code file (.c file)
# 2. The input file to be used for testing
# 3. The mode of input, default is scanf mode

# Check if the correct number of arguments is provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 <source_code_.c_file> <input_file> <mode>"
    echo "     mode: @ for cmd args, otherwise for scanf like"
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
source_code_file=$(readlink -f "$1")
input_file=$(readlink -f "$2")

# check mode
CMD_ARGS_MODE="@"
SCANF_MODE="scanf"
mode=$SCANF_MODE

if [ $# -ge 3 ] && [ "$3" = "@" ]; then
    mode=$CMD_ARGS_MODE
    echo "Using command line arguments mode"
else
    echo "Using scanf mode"
fi

check_file_exists "$source_code_file"
check_file_exists "$input_file"

# 获取 source_code_file 所在目录
program_dir=$(dirname "$source_code_file")
if ! cd "$program_dir"; then
    echo "Error: Failed to change directory to $program_dir"
    exit 1
fi

pwd
# 获取 source_code_file 和 input_file 相对于 program_dir 的路径
source_code_file=$(basename "$source_code_file")

# Compile the source code file with coverage flags
gcc --coverage "$source_code_file" -o "${source_code_file%.*}"

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

# Run the compiled program with input from input.txt
while IFS= read -r line; do
    # 检查是否为空行或者只包含空格
    if [ -z "$(echo "$line" | sed 's/ *//g')" ]; then
        continue
    fi
    if [ "$mode" = "$CMD_ARGS_MODE" ]; then
        ./${source_code_file%.*} $line
    else
        echo "$line" | "./${source_code_file%.*}"
    fi
done < "$input_file"

# Generate coverage report
outjson="${source_code_file%.*}_coverage.json"
gcovr --json-summary "$outjson"

# Clean up generated files
rm -f "${source_code_file%.*}" "${source_code_file%.*}.gcda" "${source_code_file%.*}.gcno"

echo "Coverage report of [$program_dir/${source_code_file}] generated successfully to [$program_dir/$outjson]"

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