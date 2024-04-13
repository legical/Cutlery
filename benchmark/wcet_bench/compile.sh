#!/bin/bash

# 创建build目录
mkdir -p build

# 编译所有.c文件并将生成的二进制文件移动到build目录
for file in *.c; do
    # 提取文件名（不含扩展名）
    filename=$(basename -- "$file" .c)
    # 编译并生成二进制文件
    gcc "$file" -o "build/$filename"
done

echo "编译完成！所有二进制文件已存放在build目录中。"
