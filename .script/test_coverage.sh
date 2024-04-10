#!/bin/bash

# Check if the correct number of arguments is provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <source_code_file> <input_file>"
    exit 1
fi

# Assigning arguments to variables
source_code_file="$1"
input_file="$2"

# Compile the source code file with coverage flags
gcc -fprofile-arcs -ftest-coverage "$source_code_file" -o "${source_code_file%.*}"

# Check if compilation was successful
if [ $? -ne 0 ]; then
    echo "Compilation failed"
    exit 1
fi

# Run the compiled program with input from input.txt
while IFS= read -r input_line; do
    ./"${source_code_file%.*}" <<< "$input_line" >/dev/null
done < "$input_file"

# Generate coverage report
gcov "${source_code_file%.*}"

# Display coverage report
lcov --summary "*/${source_code_file%.*}.gcov"

# Clean up generated files
rm -f "${source_code_file%.*}" "${source_code_file%.*}.gcda" "${source_code_file%.*}.gcno"
