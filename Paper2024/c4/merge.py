

import argparse
import datetime
import os

import chardet
def saveCases(case_path: str) -> str:
    # copy all .in files in in_path to cases_file
    test_cases = ""
    for filename in os.listdir(case_path):
        if filename.endswith(".in"):
            with open(os.path.join(case_path, filename), "rb") as file:  # 以二进制模式打开文件
                raw_data = file.read()
                detected_encoding = chardet.detect(raw_data)['encoding']
                if detected_encoding:
                    test_cases += raw_data.decode(detected_encoding)
                else:
                    # 如果无法检测编码，则默认使用UTF-8
                    test_cases += raw_data.decode("utf-8", errors="replace")
                test_cases += '\n'
                
    # 去除多余的空行和空格
    test_cases = '\n'.join([line.strip() for line in test_cases.splitlines() if line.strip()])
                
    return test_cases

def merge(in_path:str):
    # 保存本次输出的seeds
    cases_file = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    cases_file_path = os.path.join(in_path, f"{cases_file}.txt")
            
    test_cases = saveCases(in_path)
    # 将聚合后的测试用例内容写入到输出文件中
    with open(cases_file_path, "a", encoding="utf-8") as output_file:
        output_file.write(test_cases)
            
    return cases_file_path
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Merge seeds', add_help=True)
    # parser.add_argument('target_path', help='Path to the target program')
    parser.add_argument(
        '-i', '--input', help='Path to save the .in file', required=True)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='generate detail')
    args = parser.parse_args()
    
    cases_file_path = merge(args.input)
    if args.verbose:
        print(f"Merge seeds to {cases_file_path}")