import argparse
import angr

def find_function_address(binary_path, function_name):
    # 初始化 Angr 项目
    proj = angr.Project(binary_path, auto_load_libs=False)

    # 使用 CFGFast 分析二进制程序
    cfg = proj.analyses.CFGFast()
    cfg.normalize()

    # 获取所有函数的起始地址
    function_addresses = {}
    for func in cfg.kb.functions.values():
        function_addresses[func.name] = func.addr

    # 找到给定函数的起始地址
    if function_name in function_addresses:
        return function_addresses[function_name]
    else:
        print(f"Function '{function_name}' not found in the binary.")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find the address of a function in a binary using Angr.")
    parser.add_argument('binary',
                      help='path to binary file.')
    parser.add_argument('-f', '--function', metavar='', required=True,
                      help='Name of the function to find.')
    args = parser.parse_args()

    function_address = find_function_address(args.binary, args.function)
    if function_address:
        print(f"The address of function '{args.function}' is: 0x{hex(function_address)}")
