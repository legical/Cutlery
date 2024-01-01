import angr
import sys
from angrutils import *

def generate_cfg(program_path):
    # 创建一个angr项目对象
    project = angr.Project(program_path, auto_load_libs=False)

    # 使用angr中的CFGFast类生成程序的CFG
    cfg = project.analyses.CFGFast()

    #使用完整生成方法生成CFG
    cfg1 = project.analyses.CFGEmulated()

    #调用angr-utils库可视化
    plot_cfg(cfg1, "生成的cfg文件名", asminst=True, remove_imports=True, remove_path_terminator=True)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_cfg.py <program_path>")
        sys.exit(1)

    program_path = sys.argv[1]
    generate_cfg(program_path)
