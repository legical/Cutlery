import angr
import sys
from angrutils import *

def generate_cfg(target_path, output_path):
    print("Gen cfg for [%s] at main function with output [%s]." % (target_path, output_path))
    project = angr.Project(target_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast()
    cfg.normalize()
    if output_path.endswith('.png') or output_path.endswith('.jpg'):
        output_path = output_path[:-4]  # 去掉结尾的.png或.jpg
    plot_cfg(cfg, output_path, format='png', asminst=True, remove_imports=True, remove_path_terminator=True)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("usage: python3 drawcfg.py /path/to/your/target/program -o /path/to/save/output/graph")
        sys.exit(-1)
    import argparse
    parser = argparse.ArgumentParser(description='Generate CFG graph using angr and save it to a file')
    parser.add_argument('target_path', help='Path to the target program')
    parser.add_argument('-o', '--output', help='Path to save the CFG graph', required=True)
    args = parser.parse_args()

    generate_cfg(args.target_path, args.output)


