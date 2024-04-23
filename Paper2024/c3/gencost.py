import angr
import argparse
import os
import sys
import time

sys.path.append("../../PTATM")
from CFGCut import CutBuilder

# 获取当前脚本所在的目录路径
script_dir = os.path.dirname(os.path.abspath(__file__))
mibench_dir = script_dir + '/benchmarks/mibench'
wcetbench_dir = script_dir + '/benchmarks/wcet_bench'    
    
# SPEC 06
bzip2 = "/usr/local/software/spec2006/benchspec/CPU2006/401.bzip2/run/run_base_ref_amd64-m64-gcc42-nn.0000/bzip2_base.amd64-m64-gcc42-nn"
gcc = "/usr/local/software/spec2006/benchspec/CPU2006/403.gcc/run/run_base_ref_amd64-m64-gcc42-nn.0000/gcc_base.amd64-m64-gcc42-nn"
mcf = "/usr/local/software/spec2006/benchspec/CPU2006/429.mcf/run/run_base_ref_amd64-m64-gcc42-nn.0000/mcf_base.amd64-m64-gcc42-nn"
calculix = "/usr/local/software/spec2006/benchspec/CPU2006/454.calculix/run/run_base_ref_amd64-m64-gcc42-nn.0000/calculix_base.amd64-m64-gcc42-nn"
libquantum = "/usr/local/software/spec2006/benchspec/CPU2006/462.libquantum/run/run_base_ref_amd64-m64-gcc42-nn.0000/libquantum_base.amd64-m64-gcc42-nn"
lbm = "/usr/local/software/spec2006/benchspec/CPU2006/470.lbm/run/run_base_ref_amd64-m64-gcc42-nn.0000/lbm_base.amd64-m64-gcc42-nn"
sphinx3 = "/usr/local/software/spec2006/benchspec/CPU2006/482.sphinx3/run/run_base_ref_amd64-m64-gcc42-nn.0000/sphinx_livepretend_base.amd64-m64-gcc42-nn"

# SPEC 17
_507 = "/usr/local/software/spec2017/benchspec/CPU/507.cactuBSSN_r/run/run_base_refrate_mytest-m64.0000/cactusBSSN_r_base.mytest-m64"
_549 = "/usr/local/software/spec2017/benchspec/CPU/549.fotonik3d_r/run/run_base_refrate_mytest-m64.0000/fotonik3d_r_base.mytest-m64"
_621 = "/usr/local/software/spec2017/benchspec/CPU/621.wrf_s/run/run_base_refspeed_mytest-m64.0000/wrf_s_base.mytest-m64"
_627 = "/usr/local/software/spec2017/benchspec/CPU/627.cam4_s/run/run_base_refspeed_mytest-m64.0000/cam4_s_base.mytest-m64"
_628 = "/usr/local/software/spec2017/benchspec/CPU/628.pop2_s/run/run_base_refspeed_mytest-m64.0000/speed_pop2_base.mytest-m64"

# linux tool
ls = "/bin/ls"
grep = "/bin/grep"
cat = "/bin/cat"

def get_all_files_in_directory(directory) -> list:
    file_paths = []
    # 获取目录下的所有文件和目录名称
    items = os.listdir(directory)
    for item in items:
        # 拼接文件的绝对路径
        file_path = os.path.join(directory, item)
        # 判断是否是文件，并且不是目录
        if os.path.isfile(file_path):
            # 添加到列表中
            file_paths.append(file_path)
    return file_paths


def get_benchmark_list() -> list:
    # generate benchmark list
    binarys = list()
    mibenchfiles = get_all_files_in_directory(mibench_dir)
    wcetbenchfiles = get_all_files_in_directory(wcetbench_dir)
    specs = [bzip2, gcc, mcf, calculix,
               libquantum, lbm, sphinx3, _507, _549, _621, _627, _628
               ]
    linuxtools = [ls, grep, cat]
    binarys.extend(mibenchfiles)
    binarys.extend(wcetbenchfiles)
    binarys.extend(specs)
    binarys.extend(linuxtools)
    return binarys
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate Segment cost', add_help=True)
    # parser.add_argument('target_path', help='Path to the target program')
    parser.add_argument(
        '-o', '--output', help='Path to save the cost file', required=True)
    parser.add_argument('-m', '--max-seg', type=int,
                        help='Max segment number', required=False, default=1000)
    parser.add_argument('-p', '--precision', type=int,
                        help='Round precision to the pth decimal place', required=False, default=8)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='generate detail')
    args = parser.parse_args()

    # generate benchmark list
    binarys = get_benchmark_list()
    
    # max_seg = 100
    # 结点数 边数 | Angr静态分析	CFG重建	孤立函数 分段 | 分段点数量  孤立函数数量  孤立函数展示
    with open(args.output, "a") as f:
        f.write(f"binary,结点数,边数,T-Angr静态分析,T-CFG重建,T-孤立函数,T-分段,分段点数量,待分段函数数量,孤立函数名\n")

    for i, binary in enumerate(binarys):
        # continue if binary not exist
        if os.path.exists(binary) == False:
            if args.verbose:
                print(f"{binary} not exist")
            continue

        if args.verbose:
            print(f"Start to process {binary}")
        # Parse binary with angr.
        angr_project = angr.Project(binary,
                                    load_options={'auto_load_libs': False})
        start = time.time()
        angr_cfg = angr_project.analyses.CFGFast()
        end = time.time()
        cost_gencfg = round(end - start, args.precision)
        angr_cfg.normalize()

        # 获取节点数量
        num_nodes = len(angr_cfg.graph.nodes())
        # 获取边数量
        num_edges = len(angr_cfg.graph.edges())

        # Refactor CFG.
        start = time.time()
        sfg_builder = CutBuilder.SegmentBuilder(args.max_seg, angr_cfg)
        end = time.time()
        cost_refactorcfg = round(end - start, args.precision)
        # print("timecost for CFG refactor:", round(end - start, 4))

        # find iso functions
        cut_builder = CutBuilder.CutFuncGetter(
            max_seg=args.max_seg, angr_cfg=angr_cfg)
        start = time.time()
        seg_func_names = cut_builder.findCutFunctionFromMain(sfg_builder)
        end = time.time()
        cost_isofunc = round(end - start, args.precision)
        
        if seg_func_names is None:
            continue
        n_isofuncs = len(seg_func_names)
        # print("timecost for segmentation:", round(end - start, 4))

        # task Segment
        start = time.time()
        seg_points = cut_builder.getTaskSegmentPoints(sfg_builder)
        end = time.time()
        cost_taskseg = round(end - start, args.precision)
        n_segpoints = len(seg_points) if seg_points is not None else 0

        # save task segment info
        # 结点数 边数 | Angr静态分析	CFG重建	孤立函数 分段 | 分段点数量  孤立函数数量  孤立函数展示
        with open(args.output, "a") as f:
            f.write(f"{os.path.basename(binary)},{num_nodes},{num_edges},{cost_gencfg},{cost_refactorcfg},{cost_isofunc},{cost_taskseg},{n_segpoints},{n_isofuncs},{seg_func_names}\n")

        if args.verbose:
            print(f"[{i+1}/{len(binarys)}] Done.\t{binary}")

# # automotive
# basicmath_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/basicmath_large"
# basicmath_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/basicmath_small"
# bitcnts = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/bitcnts"
# qsort_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/qsort_large"
# qsort_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/qsort_small"
# susan = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/susan"
# # network
# dijkstra_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/dijkstra_large"
# dijkstra_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/dijkstra_small"
# # office
# search_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/search_large"
# search_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/search_small"
# # security
# bf = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/bf"
# sha = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/sha"
# # telecomm
# crc = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/crc"
# fft = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/fft"
# gsm_toast = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/gsm_toast"
# gsm_untoast = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/gsm_untoast"