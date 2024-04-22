import os
import sys, time

sys.path.append("../..")
from functools import reduce
from CFG2Segment.CFGBase import CFG
from CFG2Segment.CFGRefactor import FunctionalCFGRefactor
from CFG2Segment.SFGBase import SFG
from CFG2Segment.SFGBuilder import FunctionalSFGBuilder
import argparse, angr
from PTATM.CFGCut import CutBuilder

# automotive
basicmath_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/basicmath_large"
basicmath_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/basicmath_small"
bitcnts = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/bitcnts"
qsort_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/qsort_large"
qsort_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/qsort_small"
susan = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/susan"
# network
dijkstra_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/dijkstra_large"
dijkstra_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/dijkstra_small"
# office
search_large = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/search_large"
search_small = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/search_small"
# security
bf = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/bf"
sha = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/sha"
# telecomm
crc = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/crc"
fft = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/fft"
gsm_toast = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/toast"
gsm_untoast = "/home/hao/Project/PTATM-AFL/Paper2024/c3/benchmarks/untoast"

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

if __name__ == "__main__":
    binarys = [
        basicmath_large, basicmath_small, bitcnts, qsort_large, qsort_small,
        susan, dijkstra_large, dijkstra_small, search_large, search_small, bf,
        sha, crc, fft, gsm_toast, gsm_untoast, bzip2, gcc, mcf, calculix,
        libquantum, lbm, sphinx3, _507, _549, _621, _627, _628
    ]

    max_seg = 100

    for binary in binarys:
        # continue if binary not exist
        if os.path.exists(binary) == False:
            continue
        # Parse binary with angr.
        angr_project = angr.Project(binary,
                                    load_options={'auto_load_libs': False})
        start = time.time()
        angr_cfg = angr_project.analyses.CFGFast()
        end = time.time()
        cost_gencfg = round(end - start, 6)
        angr_cfg.normalize()

        # Refactor CFG.
        start = time.time()
        sfg_builder = CutBuilder.SegmentBuilder(max_seg, angr_cfg)
        sfg = sfg_builder.SFGInit()
        end = time.time()
        cost_funccfg = round(end - start, 6)
        # print("timecost for CFG refactor:", round(end - start, 4))

        # Build SFG.
        sfg = SFG(angr_cfg)
        sfg_builder = FunctionalSFGBuilder(max_seg)
        start = time.time()
        build_result = sfg_builder.build(sfg)
        end = time.time()
        print("timecost for segmentation:", round(end - start, 4))

        # Collect probes from segment information.
        # Probe format: EVENT=PROBE => segment.name=function.name+offset
        probes = []
        for name, segfunc in sfg.functions.items():
            for segment in segfunc.segments:
                offset = hex(segment.startpoint.addr - segfunc.addr)
                probe_prefix = segment.name + "="
                probe_suffix = segfunc.name + ("+" + offset
                                               if offset != "0x0" else '')
                probes.append(probe_prefix + probe_suffix)
            probes.append(segfunc.name + "=" + segfunc.name + r"%return")

        # Collect nr_node, nr_edge
        nr_node, nr_edge = 1, 0
        for name in sfg.functions.keys():
            cfgfunc = cfg.functions[name]
            for node in cfgfunc.nodes.values():
                if len(node.successors) != 0:
                    nr_node += 1
                    nr_edge += len(node.successors)

        # Output
        print("nr_node , nr_edge =", nr_node, ",", nr_edge)

        print(reduce(lambda x, y: x + ',' + y, probes))
        print("refactor result", refactor_result)
        print("refactor failed", cfg_refactor.failed)
        print("segment  result", build_result)
        print("segment  failed", sfg_builder.build_failed)
