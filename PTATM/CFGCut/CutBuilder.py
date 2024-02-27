from . import CutTool
import networkx as nx
import angr
from CFG2Segment import CFGBase, CFGRefactor, SFGBase, SFGBuilder
from functools import reduce
import sys
sys.path.append("..")


class SegmentBuilder:
    def __init__(self, max_seg: int, angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> None:
        # Normalize this cfg first if not normalized.
        if not angr_cfg.normalized:
            angr_cfg.normalize()
        self.angr_cfg = angr_cfg
        self.max_seg = max_seg

    def SFGInit(self):
        # Refactor CFG.
        cfg = CFGBase.CFG(self.angr_cfg)
        cfg_refactor = CFGRefactor.FunctionalCFGRefactor()
        refactor_result = cfg_refactor.refactor(cfg)

        # Build SFG.
        sfg = SFGBase.SFG(cfg)
        return sfg

    def genFuncSegment(self, sfg, func_names=None, output_path: str = None):
        # sfg = self.SFGInit()
        sfg_builder = SFGBuilder.FunctionalSFGBuilder(self.max_seg, func_names)
        build_result = sfg_builder.build(sfg)

        func_seg_names = []  # 生成的分段列表名
        func_seg_addrs = []  # 生成的分段列表地址
        for name in func_names:
            segfunc = sfg.getSegmentFunc(name)
            if segfunc is None:
                continue
            for segment in segfunc.segments:
                offset = hex(segment.startpoint.addr - segfunc.addr)
                probe_prefix = segment.name + "="
                probe_suffix = segfunc.name + ("+" + offset if offset != "0x0" else '')
                func_seg_names.append(probe_prefix + probe_suffix)
                func_seg_addrs.append(segment.startpoint.addr)
            func_seg_names.append(segfunc.name + "=" + segfunc.name + r"%return")
            last_block_addr = CutTool.FunctionTool.getFunctionLastBlockAddr(segfunc.function.angr_function)
            if last_block_addr != None:
                func_seg_addrs.append(last_block_addr)

        # 将函数分段结果输出到文件
        if output_path is not None:
            if len(func_seg_names) != 0:
                with open(output_path, 'a') as output:
                    output.write('\n' + reduce(lambda x, y: x + ',' + y, func_seg_names))
        return func_seg_names, func_seg_addrs


class CutMethod:
    # 对于任意两个节点，查找中间是否存在割边
    # 注意，cfg要已经去除了FakeRet
    @staticmethod
    def findCutEdges(cfg, start_addr: int, end_addr: int):
        start_node = cfg.get_any_node(start_addr)
        end_node = cfg.get_any_node(end_addr)
        return nx.minimum_edge_cut(cfg.graph, start_node, end_node)

    # 对于任意两个节点，查找是否存在割点函数
    @staticmethod
    def findCutFunction(cfg, start_addr: int, end_addr: int):
        ap = CutMethod.findCutEdges(cfg, start_addr, end_addr)
        if ap is None or len(ap) != 1:
            return None

        unrecommended_func = CutTool.FunctionTool.getUnrecommendFuncs(cfg, start_addr, end_addr)

        for node_pair in ap:
            for node in node_pair:
                cut_func_addr = node.function_address
                if cut_func_addr not in unrecommended_func and CutTool.FunctionTool.funcOnlyMainCall(cfg, func_addr=cut_func_addr):
                    return CutTool.FunctionTool.getFunctionObj(cfg, func_addr=cut_func_addr)
        return None


class CutFuncGetter:
    def __init__(self, max_seg: int, angr_cfg: angr.analyses.cfg.cfg_fast.CFGFast = None, binary: str = None, output_file: str = None) -> None:
        if angr_cfg is None:
            if binary is None:
                raise ValueError("When creating the CutFuncGetter class, angr_cfg and binary cannot both be None.")
            project = angr.Project(binary, load_options={'auto_load_libs': False})
            angr_cfg = project.analyses.CFGFast()
        # Normalize this cfg first if not normalized.
        if not angr_cfg.normalized:
            angr_cfg.normalize()
        self.angr_cfg = angr_cfg
        self.max_seg = max_seg
        self.output_file = output_file
        self.directed_cfg = CutTool.CFGTool.removeFakeRet(angr_cfg)
        # 要进行分段的函数名称集合
        self.seg_func_names = set(['main'])

    # 对于任意两个节点，查找是否存在割点函数
    # 如果有，添加到self.seg_func_names。并递归查找[start_block, cut_function_start_block]和[cut_function_end_block, end_block]之间的割点函数
    def findAddCutFunction(self, start_addr, end_addr):
        if start_addr == end_addr or start_addr is None or end_addr is None:
            return

        cut_func = CutMethod.findCutFunction(self.directed_cfg, start_addr, end_addr)
        if cut_func is None:
            return

        # 添加割点函数名称到self.seg_func_names
        self.seg_func_names.add(cut_func.name)

        cut_func_start_addr = cut_func.addr
        cut_func_end_addr = CutTool.FunctionTool.getFunctionLastBlockAddr(cut_func)
        self.findAddCutFunction(start_addr, cut_func_start_addr)
        self.findAddCutFunction(cut_func_end_addr, end_addr)
        return

    # 获取main函数的分段地址结果
    # 每次取出main函数相邻两个的地址，查找割点函数
    def findCutFunctionFromMain(self):
        sfg_builder = SegmentBuilder(self.max_seg, self.angr_cfg)
        sfg = sfg_builder.SFGInit()
        _, main_seg_addrs = sfg_builder.genFuncSegment(sfg, func_names=['main'])

        if len(main_seg_addrs) < 2:
            return

        # 每次取出main函数相邻两个的地址
        for i in range(len(main_seg_addrs) - 1):
            start_addr, end_addr = (main_seg_addrs[i], main_seg_addrs[i + 1])
            self.findAddCutFunction(start_addr, end_addr)

        if self.output_file is not None:
            sfg_builder.genFuncSegment(sfg, func_names=self.seg_func_names, output_path=self.output_file)
        return self.seg_func_names
