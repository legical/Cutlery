import angr
import networkx as nx
from angrutils import *
import sys
import random


def show_object_info(obj):
    print(f"Object: {obj}\t Type: {type(obj)}")
    # 获取对象的所有属性
    attributes = dir(obj)

    # 打印每个属性和其类型
    for attr in attributes:
        if not attr.startswith(('__', 'syscall_name')):  # 过滤掉一些特殊属性
            attr_value = getattr(obj, attr)
            attr_type = type(attr_value)
            print(f"Attribute: {attr}, Type: {attr_type}")
    print("")


def get_function_block(func: angr.knowledge_plugins.functions.function.Function, addr):
    # 获取特定地址的 BlockNode 对象
    for block in func.blocks:
        if block.addr == addr:
            return block
    return None


def get_function_endaddr(func: angr.knowledge_plugins.functions.function.Function):
    # 获取函数的终止基本块地址
    if len(func.ret_sites) == 1:
        print(f"{type(func.ret_sites[0])} \n {func.ret_sites[0].addr}")
        return func.ret_sites[0].addr
    return None

def show_graph_nodes(graph):
    for node in graph.nodes:
        if node is None:
            continue
        # if has attr 'name', check it equal None.
        if hasattr(node, 'name') and node.name is None:
            continue
        if isinstance(node, angr.knowledge_plugins.cfg.cfg_node.CFGNode):
            print(f"{type(node)}\t{node.name}\t{node.successors}")
        elif isinstance(node, angr.knowledge_plugins.functions.function.Function):
            print(f"{type(node)}\t{node.name}")
        else:
            print(f"{type(node)}\t{node}")

    print("")


def get_articulation_points(target_path):
    print("get articulation_points for [%s]." % (target_path))
    project = angr.Project(target_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast()
    cfg.normalize()

    # show_graph_nodes(cfg.graph)

    # 获取 main 函数的起始地址和终止地址
    main_function = cfg.functions.function(name="main")
    caseb_function = cfg.functions.function(name="caseb")
    main_start_address = main_function.addr + 0x46
    main_end_address = main_function.addr + 0x50

    # 获取 main 函数的 CFGNode
    start_node = cfg.get_any_node(main_start_address)
    end_node = cfg.get_any_node(main_end_address)

    print(f"{main_function.addr} {cfg.get_any_node(main_start_address).function_address}")

    # 检测并移除属性值为 'Ijk_FakeRet' 的边
    edges_to_remove = [(u, v) for u, v, data in cfg.graph.edges(data=True) if data.get('jumpkind') == 'Ijk_FakeRet']
    cfg.graph.remove_edges_from(edges_to_remove)

    # start_node = get_function_block(main_function, main_start_address)
    # end_node = get_function_block(main_function, main_end_address)
    ap = nx.minimum_edge_cut(cfg.graph, start_node, end_node)
    if ap is None:
        print("No articulation_points found.")
        return
    else:
        print(f"find {len(ap)} cut nodes.")
        for node in ap:
            print(node)
            print(f"{node[0]} {node[0].addr} {node[0].name} {node[0].function_address}")
            print(cfg.graph.get_edge_data(node[0], node[1]))

            for innernode in node:
                if innernode.function_address == main_function.addr:
                    print(f"{innernode} belong to main function.")
                else:
                    print(f"{innernode} not belong to main function, can be used to find cut function.")

    # 获取main函数的终止地址
    main_terminating_address = get_function_endaddr(main_function)
    print(
        f"Main function terminating address: {hex(main_terminating_address)} = main+{hex(main_terminating_address - main_function.addr)}")


def analyze_binary(binary_path):
    # 创建一个Project对象，加载二进制文件
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast()
    cfg.normalize()

    for func in cfg.functions.values():
        if isUserFunction(func):
            node = cfg.get_any_node(func.addr)
            if 1 == len(node.predecessors) and node.predecessors[0].name.find("main") != -1:
                print(f"{func.name}\tpre: {node.predecessors[0].name}")


def isUserFunction(angr_function: angr.knowledge_plugins.functions.function.Function) -> bool:
    # Normalize this angr_function first if not normalized.
    if not angr_function.normalized:
        angr_function.normalize()
    sys_compiler_funcs = ["_init", "_start", "__do_global_dtors_aux", "frame_dummy", "_fini"]
    if angr_function.is_plt or angr_function.has_unresolved_jumps or angr_function.is_simprocedure or angr_function.is_default_name or angr_function.is_syscall or angr_function.name in sys_compiler_funcs or 0 == angr_function.size:
        return False
    else:
        return True


def getUserFunctionList(cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> list:
    # Normalize this cfg and func first if not normalized.
    if not cfg.normalized:
        cfg.normalize()

    funcList = list()
    for func in cfg.functions.values():
        if isUserFunction(func):
            funcList.append(func.addr)
    return funcList


def funcOnlyMainCall(cfg: angr.analyses.cfg.cfg_fast.CFGFast, func: angr.knowledge_plugins.functions.function.Function) -> bool:
    if not isUserFunction(func):
        return False

    node = cfg.get_any_node(func.addr)

    if node.predecessors is None:
        return False

    if 1 == len(node.predecessors) and node.predecessors[0].name.find("main") != -1:
        return True

    return False


def getNode(cfg, addr):
    return cfg.get_any_node(addr)


def DFSShowFuncNode(cfg, node: angr.knowledge_plugins.cfg.cfg_node.CFGNode):
    if node is None:
        return

    print(node.name)

    if node.successors is None:
        print(f"{node.name}.successors is None")
        return

    for successor in node.successors:
        if isinstance(successor, angr.knowledge_plugins.cfg.cfg_node.CFGNode):
            DFSShowFuncNode(cfg, successor)
            break
        elif isinstance(successor, angr.knowledge_plugins.functions.function.Function):
            if successor.addr == node.function_address:
                continue
            else:
                if isUserFunction(successor):
                    successorNode = getNode(cfg, successor.addr)
                    DFSShowFuncNode(cfg, successorNode)
                    break
        else:
            # Add to unresolved_block.
            continue


def showFuncNodeAddr(binary_path, func_name: str):
    # 创建一个Project对象，加载二进制文件
    project = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast()
    cfg.normalize()

    # get function by name
    func = cfg.functions.get(func_name, None)
    if func is None:
        print("function [%s] not found." % (func_name))
        return

    # get all nodes in this function
    # for addr in func.block_addrs_set:
    #     node = cfg.get_any_node(addr)
    #     # print node_name%node_addr
    #     print(f"{node.name}")

    # get start node
    start_node = cfg.get_any_node(func.addr)
    DFSShowFuncNode(cfg, start_node)

def testCut(binary:str):
    import sys
    sys.path.append("../PTATM/")
    from CFGCut import CutBuilder
    cut_builder = CutBuilder.CutFuncGetter(4, binary=binary)
    seg_func_names = cut_builder.findCutFunctionFromMain()
    print(seg_func_names)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python3 drawcfg.py /path/to/your/target/program -o /path/to/save/output/graph")
        sys.exit(-1)
    import argparse
    parser = argparse.ArgumentParser(description='Generate CFG graph using angr and save it to a file')
    parser.add_argument('target_path', help='Path to the target program')
    parser.add_argument('-f', '--function', help='funtion name', required=False, default='main')
    # parser.add_argument('-o', '--output', help='Path to save the CFG graph', required=True)
    args = parser.parse_args()

    # showFuncNodeAddr(args.target_path, args.function)
    testCut(args.target_path)
