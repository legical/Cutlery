import angr
import networkx as nx
from angrutils import *
import sys
import random

def get_articulation_points(target_path):
    print("get articulation_points for [%s]." % (target_path))
    project = angr.Project(target_path, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast()
    cfg.normalize()
    ap = nx.minimum_node_cut(cfg, flow_func="shortest_augmenting_path")
    print(ap)

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
    analyze_binary(args.target_path)