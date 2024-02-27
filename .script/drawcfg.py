import angr
import sys
from angrutils import *
import argparse


def isUserFunction(angr_function: angr.knowledge_plugins.functions.function.Function) -> bool:
    # Normalize this angr_function first if not normalized.
    if not angr_function.normalized:
        angr_function.normalize()
    sys_compiler_funcs = ["_init", "_start", "__do_global_dtors_aux", "frame_dummy", "_fini"]
    if angr_function.is_plt or angr_function.has_unresolved_jumps or angr_function.is_simprocedure or angr_function.is_default_name or angr_function.is_syscall or angr_function.name in sys_compiler_funcs or 0 == angr_function.size:
        return False
    else:
        return True


def getFunc(project, addr: int = None, name: str = None) -> angr.knowledge_plugins.functions.function.Function:
    # get Angr function object by addr
    if addr is not None:
        return project.kb.functions.function(addr=addr)
    # get Angr function object by name
    if name is not None:
        return project.kb.functions.function(name=name)
    return None


def getUserFunctionList(cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> dict:
    # Normalize this cfg and func first if not normalized.
    if not cfg.normalized:
        cfg.normalize()

    funcList = dict()
    for func in cfg.functions.values():
        if isUserFunction(func):
            # add func.addr:func
            funcList[func.addr] = func
    return funcList


def processGraph(cfg, all_cfg: bool = False, remove_fakeret: bool = False):
    # Normalize this cfg and func first if not normalized.
    if not cfg.normalized:
        cfg.normalize()

    # Remove all edges with jumpkind 'Ijk_FakeRet'
    if remove_fakeret:
        edges_to_remove = [(u, v) for u, v, data in cfg.graph.edges(data=True) if data.get('jumpkind') == 'Ijk_FakeRet']
        cfg.graph.remove_edges_from(edges_to_remove)

    # Remove all edges which are not from main function
    if not all_cfg:
        main_function = cfg.kb.functions.function(name="main")
        target_node = cfg.get_any_node(main_function.addr)
        subgraphs = list(nx.weakly_connected_components(cfg.graph))
        target_subgraph = None
        for subgraph in subgraphs:
            if target_node in subgraph:
                target_subgraph = subgraph
                break
        # 删除其他节点和边
        nodes_to_remove = set(cfg.graph.nodes()) - target_subgraph
        cfg.graph.remove_nodes_from(nodes_to_remove)

    return cfg


def generate_cfg(target_path, output_path, use_emulated: bool = False, all_cfg: bool = False, remove_fakeret: bool = False):
    print("Gen cfg for [%s] at main function with output [%s]." % (target_path, output_path))
    project = angr.Project(target_path, load_options={'auto_load_libs': False})

    if use_emulated:
        cfg = project.analyses.CFGEmulated()
    else:
        cfg = project.analyses.CFGFast()

    # 获取函数对象
    function = project.kb.functions.function(name="main")

    # 获取函数对象的最后一个基本块
    last_block = function.endpoints[0]
    print(len(function.endpoints))

    # 打印最后一个基本块的地址
    print(f"最后一个基本块的地址：{hex(last_block.addr)} = main + {hex(last_block.addr - function.addr)}")

    cfg = processGraph(cfg, all_cfg, remove_fakeret)

    if output_path.endswith('.png') or output_path.endswith('.jpg'):
        output_path = output_path[:-4]  # 去掉结尾的.png或.jpg
    plot_cfg(cfg, output_path, format='png', asminst=True, remove_imports=True,
             remove_path_terminator=True, remove_simprocedures=True, comments=False)


def usage():
    print("usage: python3 drawcfg.py /path/to/your/target/program -o /path/to/save/output/graph")
    print("""
          Generate CFG graph using angr and save it to a PNG file.

          positional arguments:
            target_path           Path to the target program
          
          optional arguments:
            -h, --help            show this help message and exit
            -e, --emulated        Use CFGEmulated instead of CGFFast
            -a, --all-cfg         Draw all CFG, not just main function
            -r, --remove-fakeret  Remove all edges with jumpkind Ijk_FakeRet
          """)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate CFG graph using angr and save it to a PNG file', add_help=True)
    parser.add_argument('target_path', help='Path to the target program')
    parser.add_argument('-o', '--output', help='Path to save the CFG graph', required=True)
    parser.add_argument('-e', '--emulated', action='store_true',
                        help='Use CFGEmulated instead of CGFFast', required=False, default=False)
    parser.add_argument('-a', '--all-cfg', action='store_true',
                        help='Draw all CFG, not just main function', required=False, default=False)
    parser.add_argument('-r', '--remove-fakeret', action='store_true',
                        help='Remove all edges with jumpkind Ijk_FakeRet', required=False, default=False)
    args = parser.parse_args()

    generate_cfg(args.target_path, args.output, args.emulated, args.all_cfg, args.remove_fakeret)
