import argparse
import angr

def showFuncAttr(cfg: angr.analyses.cfg.cfg_fast.CFGFast) -> dict:
    # Normalize this cfg and func first if not normalized.
    if not cfg.normalized:
        cfg.normalize()

    for func in cfg.functions.values():
        print(f"funcname: {func.name}")
        print(f"is_plt: {func.is_plt}")
        print(f"has_unresolved_jumps: {func.has_unresolved_jumps}")
        print(f"is_simprocedure: {func.is_simprocedure}")
        print(f"is_default_name: {func.is_default_name}")
        print(f"size==0?: {func.size == 0}\n")


def genCFG(target_path:str, lib:bool=False):
    project = angr.Project(target_path, load_options={'auto_load_libs': lib})
    cfg = project.analyses.CFGFast()
    showFuncAttr(cfg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate CFG graph using angr and save it to a PNG file', add_help=True)
    parser.add_argument('target_path', help='Path to the target program')
    parser.add_argument('-l', '--lib', action='store_true',
                      help='auto_load_libs')
    args = parser.parse_args()
    genCFG(args.target_path, args.lib)