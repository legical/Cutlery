import angr, sys
from angrutils import *

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python3 ./thisfile binfile output")
        sys.exit(-1)
    binfile, output = sys.argv[1], sys.argv[2]
    print("Gen cfg for %s at main function with output %s." % (binfile, output))
    proj = angr.Project(binfile, load_options={'auto_load_libs': False})
    # main = proj.loader.main_object.get_symbol("main")
    # start_state = proj.factory.blank_state(addr=main.rebased_addr)
    # cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
    cfg = proj.analyses.CFGFast()
    cfg.normalize()
    plot_cfg(cfg, output, format='png', asminst=True, remove_imports=True, remove_path_terminator=True)
