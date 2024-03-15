import Module.PTATM as PTATM
from functools import reduce

def genprobes(binary: str, functions: list, max_seg: int, verbose: bool):
    import angr
    from CFG2Segment import CFGBase, CFGRefactor, SFGBase, SFGBuilder

    # Parse binary with angr.
    if verbose:
        PTATM.info('Build angr cfg for binary[%s].' % binary)
    angr_project = angr.Project(binary, load_options={'auto_load_libs': False})
    angr_cfg = angr_project.analyses.CFGFast()

    # Refactor CFG.
    if verbose:
        PTATM.info('Refactor angr cfg.')
    cfg = CFGBase.CFG(angr_cfg)
    cfg_refactor = CFGRefactor.FunctionalCFGRefactor()
    refactor_result = cfg_refactor.refactor(cfg)

    # Build SFG.
    if verbose:
        PTATM.info('Segment cfg with max_seg[%d] for function%s.' % (max_seg, functions))
    sfg = SFGBase.SFG(cfg)
    sfg_builder = SFGBuilder.FunctionalSFGBuilder(max_seg, functions)
    build_result = sfg_builder.build(sfg)

    # Dump uprobes.
    if verbose:
        PTATM.info('Dump uprobes.')
    probes = []
    for name in functions:
        segfunc = sfg.getSegmentFunc(name)
        if segfunc is None:
            continue
        for segment in segfunc.segments:
            offset = hex(segment.startpoint.addr - segfunc.addr)
            probe_prefix = segment.name + "="
            probe_suffix = segfunc.name + ("+" + offset if offset != "0x0" else '')
            probes.append(probe_prefix + probe_suffix)
        probes.append(segfunc.name + "=" + segfunc.name + r"%return")
    return probes


def service(args):
    if not hasattr(args, 'function'):
        args.function = ['main']
    probes = genprobes(args.binary, args.function, args.max_seg, args.verbose)
    if len(probes) != 0:
        if args.verbose:
            PTATM.info(f'Save result into ➜  {args.output}')
        with open(args.output, 'a') as output:
            output.write('\n' + reduce(lambda x, y: x + ',' + y, probes))
        if args.verbose:
            PTATM.info('Done.')
    elif args.verbose:
        PTATM.warn('Nothing to segment, check func arguments.')