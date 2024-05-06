import angr
import Module.PTATM as PTATM

def service(args):
    from CFGCut import CutBuilder
    # Gen angr CFG of binary
    if args.verbose:
        PTATM.info(f'Gen Angr CFG for binary[{args.binary}].')
    project = angr.Project(args.binary, load_options={'auto_load_libs': False})
    angr_cfg = project.analyses.CFGFast()
    angr_cfg.normalize()
    # gen cut tool
    if args.verbose:
        PTATM.info(f'Start finding cut-function list for binary[{args.binary}].')
    cut_builder = CutBuilder.CutFuncGetter(max_seg=args.max_seg, angr_cfg=angr_cfg)
    sfg_builder = CutBuilder.SegmentBuilder(args.max_seg, angr_cfg)
    seg_func_names = cut_builder.findCutFunctionFromMain(sfg_builder)
    if len(seg_func_names) != 0:
        if args.verbose:
            PTATM.info(f'Find {len(seg_func_names)} isolated functions: {seg_func_names}.')
        seg_points = cut_builder.getTaskSegmentPoints(sfg_builder)
        cut_builder.saveTaskSegmentPoints(seg_points, args.output)
        if args.verbose:
                PTATM.info(f'Save cut-function segment result into ➜  {args.output}.')
                PTATM.info('Done.')
    elif args.verbose:
        PTATM.warn('No cut-function found, check code structure.')