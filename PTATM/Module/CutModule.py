import Module.PTATM as PTATM

def service(args):
    from CFGCut import CutBuilder
    cut_builder = CutBuilder.CutFuncGetter(max_seg=args.max_seg, binary=args.binary, output_file=args.output)
    if args.verbose:
        PTATM.info(f'Start finding cut-function list for binary[{args.binary}].')
    seg_func_names = cut_builder.findCutFunctionFromMain()
    if len(seg_func_names) != 0:
        if args.verbose:
            PTATM.info(f'Find cut-node function list: {seg_func_names}.')
            PTATM.info(f'Save cut-function segment result into ➜  {args.output}.')
            PTATM.info('Done.')
    elif args.verbose:
        PTATM.warn('No cut-function found, check code structure.')