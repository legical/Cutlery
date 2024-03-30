import Module.PTATM as PTATM
from Fuzz import FuzzEnv, FuzzTool

def initWorkspace(args):
    # Check input and output directories for legality.
    if args.verbose:
        PTATM.info('Check Fuzzing env for legality.')
    FuzzEnv.CheckEnv.checkWorkspace(args.input, args.output, args.binary)
    # Get Segment list.
    seginfo = FuzzEnv.Seginfo.getSegInfo(args.seg_info, args.function)
    if args.verbose:
        PTATM.info(f'Get {function} Segment list : {seginfo}')
    return seginfo

def service(args):
    if not hasattr(args, 'function'):
        args.function = "main"
    if not hasattr(args, 'binary_args'):
        args.binary_args = ""
    if not hasattr(args, 'afl_extra_cmd'):
        args.afl_extra_cmd = ""
    if not hasattr(args, 'seg_info'):
        args.seg_info = None

    seginfo = initWorkspace(args)
    fuzz = FuzzTool.FuzzCtrl()
    # generate & run AFL cmd.
    suf_afl_cmd = fuzz.genSufAFLCmd(args.binary, args.readfile, args.binary_args)
    import time
    start_time = time.time()  # 记录开始时间
    for offset in seginfo:
        pre_afl_cmd = fuzz.genPreAFLCmd(args.in_path, args.out_path, offset)
        afl_cmd = fuzz.genAFLCmd(pre_afl_cmd, suf_afl_cmd, args.afl_extra_cmd)
        if args.verbose:
            PTATM.info(f'Execute AFL command ➜  {afl_cmd}')
        exit_code = fuzz.run_command(afl_cmd)
        if args.verbose:
            PTATM.info(f'AFL fuzzing return [{exit_code}]. Merge seeds...')
        FuzzEnv.CaseTool.mergeSeeds(args.in_path, args.out_path, offset)
        if args.verbose:
            PTATM.info(f'Fuzzing {args.function}+{offset} done.')
    elapsed_time = time.time() - start_time  # 计算总体耗时
    cases_file = FuzzEnv.CaseTool.saveCases(args.in_path, args.output)
    if args.verbose:
        PTATM.info(f'Generated test cases have been saved to {cases_file}. Total cost: {fuzz.fuzztime(elapsed_time)}')
        PTATM.info(f'All done.')