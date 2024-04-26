import Module.PTATM as PTATM
from Fuzz import FuzzEnv, FuzzTool

def initWorkspace(args):
    # Check input and output directories for legality.
    if args.verbose:
        PTATM.info('Check Fuzzing env for legality.')
    try:
        FuzzEnv.CheckEnv.checkWorkspace(args.input, args.output, args.binary)
    except Exception as e:
        PTATM.error(f'AFL env init failed: {e}')
        exit(1)
    # Get Segment list.
    seginfo = FuzzEnv.Seginfo.getSegInfo(args.seg_info, args.binary)
    if args.verbose:
        PTATM.info(f'Get segment list: {seginfo}.')
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
    for idx, offset in enumerate(seginfo, 1):
        pre_afl_cmd = fuzz.genPreAFLCmd(args.input, args.output, offset)
        afl_cmd = fuzz.genAFLCmd(pre_afl_cmd, suf_afl_cmd, args.afl_extra_cmd)
        if args.verbose:
            PTATM.info(f'Fuzz segment {offset} [{idx}/{len(seginfo)}]')
            PTATM.info(f'Execute AFL command ➜  {afl_cmd}')
        exit_code = fuzz.run_command(afl_cmd)
        if args.verbose:
            PTATM.info(f'AFL fuzzing return [{exit_code}]. Merge seeds...')
        FuzzEnv.CaseTool.mergeSeeds(args.input, args.output, offset)        
        cases_file = FuzzEnv.CaseTool.onlySaveSeeds(args.output)
        if args.verbose:
            PTATM.info(f'Fuzzing {offset} done. Save test cases to {cases_file}.')
    elapsed_time = time.time() - start_time  # 计算总体耗时
    if args.verbose:
        PTATM.info(f'All done.  Total cost: {fuzz.fuzztime(elapsed_time)}')