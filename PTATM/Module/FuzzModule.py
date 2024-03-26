import Module.PTATM as PTATM

def initWorkspace(in_path, out_path, seg_path: str, binary: str, verbose: bool, function="main"):
    from Fuzz import FuzzEnv
    # Check input and output directories for legality.
    if verbose:
        PTATM.info('Check Fuzzing env for legality.')
    fuzz_env = FuzzEnv.FuzzEnv(in_path, out_path, seg_path, binary)
    fuzz_env.initWorkspace()
    # Get Segment list.
    fuzz_env.getSeginfo(function)
    if verbose:
        PTATM.info(f'Get {function} Segment list : {fuzz_env.seginfo}')
    return fuzz_env

def service(args):
    from Fuzz import FuzzTool
    if not hasattr(args, 'function'):
        args.function = "main"
    if not hasattr(args, 'binary_args'):
        args.binary_args = ""
    if not hasattr(args, 'afl_extra_cmd'):
        args.afl_extra_cmd = ""
    fuzz_env = initWorkspace(args.input, args.output, args.seg_info,
                                        args.binary, args.verbose, args.function)
    fuzz_tool = FuzzTool.FuzzTool(fuzz_env.afl_root)
    # generate & run AFL cmd.
    suf_afl_cmd = fuzz_tool.genSufAFLCmd(args.binary, args.readfile, args.binary_args)
    import time
    start_time = time.time()  # 记录开始时间
    for offset in fuzz_env.seginfo:
        pre_afl_cmd = fuzz_tool.genPreAFLCmd(fuzz_env.in_path, fuzz_env.out_path, offset)
        afl_cmd = fuzz_tool.genAFLCmd(pre_afl_cmd, suf_afl_cmd, args.afl_extra_cmd)
        if args.verbose:
            PTATM.info(f'Execute AFL command ➜  {afl_cmd}')
        exit_code = fuzz_tool.run_command(afl_cmd)
        if args.verbose:
            PTATM.info(f'AFL fuzzing return [{exit_code}]. Merge seeds...')
        fuzz_env.mergeSeeds(offset)        
        if args.verbose:
            PTATM.info(f'Fuzzing {args.function}+{offset} done.')
    elapsed_time = time.time() - start_time  # 计算总体耗时
    cases_file = fuzz_env.savecases()
    if args.verbose:
        PTATM.info(f'Generated test cases have been saved to {cases_file}. Total cost: {fuzz_tool.fuzztime(elapsed_time)}')
        PTATM.info(f'All done.')