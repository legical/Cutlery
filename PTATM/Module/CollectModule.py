import json
import multiprocessing
import os
import random
import signal
import Module.PTATM as PTATM
import Module.ControlModule as ControlModule

root = PTATM.root
# MACRO for service.
RANDOMIZER = root + '/L3Contention/RandomizeBuddy'
TARGET = 'target'
CONTENDER = 'contender'
CORE = 'core'
TASK = 'task'
DIR = 'dir'
BINARY = 'binary'
PROBES = 'probes'
INPUTS = 'inputs'
CMD = 'cmd'
RUN_CONTENDER = False


def gentrace(binary: str, command: str, uprobes: list, clock: str):
    from SegmentInfoCollector.Collector import TraceCollector
    # Del all uprobes.
    TraceCollector.delprobe(TraceCollector.PROBE_ALL)
    try:
        # Add uprobes.
        for uprobe in uprobes:
            if not TraceCollector.addprobe(binary, TraceCollector.PROBE_PREFIX + uprobe):
                raise Exception('Failed to add uprobe[%s] for binary[%s].' %
                                (TraceCollector.PROBE_PREFIX + uprobe, binary))
            
        # TraceCollector.showprobe(binary)
        # Start collect.
        ok, info = TraceCollector.collectTrace(command, clock)
        if not ok:
            raise Exception('Failed to collect info for command[%s] with clock[%s].\n%s' % (command, clock, info))
    except Exception as error:
        raise error
    finally:
        # Clean all uprobes.
        TraceCollector.delprobe(TraceCollector.PROBE_ALL)
    return info


def compete(contender: dict, core: int):
    os.setpgid(0, 0)

    def handler(x, y):
        os.killpg(os.getpgid(0), signal.SIGKILL)
    signal.signal(signal.SIGTERM, handler)
    contenders, nr_contender = contender[TASK], len(contender[TASK])
    def gencmd(task): return 'cd %s && taskset -c %d %s' % (task[DIR], core, task[CMD])
    while True:
        contender_id = random.randint(0, nr_contender-1)
        exec(gencmd(contenders[contender_id]))


def checkconf(conf: dict):
    target = conf[TARGET]
    # Check target.
    for core in target[CORE]:
        if not isinstance(core, int) or core >= multiprocessing.cpu_count() or core < 0:
            raise Exception('Invalid core[%d].' % core)
    for task in target[TASK]:
        # Check dir.
        if not isinstance(task[DIR], str):
            raise Exception('Invalid dir[%s].' % task[DIR])
        # Check binary.
        if not isinstance(task[BINARY], str):
            raise Exception('Invalid binary[%s].' % task[BINARY])
        # Check probes.
        for uprobe in task[PROBES]:
            if not isinstance(uprobe, str):
                raise Exception('Invalid uprobe[%s].' % uprobe)
        # Check inputs:
        for in_vec in task[INPUTS]:
            if not isinstance(in_vec, str):
                raise Exception('Invalid input[%s].' % in_vec)
    # Check contender.
    contender = conf[CONTENDER]
    if contender is not None and len(contender) > 0:
        RUN_CONTENDER = True
        for core in contender[CORE]:
            if not isinstance(core, int) or core >= multiprocessing.cpu_count() or core < 0:
                raise Exception('Invalid core[%d].' % core)
        for task in contender[TASK]:
            # Check dir.
            if not isinstance(task[DIR], str):
                raise Exception('Invalid dir[%s].' % task[DIR])
            # Check cmd.
            if not isinstance(task[CMD], str):
                raise Exception('Invalid cmd[%s].' % task[CMD])


def randomInput(repeat: int, inputs: list) -> list:
    randoms = list()
    while len(randoms) < repeat:
        random_list = list(range(len(inputs)))
        random.shuffle(random_list)
        randoms.extend(random_list)
    return randoms


def service(args):
    if not PTATM.issudo():
        raise Exception('You should run as a sudoer.')
    if not hasattr(args, 'output'):
        raise Exception('You should specify an output file path.')
    taskjson = json.loads(open(args.taskconf, 'r').read())
    checkconf(taskjson)
    target, contender = taskjson[TARGET], taskjson[CONTENDER]
    if RUN_CONTENDER:
        # Start contender at each core.
        contender_procset = set()
        for core in contender[CORE]:
            if args.verbose:
                PTATM.info('Start contender at core %d.' % core)
            contender_procset.add(multiprocessing.Process(target=compete, args=(contender, core)))
        for proc in contender_procset:
            proc.start()
    try:
        # Collect tarce for each target.
        target_coreset = target[CORE]
        outfile = open(args.output, 'a')
        pwd = os.getcwd()
        for task in target[TASK]:
            taskdir = task[DIR]
            binary = os.path.abspath(task[BINARY])
            uprobes = task[PROBES]
            inputs = task[INPUTS]
            cmdpat = 'taskset -c %%d %s %%s' % binary
            # Change working directory for collect.
            os.chdir(taskdir)
            # random input
            random_idx = randomInput(args.repeat, inputs)
            for i, r_idx in enumerate(random_idx, 1):
                # 清理空字节和其他非法字符
                in_vec = inputs[r_idx].replace("\x00", "")
                core = target_coreset[random.randint(0, len(target_coreset)-1)]
                command = cmdpat % (core, in_vec)
                if args.verbose:
                    PTATM.info(f'[{i}/{len(random_idx)}]\tCollect for command [{command}].')
                # Randomize buddy.
                PTATM.exec(ControlModule.RANDOMIZER)
                traceinfo = gentrace(binary, command, uprobes, args.clock)
                outfile.write('\n[%s] [%s]\n' % (command, args.clock) + traceinfo)
                outfile.flush()
    except Exception as error:
        raise error
    finally:
        os.chdir(pwd)
        # Terminate all alive contender.
        if RUN_CONTENDER:
            for proc in contender_procset:
                if proc.is_alive():
                    proc.terminate()
        # Close output.
        outfile.close()
    if args.verbose:
        PTATM.info('Done.')


def genjson(args):
    # check probefile is exist
    if not os.path.exists(args.probe):
        raise FileNotFoundError(f"File '{args.probe}' not found.")
    # check inputfile is exist
    if not os.path.exists(args.input):
        raise FileNotFoundError(f"File '{args.input}' not found.")
    
    from SegmentInfoCollector.InputTool import InputJson
    if args.verbose:
        PTATM.info('Generate collect input json file.')
    inputjson = InputJson(args.binary, args.probe, args.input)
    collect_json = inputjson.genJson(args.output)
    if args.verbose:
        PTATM.info(f'Save json file to : [{collect_json}].')
        PTATM.info('Done.')