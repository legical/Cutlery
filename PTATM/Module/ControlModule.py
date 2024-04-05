import Module.PTATM as PTATM
import json
import os
import random
import math
import multiprocessing

root = PTATM.root
# MACRO for gencarsim.
NOP = 'nop;'
SIMSRC = root + r'/L3Contention/CARSimulator.c'
SIMCMD = 'gcc -DNOPSTR=\'"%s"\' -O1 -o %s %s'
# MACRO for genwcar.
RANDOMIZER = root + r'/L3Contention/RandomizeBuddy'
PROFILER = root + r'/L3Contention/profiler'
TMPFILE = r'/tmp/PTATM-wcar.json'
TARGETID = r'target'
MODE = 'SAMPLE_ALL'
INS = 'INSTRUCTIONS'
LLC_ACC = 'LLC_REFERENCES'
CYCLE = 'CYCLES'
PERIOD = 1000000000
PERFCMD = '%s --output=%s --log=/dev/null --json-plan=\'%s\' --cpu=%%d'
REPEAT = 1
# MACRO for service.
CORE = 'core'
DIR = 'dir'
CMD = 'cmd'
LLC_WCAR = 'llc-wcar'

def gencarsim(car, output):
    if car <= 5:
        PTATM.warn('CAR[%d] is too small to simulate, adjust it to worst.' % car)
    nopstr = NOP * (0 if car <= 5 else 4*car - 21)
    cmd = SIMCMD % (nopstr, output, SIMSRC)
    return PTATM.execWithResult(cmd)

def genwcar(command, cpuset: list):
    target_plan = json.dumps({
        'id': TARGETID,
        'type': MODE,
        'task': command,
        'rt': True,
        'pincpu': True,
        'leader': CYCLE,
        'period': PERIOD,
        'member': [INS, LLC_ACC]
    })
    tmpfile = TMPFILE
    pcmd = PERFCMD % (PROFILER, tmpfile, target_plan)
    # Start collecting.
    if os.path.exists(tmpfile) and not exec('rm ' + tmpfile):
        raise Exception('Cannot remove temp file[%s].' % tmpfile)
    for _ in range(REPEAT):
        cpu = cpuset[random.randint(0, len(cpuset)-1)]
        exec(RANDOMIZER)
        if not exec(pcmd % cpu):
            raise Exception('Failed to exec [%s] on core[%d]' % (pcmd, cpu))
    # Gen worst car.
    wcar = None
    for data in json.loads(open(tmpfile, 'r').read()):
        target = data[TARGETID]
        inslist, acclist = target[INS], target[LLC_ACC]
        for i in range(min(len(inslist), len(acclist))):
            ins, acc = int(inslist[i]), int(acclist[i])
            if ins != 0 and acc != 0:
                car = math.ceil(ins / acc)
                wcar = car if wcar is None else min(wcar, car)
    return wcar

def checkconf(conf: dict):
    for task in conf:
        for core in task[CORE]:
            if not isinstance(core, int) or core >= multiprocessing.cpu_count() or core < 0:
                raise Exception("Invalid core[%d]." % core)
        if not isinstance(task[DIR], str):
            raise Exception("Invalid dir[%s]." % task[DIR])
        if not isinstance(task[CMD], str):
            raise Exception("Invalid cmd[%s]." % task[DIR])
        if not isinstance(task.get(LLC_WCAR, -1), int):
            raise Exception("Invalid llc-wcar[%s]." % task[LLC_WCAR])

def service(args):
    llc_wcar = None
    if not PTATM.issudo():
        raise Exception('You should run as a sudoer.')
    if os.path.exists(args.output):
        raise Exception('Output[%s] is already exist.' % args.output)
    if hasattr(args, 'llc_wcar'):
        llc_wcar = args.llc_wcar
    else:
        taskjson = json.loads(open(args.taskconf, 'r').read())
        checkconf(taskjson)
        try:
            for task in taskjson:
                # Collect wcar for each task.
                if args.force or int(task.get(LLC_WCAR, -1)) < 0:
                    # Get necessary fields from config.
                    core = task[CORE]
                    wdir = task[DIR]
                    cmd = task[CMD]
                    # Collect wcar for current task.
                    pwd = os.getcwd()
                    os.chdir(wdir)
                    task_wcar = genwcar(cmd, core)
                    os.chdir(pwd)
                    # Save wcar into json opbject.
                    task[LLC_WCAR] = task_wcar
                    if args.verbose:
                        PTATM.info('Collect task[%s] done with wcar[%d].' % (cmd, task_wcar))
                task_wcar = task[LLC_WCAR]
                llc_wcar = task_wcar if llc_wcar is None else min(llc_wcar, task_wcar)
            # Save llc_wcar result into args.taskconf
            if args.verbose:
                PTATM.info('Save wcar result into taskconf[%s].' % (args.taskconf))
        except Exception as error:
            raise error
        finally:
            open(args.taskconf, 'w').write(json.dumps(taskjson, indent=4))
    # Generate car simulator with llc_wcar.
    if llc_wcar is not None:
        if args.verbose:
            PTATM.info('Generate control task at output[%s].' % args.output)
        result = gencarsim(llc_wcar, args.output)
        if 0 != result.returncode:
            raise Exception(result.stderr.decode('utf-8'))
    else:
        raise Exception('Invalid llc_wcar[None].')
    if args.verbose:
        PTATM.info('Done.')