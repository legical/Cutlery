import os
import traceback
import argparse
from Module import PTATM, SegmentModule, CutModule, FuzzModule, ControlModule, CollectModule, SeginfoModule, PWCETModule, CopulaModule

helper = """
Usage: python3 analysis.py command [options] ...
Provide pwcet analysis service.

[command]
    segment     parse binary file into segment.
        positional argument     required    path to binary file.
        -f, --function=         repeated    interested functions, default is main only.
        -s, --max-seg=          optional    max segment num, default is 2.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save segment result.

        [output]
            Append probes separate by ',' into output.

    cut      get all cut function.
        positional argument     required    path to binary file.
        -f, --function=         repeated    interested functions, default is main only.
        -s, --max-seg=          optional    max segment num, default is 4.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save cut-node function list result.

        [output]
            Append cut-function separate by ',' into output.

    fuzz     automated test case generation via fuzzing.
        positional argument     required    path to binary file.
        -s, --seg-info=         required    path to store segment info.
        -i, --input=            required    path to store AFL fuzzing starting seeds.
        -r, --readfile=         optional    whether to use file as AFL fuzzing input seeds.
        -o, --output=           required    path to save fuzzing-generated test cases.
        -f, --function=         repeated    interested functions, default is main only.
        -a, --afl-extra-cmd=    optional    extra cmd for AFL, default is empty.
        -b, --binary-args=      optional    arguments for binary, default is empty.
        -v, --verbose           optional    generate detail.

        [output]
            Test cases.

    control     generate shared resource controller of taskset.
        positional argument     required    path to file includes parallel tasks.
        -w, --llc-wcar=         optional    use llc wcar to generate resource controller.
        -F, --force             optional    force to measure wcar for each task.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save control task.

        [input]
            [positional argument]
                File is in json format.
                [
                    {
                        "core": core set used by task,
                        "dir": working directory,
                        "cmd": command,
                        "llc-wcar": llc-wcar
                    },
                    other task...
                ]
            [llc-wcar]
                An integer hints a cache access occurs every ${llc-wcar} instructions.

        [output]
            Executable file of control task.

        [note]
            We will save wcar result into the file provided by positional argument.

    collect     collect trace for task.
        positional argument     required    path to config of the target to collect and its contenders.
        -c, --clock=            optional    clock the tracer used, default is global, see man perf record.
        -r, --repeat=           optional    generate multiple trace information by repeating each input, default is 20.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save trace.

        [input]
            [positional argument]
                File is in json format.
                {
                    "target": {
                        "core": core set used by target,
                        "task": [
                            {
                                "dir": working directory,
                                "binary": path to binary file,
                                "probes": [uprobe1, uprobe2, ...],
                                "inputs": [arguments1, arguments2, ...]
                            },
                            other task to collect...
                        ]
                    },
                    "contender": {
                        "core": core set used by contender,
                        "task": [
                            {
                                "dir": working directory, 
                                "cmd": command1
                            },
                            other contender...
                        ]
                    }
                }

        [output]
            Append trace information into trace file, the trace format is:
            [${binary} ${args}]
            time1,uprobe1
            ...

    seginfo     dump trace/seginfo, and generate a new seginfo.
        positional argument     ignored
        -r, --raw-trace=        repeated    path to raw trace file.
        -j, --json-trace=       repeated    path to json trace file(segment info).
        -m, --strip-mode=       repeated    choose time or callinfo or both to strip.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save seginfo.

        [limit]
            num of trace-file sum num of seginfo must be grater than 0.
            if only one seginfo is provoided, the strip-mode must be selected.

        [input]
            [trace-file]
                File format see command collect.
            [seginfo]
                A file in json format, see SegmentInforCollector/TraceTool.py for detail.
            [strip-mode]
                You can choose time, callinfo.
                Strip time will clear all time information for seginfo file.
                Strip callinfo will make an unique callinfo list for seginfo file.

        [output]
            Segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

    pwcet       generate pwcet result, build arguments of extreme distribution for segment and expression for function.
        positional argument     reuqired    path to segment information(or json trace).
        -f, --function=         repeated    target functions to generate, default is main only.
        -t, --evt-type=         optional    choose type of EVT family(GEV or GPD), default is GPD.
        -F, --force             optional    force to rebuild arguments of extreme distribution and expressions, even if they are already exist.
        -p, --prob=             repeated    exceedance probability, default is [1e-1, ..., 1e-9].
        -m, --mode=             optional    output mode, choose txt or png, default is txt.
        -v, --verbose           optional    generate detail.
        -o, --output=           required    path to save pwcet result.

        [input]
            [positional argument]
                File of segment information in json format, see SegmentInforCollector/TraceTool.py for detail.

        [output]
            When mode is txt, then we append pwcet estimate for each function into output, the format is:
            function,prob1,prob2,...
            func1,pWCET11,pWCET12,...
            func2,pWCET21,pWCET22,...
            pwcet estimate for other function...
            When mode is png, then we output a png file with pwcet curve for each function.
        
        [note]
            We will save arguments of extreme distribution and expressions into the file provided 
            by positional argument, see PWCETGenerator/PWCETSolver.py for detail.
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='pwcet analysis service.')

    # Set subcommand parser.
    subparsers = parser.add_subparsers(title='command', dest="subcommand")

    # Add subcommand segment.
    segment = subparsers.add_parser('segment', help='parse binary file into segment')
    segment.add_argument('binary',
                         help='path to binary file')
    segment.add_argument('-f', '--function', metavar='', action='extend', default=argparse.SUPPRESS, nargs='+',
                         help='function name, default is main only')
    segment.add_argument('-s', '--max-seg', metavar='', type=int, default=2,
                         help='max segment num, default is 2')
    segment.add_argument('-v', '--verbose', action='store_true',
                         help='generate detail')
    segment.add_argument('-o', '--output', metavar='', required=True,
                         help='path to save segment result')
    segment.set_defaults(func=SegmentModule.service)

    # Add subcommand cut.
    cut = subparsers.add_parser('cut', help='generate cut function list')
    cut.add_argument('binary',
                         help='path to binary file')
    cut.add_argument('-s', '--max-seg', metavar='', type=int, default=10,
                         help='max segment num of main fuction, default is 10')
    cut.add_argument('-v', '--verbose', action='store_true',
                         help='generate detail')
    cut.add_argument('-o', '--output', metavar='', required=True,
                         help='path to save cut-node function list result')
    cut.set_defaults(func=CutModule.service)

    # Add subcommand fuzz.
    fuzz = subparsers.add_parser('fuzz', help='automated test case generation via fuzzing')
    fuzz.add_argument('binary',
                      help='path to binary file')
    fuzz.add_argument('-s', '--seg-info', metavar='', required=True,
                      help='path to store segment info')
    fuzz.add_argument('-i', '--input', metavar='', required=True,
                      help='path to store AFL fuzzing starting seeds')
    fuzz.add_argument('-r', '--readfile', action='store_true',
                      help='whether to use file as AFL fuzzing input seeds')
    fuzz.add_argument('-o', '--output', metavar='', required=True,
                      help='path to save fuzzing-generated test cases')
    fuzz.add_argument('-f', '--function', metavar='', action='extend', default=argparse.SUPPRESS, nargs='+',
                      help='function name, default is main only')
    fuzz.add_argument('-a', '--afl-extra-cmd', metavar='', default='',
                      help='extra cmd for AFL, default is empty')
    fuzz.add_argument('-b', '--binary-args', metavar='', default='',
                      help='arguments for binary, default is empty')
    fuzz.add_argument('-v', '--verbose', action='store_true',
                      help='generate detail')
    fuzz.set_defaults(func=FuzzModule.service)

    # Add subcommand control.
    control = subparsers.add_parser('control', help='generate shared resource controller of taskset')
    control.add_argument('taskconf',
                         help="path to file who includes parallel tasks")
    control.add_argument('-w', '--llc-wcar', metavar='', type=int, default=argparse.SUPPRESS,
                         help='use llc wcar to generate resource controller')
    control.add_argument('-F', '--force', action='store_true',
                         help='force to measure wcar for each task')
    control.add_argument('-v', '--verbose', action='store_true',
                         help='generate detail')
    control.add_argument('-o', '--output', metavar='', required=True,
                         help='path to save control task')
    control.set_defaults(func=ControlModule.service)

    # Add subcommand collect.
    collect = subparsers.add_parser('collect', help='collect trace for task')
    collect.add_argument('taskconf',
                         help="path to config of the target to collect and its contenders")
    collect.add_argument('-c', '--clock', metavar='', default='global',
                         help='clock the tracer used, default is global, see man perf record')
    collect.add_argument('-r', '--repeat', metavar='', type=int, default=20,
                         help='generate multiple trace information by repeating each input, default is 20')
    collect.add_argument('-v', '--verbose', action='store_true',
                         help='generate detail')
    collect.add_argument('-o', '--output', metavar='', required=True,
                         help='path to save trace')
    collect.set_defaults(func=CollectModule.service)
    
    # Add subcommand seginfo.
    seginfo = subparsers.add_parser('seginfo', help='dump trace/seginfo, and generate a new seginfo')
    seginfo.add_argument('-i', '--input-trace', metavar='', action='extend', default=list(), nargs='+',
                         help='path to raw trace file')
    seginfo.add_argument('-j', '--json-trace', metavar='', action='extend', default=list(), nargs='+',
                         help='path to json trace file(segment info)')
    seginfo.add_argument('-m', '--strip-mode', action='extend', choices=list(SeginfoModule.MODE.keys()),
                         default=argparse.SUPPRESS, nargs='+',
                         help='choose time or callinfo or both to strip')
    seginfo.add_argument('-d', '--direct', action='store_true',
                         help='use cut-func direct seginfo')
    seginfo.add_argument('-v', '--verbose', action='store_true',
                         help='generate detail')
    seginfo.add_argument('-o', '--output', metavar='', required=True,
                         help='path to save seginfo')
    seginfo.set_defaults(func=SeginfoModule.service)

    # Add subcommand pwcet.
    pwcet = subparsers.add_parser(
        'pwcet', help='generate pwcet result, build arguments of extreme distribution for segment and expression for function')
    pwcet.add_argument('seginfo',
                       help='path to segment information(or json trace)')
    pwcet.add_argument('-f', '--function', metavar='', action='extend', default=argparse.SUPPRESS, nargs='+',
                       help='target functions to generate, default is main only')
    pwcet.add_argument('-t', '--evt-type', choices=list(PWCETModule.EVT.keys()), default='GPD',
                       help='choose type of EVT family(GEV or GPD), default is GPD')
    pwcet.add_argument('-F', '--force', action='store_true',
                       help='force to rebuild arguments of extreme distribution and expressions, even if they are already exist')
    pwcet.add_argument('-p', '--prob', metavar='', type=float, action='extend', default=argparse.SUPPRESS, nargs='+',
                       help='exceedance probability, default is [1e-1, ..., 1e-9]')
    pwcet.add_argument('-m', '--mode', choices=list(PWCETModule.MODE.keys()), default='txt',
                       help='output mode, choose txt or png, default is txt')
    pwcet.add_argument('-v', '--verbose', action='store_true',
                       help='generate detail')
    pwcet.add_argument('-o', '--output', metavar='', required=True,
                       help='path to save pwcet result')
    pwcet.set_defaults(func=PWCETModule.service)

    # Add subcommand copula.
    copula = subparsers.add_parser(
        'copula', help='generate pwcet result with vine-copula model')
    copula.add_argument('-i', '--input',
                       help='path to segment information(or json trace)')
    copula.add_argument('-f', '--function', metavar='', default='main',
                       help='target functions to generate, default is main')
    copula.add_argument('-s', '--segment-number', metavar='',type=int, default=-1,
                       help='Select how many Segments to fit, less than 0 selects all of the Segments of the function, default is -1')
    copula.add_argument('-n', '--simulate-number', metavar='',type=int, default=50000,
                       help='Number of Monte Carlo simulations, default is 5w')
    copula.add_argument('-F', '--firstn', metavar='',type=int, default=5000,
                       help='Take the first n numbers, default is 5k')
    copula.add_argument('-t', '--evt-type', choices=list(CopulaModule.PWCET_DISTRIBUTIONS.keys()), default='GPD',
                       help='choose type of EVT family(GEV or GPD), default is GPD')    
    copula.add_argument('-p', '--prob', metavar='', type=float, action='extend', default=argparse.SUPPRESS, nargs='+',
                       help='exceedance probability, default is [1e-1, ..., 1e-9]')
    copula.add_argument('-v', '--verbose', action='store_true',
                       help='generate detail')
    copula.add_argument('-a', '--all', action='store_true',
                       help='Whether to fit the full marginal distribution, false: only SPDs are fit')
    copula.add_argument('-o', '--output', metavar='', required=True,
                       help='path to save copula pwcet result')
    copula.set_defaults(func=CopulaModule.service)

    geninput = subparsers.add_parser('geninput', help='generate input for each module')    
    # Add subparsers for genjson sub command under collect command.
    collect_input = geninput.add_subparsers(title='generate input for collect module', dest="subcommand")
    collect_input = collect_input.add_parser('collect', help='generate json file for collecting trace')
    collect_input.add_argument('binary',
                      help='path to binary file')
    collect_input.add_argument('-p', '--probe', metavar='', required=True,
                      help='path to store binary segment probe info')
    collect_input.add_argument('-i', '--input', metavar='', required=True,
                      help='path to store binary input args')
    collect_input.add_argument('-v', '--verbose', action='store_true',
                         help='generate detail')
    collect_input.add_argument('-o', '--output', metavar='', required=True,
                         help='path to save collect json file, must end with .json')
    collect_input.set_defaults(func=CollectModule.genjson)

    try:
        # Check env.
        if os.getenv('PTATM') is None:
            os.environ['PTATM'] = PTATM.root
            print('Not found env PTATM, auto set as [%s]' % os.getenv('PTATM'))
            # raise Exception("Set PTATM env with shrc at first.")
        # Parse arguments.
        args = parser.parse_args()
        # Process subcommands.
        if not hasattr(args, 'func'):
            parser.print_help()
        else:
            args.func(args)
    except Exception as error:
        print(traceback.print_exc())
