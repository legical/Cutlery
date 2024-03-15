from functools import reduce
import os
import Module.PTATM as PTATM

# MACRO for service.
EVT = {'GEV': None, 'GPD': None}
MODE = {'txt': None, 'png': None}

def service(args):
    from SegmentInfoCollector import TraceTool
    from PWCETGenerator import EVTTool, PWCETSolver
    # Set default value for function & prob.
    if not hasattr(args, 'function'):
        args.function = ['main']
    if not hasattr(args, 'prob'):
        args.prob = [10**-x for x in range(1, 10)]
    # Check default value for evt_type & mode.
    if args.evt_type not in EVT:
        raise Exception('Unrecognized evt-type[%s].' % args.evt_type)
    if args.mode not in MODE:
        raise Exception('Unrecognized mode[%s].' % args.mode)
    # Check whether output is exist.
    if args.mode != 'txt' and os.path.exists(args.output):
        raise Exception('Output[%s] is already exist.' % args.output)
    # Create trace object.
    if args.verbose:
        PTATM.info('Build trace object(seginfo) for %s.' % args.seginfo)
    traceobj = TraceTool.Trace()
    TraceTool.JsonTraceFiller(traceobj).fill(open(args.seginfo, 'r').read())
    # Initialize solver with evt_type.
    if args.verbose:
        PTATM.info('Generate solver with evt-type[%s].' % args.evt_type)
    if args.evt_type == 'GEV':
        solver = PWCETSolver.GumbelSegmentListSolver()
    elif args.evt_type == 'GPD':
        solver = PWCETSolver.ExponentialParetoSegmentListSolver()
    # Solve trace object.
    if args.verbose:
        PTATM.info('Solve with force=%s.' % str(args.force))
    if not solver.solve(traceobj, args.force):
        raise Exception('Failed to solve seginfo[%s].\n[%s]' % (args.seginfo, solver.err_msg))
    # Save solve result.
    if args.verbose:
        PTATM.info('Save solve result into %s.' % args.seginfo)
    with open(args.seginfo, 'w') as seginfo:
        seginfo.write(TraceTool.JsonTraceSerializer(4).serialize(traceobj))
    # Get distribution for each function.
    distribution = dict()
    for fname in args.function:
        if args.verbose:
            PTATM.info('Generate distribution for function[%s].' % fname)
        lextd = solver.lextd4Function(fname)
        if lextd == None:
            raise Exception('Failed to generate distribution for function[%s], try to use -F.' % fname)
        distribution[fname] = lextd
    # Generate result.
    if args.verbose:
        PTATM.info('Generate result into %s with mode[%s].' % (args.output, args.mode))
    if args.mode == 'txt':
        with open(args.output, 'a') as output:
            # Write head line.
            headline = reduce(lambda x, y: str(x)+','+str(y), ['function'] + args.prob)
            output.write('\n' + headline)
            # Write pwcet estimate for each function.
            for fname in args.function:
                pwcet = [round(distribution[fname].isf(p), 4) for p in args.prob]
                body = reduce(lambda x, y: str(x)+','+str(y), [fname] + pwcet)
                output.write('\n' + body)
    elif args.mode == 'png':
        PTATM.warn('Cannot generate png at present, nothing to output.')
    if args.verbose:
        PTATM.info('Done.')