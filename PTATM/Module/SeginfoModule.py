import os
import Module.PTATM as PTATM

 # MACRO for service.
MODE = {'time': None, 'callinfo': None}

def service(args):
    from SegmentInfoCollector import TraceTool
    # Check whether output is exist.
    if os.path.exists(args.output):
        raise Exception('Output[%s] is already exist.' % args.output)
    # Check whether there is something to do with trace.
    nr_trace = len(args.input_trace) + len(args.json_trace)
    if nr_trace == 0:
        PTATM.warn('Nothing to dump.')
        return
    elif nr_trace == 1 and len(args.json_trace) == 1 and not hasattr(args, 'strip_mode'):
        PTATM.warn('Nothing to dump for single json trace without strip mode selected.')
        return
    # Build trace object(seginfo).
    traceobj = TraceTool.Trace()
    # Fill raw trace.
    rawfiller = TraceTool.RawTraceStringFiller(traceobj, args.direct)
    jsonfiller = TraceTool.JsonTraceFiller(traceobj)
    for rtrace in args.input_trace:
        if args.verbose:
            PTATM.info('Build raw trace[%s].' % rtrace)
        if rawfiller.fill(open(rtrace, 'r').read()) == False:
            raise Exception("Build raw trace[%s] failed with err_msg[%s]." % (rtrace, rawfiller.err_msg))
    # Fill json trace.
    for jtrace in args.json_trace:
        if args.verbose:
            PTATM.info('Build json trace[%s].' % jtrace)
        if jsonfiller.fill(open(jtrace, 'r').read()) == False:
            raise Exception("Build json trace[%s] failed with err_msg[%s]." % (jtrace, jsonfiller.err_msg))
    # Strip trace object(seginfo).
    if hasattr(args, 'strip_mode'):
        for mode in args.strip_mode:
            stripper = None
            if mode == 'time':
                stripper = TraceTool.CostTimeStripper(traceobj)
            elif mode == 'callinfo':
                stripper = TraceTool.CallinfoStripper(traceobj)
            if args.verbose:
                PTATM.info('Strip seginfo with mode[%s].' % mode)
            if stripper is not None and stripper.strip() == False:
                raise Exception("Strip trace failed at mode[%s] with err_msg[%s]." % (mode, stripper.err_msg))
    # Output trace object(seginfo).
    if args.verbose:
        PTATM.info('Output seginfo into %s.' % args.output)
    with open(args.output, 'w') as outfile:
        outfile.write(TraceTool.JsonTraceSerializer(4).serialize(traceobj))
    if args.verbose:
        PTATM.info('Done.')