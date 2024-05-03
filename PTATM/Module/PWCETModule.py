from functools import reduce
import json
import os
import csv

from matplotlib import pyplot as plt
import numpy as np
import Module.PTATM as PTATM
from PWCETGenerator import EVTTool

# MACRO for service.
EVT = {'GEV': None, 'GPD': None}
MODE = {'txt': None, 'png': None}


def compTest(compin: str, prob: list, task_costs:list=None) -> list:
    if task_costs is None:
        task_costs = []  # 创建一个空列表，用于存储total列的数据
        with open(compin, 'r', newline='') as csvfile:  # 打开CSV文件
            reader = csv.DictReader(csvfile)  # 创建一个CSV字典阅读器对象
            for row in reader:  # 遍历CSV文件的每一行
                task_costs.append(float(row['total']))  # 将当前行的'total'列数据添加到列表中
    
    evt_distribution = EVTTool.GPDGenerator(fix_c=0)
    pwcet_model = evt_distribution.fit(task_costs, True)
    if pwcet_model is None:
        evt_distribution = EVTTool.GEVGenerator(fix_c=0, nr_sample=100)
        pwcet_model = evt_distribution.fit(task_costs)
    pwcet = [round(pwcet_model.isf(p), 10) for p in prob]
    return pwcet


def drawpWCET(args, convpwcet) -> str:
    y_prob, output_file = args.prob, args.output
    ecdf_time = []
    # ECDF fit
    try:
        with open(args.seginfo, 'r') as f:
            data = json.load(f)
            ecdf_time = data.get('dump', {}).get(
                'main', {}).get('fullcost', {}).get('time', [])
    except FileNotFoundError:
        print("文件不存在")
    except json.JSONDecodeError:
        print("JSON 解析错误")

    ecdf_gen = EVTTool.ECDFGenerator()
    ecdf_model = ecdf_gen.fit(ecdf_time)
    ecdf_pwcet = [ecdf_model.isf(p) for p in y_prob]
    ecdf_evt_pwcet = compTest(args.compin, y_prob, ecdf_time)

    copula_pwcet = compTest(args.compin, y_prob)
    # 绘制图形
    plt.figure(figsize=(18, 9))
    plt.title('pWCET')
    plt.xlabel('time')
    plt.ylabel('prob')

    plt.plot(ecdf_pwcet, y_prob, label='ECDF', linestyle='-', linewidth=2)  # 实线
    plt.plot(ecdf_evt_pwcet, y_prob, label='ECDF-EVT', linestyle='--', linewidth=2)  # 虚线
    plt.plot(copula_pwcet, y_prob, label='Copula', linestyle='-.', linewidth=2)  # 点划线
    plt.plot(convpwcet, y_prob, label='Convolution', linestyle=':', linewidth=2)  # 点线

    plt.legend(loc="best")
    # 保存图形
    plt.savefig(output_file)
    plt.close()
    return output_file


def service(args):
    from SegmentInfoCollector import TraceTool
    from PWCETGenerator import EVTTool, PWCETSolver
    # Set default value for function & prob.
    if not hasattr(args, 'function'):
        args.function = ['main']
    if not hasattr(args, 'prob'):
        # args.prob = [10**-x for x in range(1, 10)]
        args.prob = np.logspace(np.log10(0.1), np.log10(1e-9), num=500)
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
        raise Exception(f'Failed to solve seginfo[{args.seginfo}]:  [{solver.err_msg}]')
    # Save solve result.
    if args.verbose:
        PTATM.info('Save solve result into %s.' % args.seginfo)
    with open(args.seginfo, 'w') as seginfo:
        seginfo.write(TraceTool.JsonTraceSerializer(4).serialize(traceobj))
    # Get distribution for each function.
    distribution = dict()
    for fname in args.function:
        if args.verbose:
            PTATM.info(f'Generate distribution for function[{fname}].')
        lextd = solver.lextd4Function(fname)
        if lextd == None:
            raise Exception(
                f'Failed to generate distribution for function[{fname}], try to use -F.')
        distribution[fname] = lextd
    # Generate result.
    if args.verbose:
        PTATM.info(
            f'Generate result into {args.output} with mode[{args.mode}].')
    if args.mode == 'txt':
        with open(args.output, 'a') as output:
            # Write head line.
            headline = reduce(lambda x, y: str(x)+','+str(y),
                              ['function'] + args.prob)
            output.write('\n' + headline)
            # Write pwcet estimate for each function.
            for fname in args.function:
                pwcet = [round(distribution[fname].isf(p), 4)
                         for p in args.prob]
                body = reduce(lambda x, y: str(x)+','+str(y), [fname] + pwcet)
                output.write('\n' + body)
    elif args.mode == 'png':
        main_pwcet = [distribution['main'].isf(p) for p in args.prob]
        drawpWCET(args, main_pwcet)
        # PTATM.warn('Cannot generate png at present, nothing to output.')
    if args.verbose:
        PTATM.info('Done.')
