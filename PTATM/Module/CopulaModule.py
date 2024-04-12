from collections import OrderedDict
import csv
from functools import reduce
import os
import matplotlib.pyplot as plt
import numpy as np
import Module.PTATM as PTATM
from PWCETGenerator import CopulaTool, EVTTool


PWCET_DISTRIBUTIONS = {
    'GEV': EVTTool.GEVGenerator,
    'Gumbel': EVTTool.GumbelGenerator,
    'GPD': EVTTool.GPDGenerator,
    'EP': EVTTool.ExponentialParetoGenerator
}


def drawpWCET(pwcet: list, raw_data: OrderedDict, args):
    y_prob, output_file = args.prob, PTATM.fileEndWith(args.output, '.png')
    # ECDF fit
    x_rawcosts = CopulaTool.DataProcess.combine(raw_data)
    ecdf_gen = EVTTool.ECDFGenerator()
    ecdf_model = ecdf_gen.fit(x_rawcosts)
    ecdf_pwcet = [ecdf_model.isf(p) for p in y_prob]    
    sorted_indices = sorted(range(len(ecdf_pwcet)), key=lambda k: ecdf_pwcet[k])
    x_sorted = [ecdf_pwcet[i] for i in sorted_indices]
    y_sorted = [y_prob[i] for i in sorted_indices]

    # 绘制图形
    plt.figure(figsize=(18, 9))
    plt.title('pWCET')
    plt.xlabel('time')
    plt.ylabel('prob')

    plt.plot(pwcet,y_prob,label='Copula',color=(0.5,0.,0.))
    plt.plot(x_sorted,y_sorted,label='ECDF',color=(0.5,0.5,0.))
    plt.legend(loc="best")
    # 保存图形
    plt.savefig(output_file)
    plt.close()


def margin_distributions(args, raw_data: OrderedDict):
    if args.verbose:
        PTATM.info(f'Fit {len(raw_data.keys())} segment: {raw_data.keys()}\n')
    # fit spd distribution
    models, costs, ECDF_value = list(), list(), 0
    for seg_name, seg_cost in raw_data.items():
        # fit each data
        distribution_gen = EVTTool.MixedDistributionGenerator(fix_c=0)
        spd_model = distribution_gen.fit(seg_cost)
        if spd_model.onlyECDF():
            ECDF_value += max(seg_cost)
        models.append(spd_model)
        costs.append(seg_cost)
        # if args.verbose:
        #     PTATM.info(f'Fit segment [{seg_name}] done.\n{spd_model.expression()}\n')

    return models, costs, ECDF_value


def simulate_and_merge(args, raw_data: OrderedDict, copula_model: CopulaTool.CopulaModel, ECDF_value: int = 0):
    SIM_MAX_TIMES = 3
    task_merge_data, task_costs = None, None
    for _ in range(SIM_MAX_TIMES):
        # simulate
        sim_values = copula_model.simulate(args.simulate_number)
        # inverse CDF
        inverse_values = copula_model.inverse_transform(sim_values)
        # merge data
        task_merge_data = CopulaTool.DataProcess.merge_simulate_obsdata(raw_data, inverse_values)
        # sum as task excution time list
        task_costs = CopulaTool.DataProcess.combine(task_merge_data, ECDF_value)
        if EVTTool.EVT.passed_kpss(task_costs) and EVTTool.EVT.passed_bds(task_costs):
            # 平稳性检验通过
            break

    try:
        # merge simulate data and total cost to csv file
        keys = list(task_merge_data.keys())
        # 新建data.csv文件
        csv_file_path = PTATM.fileEndWith(args.output, '.csv')
        with open(csv_file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # 写入标题行
            header = list(keys) + ['total']
            writer.writerow(header)
            # 写入数据行
            for i in range(len(task_costs)):
                row = [raw_data[key][i] for key in keys]
                row.append(task_costs[i])
                writer.writerow(row)
    except Exception as e:
        PTATM.error(f'Merge simulate data to [{csv_file_path}] failed : {e}')

    return task_costs


def service(args):
    """
    TODO: 类信封方法. 难点：其他分布类型怎么simulate？
    1. 使用 Copula/分布 为每个函数、函数之间的main任务段生成pWCET
    2. 给定超越概率p，获得各个函数和函数之间的main任务段的pWCET
    3. 相加，作为任务的pWCET
    """
    if not hasattr(args, 'function') or args.function is None:
        args.function = 'main'
    if not hasattr(args, 'prob'):
        # args.prob = [10**-x for x in range(1, 10)]
        args.prob = np.logspace(np.log10(0.1), np.log10(1e-9), num=500)
    if not hasattr(args, 'evt_type'):
        args.evt_type = ['GPD', 'GEV']
    # if args.evt_type not in PWCET_DISTRIBUTIONS.keys():
    #     raise Exception(f'Unrecognized evt-type[{args.evt_type}].')
    if os.path.exists(args.output):
        PTATM.warn(f'Output[{args.output}] is already exist. pWCET results will be appended to it.')

    # Get segment excution time info from json file.
    if args.verbose:
        PTATM.info(f'Parsing data from {args.input} with function[{args.function}].')
    raw_data = CopulaTool.DataProcess.json2data(args.input, args.function, args.segment_number, args.firstn)

    # Fit spd distribution for each segment.
    if args.verbose:
        PTATM.info(f'Fitting distributions for function [{args.function}].')
    models, costs, ECDF_value = margin_distributions(args, raw_data)

    # Fit D-Vine copula
    if args.verbose:
        PTATM.info(f'Fitting copula model for function [{args.function}].')
    cop_gen = CopulaTool.CopulaGenerator(models, costs)
    cop_model = cop_gen.fit(selected_structure='DVineStructure')
    if args.verbose:
        PTATM.info(cop_model.expression())

    if args.verbose:
        PTATM.info(f'Try to simulate {args.simulate_number} observations.')
    task_costs = simulate_and_merge(args, raw_data, cop_model)
    for evt_type in args.evt_type:
        evt_distribution = PWCET_DISTRIBUTIONS[evt_type](fix_c=0, nr_sample=100)
        pwcet_model = evt_distribution.fit(task_costs)
        if pwcet_model is not None:
            if args.verbose:
                PTATM.info(f'Fit [{args.function}] pWCET with evt-type [{evt_type}].')
                PTATM.info(pwcet_model.expression())
            # gen pWCET
            pwcet = [round(pwcet_model.isf(p), 10) for p in args.prob]
            drawpWCET(pwcet, raw_data, args)
            with open(args.output, 'a') as output:
                # Write head line.
                headline = f"function,{','.join(map(str, args.prob))}"
                body = f"{args.function},{','.join(map(str, pwcet))}"
                output.write('\n' + body + '\n' + headline)
            if args.verbose:
                PTATM.info(f'Generate [{args.function}] result into [{args.output}].')
                PTATM.info('Done.')
            break
