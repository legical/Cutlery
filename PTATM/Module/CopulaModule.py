from collections import OrderedDict
import csv
from functools import reduce
import os
import Module.PTATM as PTATM
from PWCETGenerator import CopulaTool, EVTTool


PWCET_DISTRIBUTIONS = {
    'GEV': EVTTool.GEVGenerator,
    'Gumbel': EVTTool.GumbelGenerator,
    'GPD': EVTTool.GPDGenerator,
    'EP': EVTTool.ExponentialParetoGenerator
}

def merge2file(args, raw_data: OrderedDict, total_cost:list):
    # 获取OrderedDict的key
    keys = list(raw_data.keys())

    # 获取output文件所在路径的文件夹
    folder_path = os.path.dirname(args.output)

    # 新建data.csv文件
    csv_file_path = os.path.join(folder_path, 'data.csv')

    try:
        with open(csv_file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # 写入标题行
            header = list(keys) + ['total']
            writer.writerow(header)

            # 写入数据行
            for i in range(len(total_cost)):
                row = [raw_data[key][i] for key in keys]
                row.append(total_cost[i])
                writer.writerow(row)
    except Exception as e:
        PTATM.error(f'merge simulate data to file failed : {e}')


def margin_distributions(args, raw_data: OrderedDict):
    if args.verbose:
        PTATM.info(f'Fit {len(raw_data.keys())} segment: {raw_data.keys()}\n')
    # fit spd distribution
    models, costs, ECDF_value = list(), list(), 0
    for seg_name, seg_cost in raw_data.items():
        # fit each data
        distribution_gen = EVTTool.MixedDistributionGenerator(args.evt_type, fix_c=0)
        spd_model = distribution_gen.fit(seg_cost)
        if spd_model.onlyECDF():
            ECDF_value += max(seg_cost)
        models.append(spd_model)
        costs.append(seg_cost)
        # if args.verbose:
        #     PTATM.info(f'Fit segment [{seg_name}] done.\n{spd_model.expression()}\n')

    return models, costs, ECDF_value


def simulate_and_merge(args, raw_data: OrderedDict, copula_model: CopulaTool.CopulaModel, ECDF_value: int = 0):
    # simulate
    if args.verbose:
        PTATM.info(f'Try to simulate {args.simulate_number} observations.')
    sim_values = copula_model.simulate(args.simulate_number)
    # inverse CDF
    inverse_values = copula_model.inverse_transform(sim_values)
    # merge data
    task_merge_data = CopulaTool.DataProcess.merge_simulate_obsdata(raw_data, inverse_values)
    # sum as task excution time list
    task_costs = CopulaTool.DataProcess.combine(task_merge_data, ECDF_value)
    merge2file(args, task_merge_data, task_costs)
    return task_costs

# TODO: 类信封方法. 难点：其他分布类型怎么simulate？
# 1. 使用 Copula/分布 为每个函数、函数之间的main任务段生成pWCET
# 2. 给定超越概率p，获得各个函数和函数之间的main任务段的pWCET
# 3. 相加，作为任务的pWCET


def service(args):
    if not hasattr(args, 'function') or args.function is None:
        args.function = 'main'
    if not hasattr(args, 'prob'):
        args.prob = [10**-x for x in range(1, 10)]
    if args.evt_type not in PWCET_DISTRIBUTIONS.keys():
        raise Exception(f'Unrecognized evt-type[{args.evt_type}].')
    if os.path.exists(args.output):
        PTATM.warn(f'Output[{args.output}] is already exist. pWCET results will be appended to it.')

    # Build copula object.
    if args.verbose:
        PTATM.info(f'Parsing data from {args.input} with function[{args.function}].')
    raw_data = CopulaTool.DataProcess.json2data(args.input, args.function, args.segment_number, args.firstn)

    # fit spd distribution
    if args.verbose:
        PTATM.info(f'Fitting distributions for function [{args.function}].')
    models, costs, ECDF_value = margin_distributions(args, raw_data)

    # fit copula
    if args.verbose:
        PTATM.info(f'Fitting copula model for function [{args.function}].')
    cop_gen = CopulaTool.CopulaGenerator(models, costs)
    if args.verbose:
        PTATM.info('Transfer all data to pseudo-observations succeed.')
    cop_model = cop_gen.fit(selected_structure='DVineStructure')
    if args.verbose:
        PTATM.info(cop_model.expression())

    task_costs = None
    # 尝试3次pWCET拟合
    for i in range(3):
        task_costs = simulate_and_merge(args, raw_data, cop_model)
        if EVTTool.EVT.passed_kpss(task_costs) and EVTTool.EVT.passed_bds(task_costs):
            # 平稳性检验通过
            break
        # else:
        #     PTATM.warn(f'pWCET fitting failed for {i+1} times.')

    # 若三次拟合都不成功，则使用最后一次拟合结果
    evt_types = ['GPD', 'GEV']
    for evt_type in evt_types:
        evt_distribution = PWCET_DISTRIBUTIONS[evt_type](fix_c=0)
        pwcet_model = evt_distribution.fit(task_costs)
        if pwcet_model is not None:
            if args.verbose:
                PTATM.info(f'Fit [{args.function}] pWCET with evt-type [{evt_type}].')
            break

    if pwcet_model is not None:
        if args.verbose:
            PTATM.info(f'Generate [{args.function}] result into [{args.output}].')
        with open(args.output, 'a') as output:
            # Write head line.
            headline = reduce(lambda x, y: str(x)+','+str(y), ['function'] + args.prob)
            output.write('\n' + headline)
            # gen pWCET
            pwcet = [round(pwcet_model.isf(p), 8) for p in args.prob]
            body = f"{args.function},{','.join(map(str, pwcet))}"
            output.write('\n' + body)

    if args.verbose:
        PTATM.info('Done.')
