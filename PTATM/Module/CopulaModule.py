from collections import OrderedDict
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


def margin_distributions(args, raw_data: OrderedDict):
    # fit spd distribution
    models, costs = list(), list()
    try:
        for seg_name, seg_cost in raw_data.items():
            # fit each data
            distribution_gen = EVTTool.MixedDistributionGenerator()
            spd_model = distribution_gen.fit(seg_cost)
            models.append(spd_model)
            costs.append(seg_cost)
            if args.verbose:
                PTATM.info(f'Fit segment[{seg_name}] with {spd_model.name()} succeed.')

    except Exception as e:
        PTATM.error(f'Build distribution failed with err_msg[{e}].')
        return models, costs
    return models, costs


def simulate_and_merge(args, raw_data: OrderedDict, copula_model: CopulaTool.CopulaModel):
    # simulate
    if args.verbose:
        PTATM.info(f'Try to simulate {args.simulate_times} observations.')
    sim_values = copula_model.simulate(args.simulate_times)
    # inverse CDF
    inverse_values = copula_model.inverse_transform(sim_values)
    # merge data
    task_merge_data = CopulaTool.DataProcess.merge_simulate_obsdata(raw_data, inverse_values)
    # sum as task excution time list
    task_costs = CopulaTool.DataProcess.combine(task_merge_data)
    return task_costs

# TODO: 类信封方法. 难点：其他分布类型怎么simulate？
# 1. 使用 Copula/分布 为每个函数、函数之间的main任务段生成pWCET
# 2. 给定超越概率p，获得各个函数和函数之间的main任务段的pWCET
# 3. 相加，作为任务的pWCET


def service(args):
    if not hasattr(args, 'function'):
        args.function = 'main'
    if not hasattr(args, 'prob'):
        args.prob = [10**-x for x in range(1, 10)]
    if args.evt_type not in PWCET_DISTRIBUTIONS.keys():
        raise Exception(f'Unrecognized evt-type[{args.evt_type}].')
    if os.path.exists(args.output):
        PTATM.warn(f'Output[{args.output}] is already exist. pWCET results will be appended to it.')

    # Build copula object.
    if args.verbose:
        PTATM.info('Parsing data from {args.input}.')
    raw_data = CopulaTool.DataProcess.json2data(args.input, args.function)

    # fit spd distribution
    if args.verbose:
        PTATM.info(f'Fitting distributions for function[{args.function}].')
    models, costs = margin_distributions(args, raw_data)

    # fit copula
    if args.verbose:
        PTATM.info(f'Fitting copula model for function[{args.function}].')
    cop_gen = CopulaTool.CopulaGenerator(models, costs)
    cop_model = cop_gen.fit(selected_structure='DVineStructure')
    if args.verbose:
        PTATM.info(cop_model.expression())

    # 尝试3次pWCET拟合
    for i in range(3):
        task_costs = simulate_and_merge(args, raw_data, cop_model)
        evt_distribution = PWCET_DISTRIBUTIONS[args.evt_type]()
        if evt_distribution.passed_kpss(task_costs) and evt_distribution.passed_bds(task_costs):
            # fit pWCET
            if args.verbose:
                PTATM.info(f'Fit [{args.function}] pWCET with evt-type[{args.evt_type}].')
            pwcet_model = evt_distribution.fit(task_costs)
            if pwcet_model is not None:
                if args.verbose:
                    PTATM.info(f'Generate [{args.function}] result into [{args.output}].')
                with open(args.output, 'a') as output:
                    # Write head line.
                    headline = reduce(lambda x, y: str(x)+','+str(y), ['function'] + args.prob)
                    output.write('\n' + headline)
                    pwcet = [round(pwcet_model.isf(p), 4) for p in args.prob]
                    body = reduce(lambda x, y: str(x)+','+str(y), args.function + pwcet)
                    output.write('\n' + body)
                break
        else:
            PTATM.warning(f'pWCET fitting failed for {i+1} times.')
