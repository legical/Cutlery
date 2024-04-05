from functools import reduce
import sys
sys.path.append("..")
import os
import json
import argparse
from collections import OrderedDict

import PWCETGenerator.CopulaTool as CopulaTool
import PWCETGenerator.EVTTool as EVTTool

PWCET_DISTRIBUTIONS = {
    'GEV': EVTTool.GEVGenerator,
    'Gumbel': EVTTool.GumbelGenerator,
    'GPD': EVTTool.GPDGenerator,
    'EP': EVTTool.ExponentialParetoGenerator
}

def json2data(json_file: str, extract_func: str = 'main'):
    # check json file is exist?
    if not os.path.exists(json_file):
        raise FileNotFoundError(f"{json_file} not found")

    with open(json_file, 'r') as file:
        data = json.load(file)

        extracted_data, idx = OrderedDict(), 0
        # process data
        if extract_func in data[CopulaTool.DataProcess.KEY_EXTRACT]:
            for seg_name, seg_cost in data[CopulaTool.DataProcess.KEY_EXTRACT][extract_func].items():
                idx += 1
                if idx > 4:
                    break
                if seg_name != CopulaTool.DataProcess.KEY_EXCLUDE:
                    time_values = seg_cost[CopulaTool.DataProcess.KEY_NORMCOST][CopulaTool.DataProcess.KEY_TIME]
                    extracted_data.setdefault(seg_name, list()).extend(time_values[:5000])
                    # print(f"Func[{extract_func}] extracted {seg_name} with {len(time_values)} values.")

        if len(extracted_data) == 0:
            raise ValueError(f"Function[{extract_func}] not found in seginfo json file.")

    return CopulaTool.DataProcess.makeValid(extracted_data)

def margin_distributions(raw_data: OrderedDict):
    # fit spd distribution
    models, costs, ECDF_value = list(), list(), 0
    p_min, p_max = 0.0001, 0.911
    for seg_name, seg_cost in raw_data.items():
        # fit each data
        distribution_gen = EVTTool.MixedDistributionGenerator('GPD', fix_c=0)
        spd_model = distribution_gen.fit(seg_cost)
        if spd_model.onlyECDF():
            ECDF_value += max(seg_cost)        
        models.append(spd_model)
        costs.append(seg_cost)
        print(f"Segment [{seg_name}] done.\n{spd_model.expression()}\n")
        # print(f"isf({p_min})={spd_model.isf(p_min)},  isf({p_max})={spd_model.isf(p_max)}\n")

    return models, costs, ECDF_value

def save2json(data, json_file: str):
    with open(json_file, 'w') as file:
        json.dump(data, file, indent=4)

def simulate_and_merge(raw_data: OrderedDict, copula_model: CopulaTool.CopulaModel, ECDF_value: int = 0):
    # simulate
    sim_values = copula_model.simulate(10000)
    # inverse CDF
    inverse_values = copula_model.inverse_transform(sim_values)
    # merge data
    task_merge_data = CopulaTool.DataProcess.merge_simulate_obsdata(raw_data, inverse_values)
    # sum as task excution time list
    task_costs = CopulaTool.DataProcess.combine(task_merge_data, ECDF_value)
    return task_costs

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Fuzz test')
    # parser.add_argument('target_path', help='Path to the target program')
    # parser.add_argument('-f', '--function', help='funtion name', required=False, default='main')
    parser.add_argument('-i', '--input', help='Path to input Fuzz test cases', required=True)
    parser.add_argument('-o', '--output', help='Path to save Fuzz test cases')
    parser.add_argument('-f', '--function', metavar='', default='main',
                       help='target functions to generate, default is main')  
    parser.add_argument('-p', '--prob', metavar='', type=float, action='extend', default=argparse.SUPPRESS, nargs='+',
                       help='exceedance probability, default is [1e-1, ..., 1e-9]')
    args = parser.parse_args()


    if not hasattr(args, 'prob'):
        args.prob = [10**-x for x in range(1, 10)]

    data = json2data(args.input)
    models, costs, _ = margin_distributions(data)
    cop_gen = CopulaTool.CopulaGenerator(models, costs)
    cop_model = cop_gen.fit(selected_structure='DVineStructure')
    print(cop_model.expression())

    task_costs = None
    for i in range(3):
        task_costs = simulate_and_merge(data, cop_model)
        if EVTTool.EVT.passed_kpss(task_costs) and EVTTool.EVT.passed_bds(task_costs):
            # 平稳性检验通过
            print(f'Passed KPSS and BDS test.')
            break

    # 若三次拟合都不成功，则使用最后一次拟合结果
    evt_types = ['GPD', 'GEV']
    for evt_type in evt_types:
        evt_distribution = PWCET_DISTRIBUTIONS[evt_type](fix_c=0)
        pwcet_model = evt_distribution.fit(task_costs)
        if pwcet_model is not None:
            print(f'Fit [{args.function}] pWCET with evt-type [{evt_type}].')
            break

    if pwcet_model is not None:
        print(f'Generate pWCET result.')
        headline = reduce(lambda x, y: str(x)+','+str(y), ['function'] + args.prob)
        print('\n' + headline)
        # gen pWCET
        pwcet = [round(pwcet_model.isf(p), 4) for p in args.prob]
        body = f"{args.function},{','.join(map(str, pwcet))}"
        print('\n' + body)