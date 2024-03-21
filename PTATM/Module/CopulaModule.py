import numpy as np
import Module.PTATM as PTATM
from PWCETGenerator import CopulaTool, EVTTool


def margin_distributions(args, raw_data):
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


def service(args):
    # Build copula object.
    if args.verbose:
        PTATM.info('Parsing data from {args.input}.')
    raw_data = CopulaTool.DataProcess.json2data(args.input, args.func_name)

    # fit spd distribution
    if args.verbose:
        PTATM.info('Fitting distributions...')
    models, costs = margin_distributions(args, raw_data)

    # fit copula
    if args.verbose:
        PTATM.info('Fitting copula...')
    cop_gen = CopulaTool.CopulaGenerator(models, costs)
    cop_model = cop_gen.fit(selected_structure='DVineStructure')
    if args.verbose:
        PTATM.info(cop_model.expression())

    # simulate
    if args.verbose:
        PTATM.info(f'Simulate {args.simulate} observations.')
    sim_values = cop_model.simulate(args.simulate)

    # inverse CDF


    # fit distribution of total task


    # give pWCET to args.output