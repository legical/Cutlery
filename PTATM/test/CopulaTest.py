import argparse
import sys
import pyvinecopulib as pv
from matplotlib import pyplot as plt
import numpy as np
sys.path.append("..")
from PWCETGenerator import CopulaTool

import random

# 生成5个随机变量
num_variables = 5
variable_values = []

# 每个变量包含200个随机值
num_values_per_variable = 200

for _ in range(num_variables):
    values = [random.random() for _ in range(num_values_per_variable)]
    variable_values.append(np.array(values))
# variable_values = pv.to_pseudo_obs(np.array(variable_values))
cop_gen = CopulaTool.CopulaGenerator(None, variable_values)
dcop = cop_gen.fit()
print(dcop.expression())
# print(dcop.copula)
print(dcop.copula.order)

sim_values = dcop.simulate(200)
print(sim_values.shape)