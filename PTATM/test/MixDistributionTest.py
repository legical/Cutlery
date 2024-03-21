import argparse
import sys

from matplotlib import pyplot as plt
import numpy as np
sys.path.append("..")
from PWCETGenerator import EVTTool

import numpy as np
import pandas as pd
from scipy.stats import genpareto, kstest, kstwobign
from statsmodels.tsa.stattools import kpss, bds
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser(description='pwcet analysis service.')
parser.add_argument('-o', '--output', type=str, help='output file path')
args = parser.parse_args()


# data = [
# 3600.02745,
# 3699.95835,
# 3700.051405,
# 3600.02745,
# 3599.934205,
# 3700.051405,
# 3500.0033,
# 3600.02745,
# 3600.02745,
# 3500.0033,
# 3699.95835,
# 3699.95835,
# 3400.07245,
# 3599.934205,
# 3500.00335
# ]


# # 设置参数
# shape = 0.5  # 形状参数
# scale = 1.0  # 尺度参数
# threshold = 0.0  # 阈值参数

# # 生成500个满足Generalized Pareto Distribution的值
# data = genpareto.rvs(c=shape, scale=scale, loc=threshold, size=500)
# random_data = np.random.uniform(min(data), min(data)*1.3, 100)
# # 将数据保存到NumPy数组中
# data = np.append(data, random_data)

# cdfgen = EVTTool.MixedDistributionGenerator(filter=0.7)
# Mixedcdf = cdfgen.fit(data)
# # print(cdf.expression())


# x_values = np.linspace(min(data), max(data), 1000)
# ccdf_values = [1-x for x in Mixedcdf.cdf(x_values)]

# # 绘制原始数据的直方图
# plt.hist(data, bins=100, density=True, alpha=0.5, label='Empirical Data')

# # 绘制拟合的累积分布函数
# plt.plot(x_values, ccdf_values, label='Fitted CDF')

# plt.xlabel('x')
# plt.ylabel('Density/CDF')
# plt.title('Fitted CDF vs Empirical Data')
# plt.legend()
# plt.savefig(args.output)

import json

# 读取JSON文件
with open(args.output, 'r') as file:
    data = json.load(file)

        
# 定义要提取的key和要排除的对象
key_to_extract = 'main'
object_to_exclude = 'fullcost'

# 获取指定key下的数据
if key_to_extract in data['dump']:
    extracted_data = []
    for obj_name, obj_data in data['dump'][key_to_extract].items():
        if obj_name != object_to_exclude:
            time_values = obj_data['normcost']['time']
            extracted_data.append((obj_name, time_values))
    print(type(extracted_data))
    # 打印提取的数据
    for obj_name, time_values in extracted_data:
        print(f"Object Name: {obj_name}, Time Values: {time_values}")
else:
    print(f"Key '{key_to_extract}' not found in the JSON data.")
