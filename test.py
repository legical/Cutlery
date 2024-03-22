import random
from collections import OrderedDict
from statsmodels.distributions.empirical_distribution import ECDF
import argparse
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import genpareto, gaussian_kde
import PTATM.PWCETGenerator.EVTTool as EVTTool

def generate_random_list(length):
    """生成随机列表"""
    return list([random.randint(1, 100) for _ in range(length)])

def generate_ordered_dict(num_entries, max_list_length):
    """生成包含随机列表的OrderedDict对象"""
    ordered_dict = OrderedDict()
    for i in range(num_entries):
        key = f'Key_{i}'
        value = generate_random_list(max_list_length)
        ordered_dict[key] = value
    return ordered_dict

def genGPDdata(size: int = 200) -> list:
    # 设置 GPD 分布的参数
    shape = 0.5  # Shape 参数
    loc = 0      # Location 参数
    scale = 1    # Scale 参数

    # 生成 GPD 分布的随机数据
    data = genpareto.rvs(shape, loc=loc, scale=scale, size=size)
    return list(data)

def test():
    # 生成数据
    data = genGPDdata()
    # 计算 ECDF
    ecdf_gen, gpd_gen = EVTTool.ECDFGenerator(), EVTTool.GPDGenerator()
    ecdf, gpd = ecdf_gen.fit(data), gpd_gen.fit(data)
    choose_data = data[2]
    print(f'Choose data: {choose_data}')
    print(f'ECDF: isf[{ecdf.cdf(choose_data)}]={ecdf.isf(ecdf.cdf(choose_data))}\t isf(ccdf)[{1-ecdf.cdf(choose_data)}]={ecdf.isf(1-ecdf.cdf(choose_data))}')
    print(f'GPD: isf[{gpd.cdf(choose_data)}]={gpd.isf(gpd.cdf(choose_data))}\t isf(ccdf)[{1-gpd.cdf(choose_data)}]={gpd.isf(1-gpd.cdf(choose_data))}')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate and save scatter plot with probability density function fits')
    parser.add_argument('-o', '--output', type=str, default='output.png', help='Output file path')
    args = parser.parse_args()
    test()
