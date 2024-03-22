import random
from collections import OrderedDict
from statsmodels.distributions.empirical_distribution import ECDF
import numpy as np

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

import argparse
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import genpareto, gaussian_kde

# 生成符合广义帕累托分布的数据
def generate_pareto_data(size, c, loc, scale):
    return genpareto.rvs(c, loc=loc, scale=scale, size=size)

def main(output_path):
    # 参数设置
    size = 1000
    c = 0.5
    loc = 0
    scale = 1

    # 生成符合广义帕累托分布的数据
    pareto_data = generate_pareto_data(size, c, loc, scale)

    # 将数据分成两部分：尾部和中心
    tail_threshold = np.percentile(pareto_data, 80)
    tail_data = pareto_data[pareto_data >= tail_threshold]
    center_data = pareto_data[pareto_data < tail_threshold]

    # 对尾部数据使用广义帕累托分布拟合
    params = genpareto.fit(tail_data)
    x_range_tail = np.linspace(min(tail_data), max(tail_data), 1000)
    y_genpareto = genpareto.pdf(x_range_tail, *params)

    # 对中心数据使用核密度函数拟合
    kde = gaussian_kde(center_data)
    x_range_center = np.linspace(min(center_data), max(center_data), 1000)
    y_kde = kde(x_range_center)

    # 绘制原始数据散点图
    plt.scatter(pareto_data, np.zeros_like(pareto_data), alpha=0.5, label='Original Data (Scatter)')

    # 绘制尾部拟合曲线和中心拟合曲线
    plt.plot(x_range_tail, y_genpareto, color='green', linestyle='--', label='Tail Fit (Genpareto)')
    plt.plot(x_range_center, y_kde, color='red', label='Center Fit (Gaussian KDE)')
    plt.legend()

    # 保存图像
    plt.savefig(output_path)
    print(f"Image saved to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate and save scatter plot with probability density function fits')
    parser.add_argument('-o', '--output', type=str, default='output.png', help='Output file path')
    args = parser.parse_args()
    main(args.output)
