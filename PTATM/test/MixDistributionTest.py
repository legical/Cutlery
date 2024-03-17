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

class MixedDistributionFitter:
    def __init__(self, data):
        self.data = data
        self.threshold = self.find_threshold()
        self.empirical_fit = self.fit_empirical()
        self.generalized_pareto_fit = self.fit_generalized_pareto()

    def find_threshold(self):
        # 使用kpss和bds检验
        if kpss(self.data)[1] < 0.05 or bds(self.data)[1] < 0.05:
            # 如果检验不通过，直接返回数据的最大值作为阈值
            return self.data.max()
        else:
            # 使用PoT筛选极值样本
            # 在这里实现PoT筛选的逻辑，此处省略
            return 0  # 仅作示例，实际应替换为根据筛选结果得到的阈值

    def fit_empirical(self):
        # 使用经验分布函数拟合小于阈值的部分
        return np.histogram(self.data[self.data <= self.threshold], bins=100, density=True)

    def fit_generalized_pareto(self):
        # 使用Generalized Pareto Distribution拟合大于阈值的部分
        data_gt_threshold = self.data[self.data > self.threshold]
        if len(data_gt_threshold) == 0:
            return None  # 如果没有大于阈值的数据，返回None
        else:
            # 拟合Generalized Pareto Distribution
            params = genpareto.fit(data_gt_threshold)
            # 使用cvm和ks进行拟合优度检验
            cvm_stat, _ = kstest(data_gt_threshold, 'genpareto', args=params)
            ks_stat = kstwobign.sf(np.sqrt(len(data_gt_threshold))*cvm_stat)
            if cvm_stat < 0.05 or ks_stat < 0.05:
                # 如果检验不通过，返回None，表示使用经验分布函数拟合全部数据
                return None
            else:
                return params

    def cdf(self, x):
        # 计算累积分布函数
        cdf_empirical = np.interp(x, self.empirical_fit[1][:-1], np.cumsum(self.empirical_fit[0]))
        if self.generalized_pareto_fit:
            cdf_gt_threshold = genpareto.cdf(x, *self.generalized_pareto_fit)
            return np.where(x <= self.threshold, cdf_empirical, 1 - cdf_gt_threshold)
        else:
            return cdf_empirical

# 示例用法
data = pd.DataFrame({'x': np.random.rand(10000)})['x']  # 假设随机变量为DataFrame中的一列
mixed_dist = MixedDistributionFitter(data)
x_values = np.linspace(0, 1, 1000)
cdf_values_mixed = mixed_dist.cdf(x_values)
cdf_values_empirical = np.interp(x_values, mixed_dist.empirical_fit[1][:-1], np.cumsum(mixed_dist.empirical_fit[0]))

plt.plot(x_values, cdf_values_mixed, label='Mixed Distribution CDF')
plt.plot(x_values, cdf_values_empirical, label='Empirical Distribution CDF')
plt.hist(data, bins=100, density=True, alpha=0.5, label='Original Data Histogram')
plt.xlabel('x')
plt.ylabel('Probability')
plt.title('CDF Comparison')
plt.legend()
plt.show()



parser = argparse.ArgumentParser(description='pwcet analysis service.')
parser.add_argument('-o', '--output', type=str, help='output file path')
args = parser.parse_args()

# 示例用法
# data = [
#     360002745,
#     369995835,
#     3700051405,
#     360002745,
#     3599934205,
#     3700051405,
#     35000033,
#     360002745,
#     360002745,
#     35000033,
#     369995835,
#     369995835,
#     340007245,
#     3599934205,
#     350000335
# ]
from scipy.stats import genpareto

# 设置参数
shape = 0.5  # 形状参数
scale = 1.0  # 尺度参数
threshold = 0.0  # 阈值参数

# 生成500个满足Generalized Pareto Distribution的值
data = genpareto.rvs(c=shape, scale=scale, loc=threshold, size=500)
random_data = np.random.uniform(min(data)*0.5, min(data)*1.1, 1000)
# 将数据保存到NumPy数组中
data = np.append(data, random_data)

cdfgen = EVTTool.MixedDistributionGenerator()
Mixedcdf = cdfgen.fit(data, 0.7)
# print(cdf.expression())


x_values = np.linspace(min(data), max(data), 1000)
cdf_values = [1-Mixedcdf.evt.cdf(x) if x > cdfgen.threshold else 1-Mixedcdf.ecdf.cdf(x) for x in x_values]

# 绘制原始数据的直方图
plt.hist(data, bins=100, density=True, alpha=0.5, label='Empirical Data')

# 绘制拟合的累积分布函数
plt.plot(x_values, cdf_values, label='Fitted CDF')

plt.xlabel('x')
plt.ylabel('Density/CDF')
plt.title('Fitted CDF vs Empirical Data')
plt.legend()
plt.savefig(args.output)
plt.show()
