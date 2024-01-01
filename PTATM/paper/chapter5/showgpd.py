import json
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats
import csv

def POT(data, nr_ext: int):
        nr_sample = len(data)
        if nr_ext < 0 or nr_ext >= nr_sample:
            return data[:]
        data = data.copy()
        data.sort()
        return data[-nr_ext:]

# 读取JSON文件
with open('seginfo.json', 'r') as f:
    data = json.load(f)

# 从JSON文件中获取数据
times = np.array(data['dump']['toplev_main']['toplev_main__1']['normcost']['time'])
times = POT(times, 4)
# 使用广义帕累托分布拟合数据
params = stats.genpareto.fit(times, f0=0)

# 生成广义帕累托分布
genpareto_dist = stats.genpareto(*params)

# 生成数据的频数直方图
plt.hist(times, bins=30, density=True, alpha=0.6, color='g')

# 生成广义帕累托分布的概率密度函数
xmin, xmax = plt.xlim()
x = np.linspace(xmin, xmax, 100)
p = genpareto_dist.pdf(x)
plt.plot(x, p, 'k', linewidth=2)

title = "Fit results: c = %.2f, loc = %.6f, scale = %.6f" % params
plt.title(title)

plt.savefig("./gpd.png")

import pandas as pd

# 读取CSV文件
df = pd.read_csv('data.csv', header=None)

# 转置数据框，将行变为列
df_transposed = df.transpose()

# 将转置后的数据保存到新的CSV文件
df_transposed.to_csv('data_transposed.csv', index=False, header=None)
