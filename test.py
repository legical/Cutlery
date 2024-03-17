import numpy as np
import pandas as pd
from scipy.stats import genpareto
from statsmodels.distributions.empirical_distribution import ECDF
from scipy.stats import kstest

# 生成随机数据
np.random.seed(42)
data = np.random.randint(0, 10000, 10000)
df = pd.DataFrame(data, columns=['random_variable'])

ecdf = ECDF(df['random_variable'])
print(ecdf.x)


from typing import Union

def example_func(x: Union[int, float] = 4):
    # 在函数体中可以直接使用参数x
    print(type(x), x)

# 测试函数
example_func()  # 将会输出 4，因为没有传入参数，使用默认值
example_func(5)  # 将会输出 5，参数为整数
example_func(3.14)  # 将会输出 3.14，参数为浮点数
