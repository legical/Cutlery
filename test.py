import random
from collections import OrderedDict

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

# 生成包含随机列表的OrderedDict对象
num_entries = 5
max_list_length = 10
random_ordered_dict = generate_ordered_dict(num_entries, max_list_length)

# 打印结果
for key, value in random_ordered_dict.items():
    print(f"{key}: {value}")

valuess = list()
for key, value in random_ordered_dict.items():
    valuess.append(value)
    
valuess = np.array(valuess)
print(type(valuess), len(valuess))
print(type(valuess[0]))