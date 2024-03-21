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
num_entries = 3
max_list_length = 4
random_ordered_dict = generate_ordered_dict(num_entries, max_list_length)

# 打印结果
for key, value in random_ordered_dict.items():
    print(f"{key}: {value}\t len(key):{len(random_ordered_dict[key])} len(value):{len(value)}")

def combine_values_by_index(ordered_dict):
    """将相同下标的值相加并保存到一个列表中"""
    max_length = min(len(value) for value in ordered_dict.values())
    combined_list = []
    for idx in range(max_length):
        task_cost = sum(ordered_dict[key][idx] for key in ordered_dict if idx < len(ordered_dict[key]))
        combined_list.append(task_cost)
    return combined_list

# 将相同下标的值相加并保存到一个列表中
combined_list = combine_values_by_index(random_ordered_dict)

# 打印结果
print(combined_list)