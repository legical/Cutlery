import matplotlib.pyplot as plt
import json, random

# 读取数据
data = json.loads(open('bigsample-et.txt', 'r').read())
y = [int(x) for x in data]
random.shuffle(y)
x = list(range(len(y)))

# 绘制曲线图
plt.scatter(x, y, color='g', label='Samples')
# 1e-9
plt.plot([x[0], x[-1]], [328.5089, 328.5089], color='r', label='pwcet under 1e-9')
# 设置y刻度
ylim = plt.ylim()
plt.ylim(ylim[0], 400)

plt.xlabel('Number of Execution')
plt.ylabel('Execution Time(s)')
plt.legend(loc='upper right')

# # 保存图形到文件并裁剪空白
plt.savefig('metric.png', bbox_inches='tight')
