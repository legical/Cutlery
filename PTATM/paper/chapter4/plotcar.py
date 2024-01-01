import matplotlib.pyplot as plt
import json

# 读取数据
data = json.loads(open('CAR-example.json', 'r').read())
ins = data[0]["phase-plan"]["INSTRUCTIONS"][:-1]
ref = data[0]["phase-plan"]["LLC_REFERENCES"][:-1]
cycle = list(range(len(ins)))
car = [float(ref[idx])/float(ins[idx])*1000 for idx in cycle]

# 绘制曲线图
plt.plot(cycle, car)
plt.xlabel('cycle(x1e8)')
plt.ylabel('CAR(x1e-3)')

# 保存图形到文件并裁剪空白
plt.savefig('CAR-example.png', bbox_inches='tight')
