import matplotlib.pyplot as plt
import json

# 读取数据
x = []
y = []
with open('simresult.json') as f:
    data = json.loads(f.read())
    refs = [int(ref) for ref in data[0]['target']["LLC_REFERENCES"]]
    incs = [int(inc) for inc in data[0]['target']["INSTRUCTIONS"]]
    x = list(range(len(incs)))
    y = [incs[i]//refs[i]for i in x]

# 绘制曲线图
plt.plot(x, y, color='black')
plt.xlabel('Cycle Interval(1e9)')
plt.ylabel('1/CAR')

# 保存图形到文件并裁剪空白
plt.savefig('simresult.png', bbox_inches='tight')
