import matplotlib.pyplot as plt
import json

# 读取数据

def getet(file: str):
    data = json.loads(open(file, 'r').read())
    return data['dump']['main']['fullcost']['time']

et = getet('seginfo.json')
etcomp = getet('seginfo-comp.json')

x = list(range(min(len(et), len(etcomp))))
exp = [et[i] for i in x]
comp = [etcomp[i] for i in x]

# 绘制曲线图
plt.scatter(x, exp, color='r', label='Experimental Group')
plt.scatter(x, comp, color='g', label='Control Group')
plt.xlabel('Number of Execution')
plt.ylabel('Execution Time(s)')
plt.legend(loc='upper right')
plt.ylim(top=200)

# 保存图形到文件并裁剪空白
plt.savefig('etresult.png', bbox_inches='tight')
