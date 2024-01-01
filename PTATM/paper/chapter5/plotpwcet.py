import matplotlib.pyplot as plt

# 读取数据
x = [325.3715, 325.9111, 326.3596, 326.7642, 327.1419, 327.5012, 327.8469, 328.1821, 328.5089]
y = [0.1, 0.01, 0.001, 0.0001, 1e-05, 1e-06, 1e-07, 1e-08, 1e-09]

# 绘制曲线图
plt.plot(x, y, color='black')
plt.xscale('linear')
plt.yscale('log')
plt.xlim(325, 329)
plt.ylim(1e-9, 0.1)
plt.xlabel('pwcet(s)')
plt.ylabel('exceedance probability')

# 保存图形到文件并裁剪空白
plt.savefig('pwcet.png', bbox_inches='tight')
