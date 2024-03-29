from matplotlib import pyplot as plt
import numpy as np
import argparse
import sys
sys.path.append("..")

def read_evt_data():
    # 从CSV文件加载数据，跳过标题行，指定数据类型为float
    data = np.genfromtxt('EVTdata.csv', delimiter=',', skip_header=1, dtype=float)

    # 对数据按列进行排序
    sorted_data = np.sort(data, axis=0)

    # 分别保存到NumPy数组中
    CYCLES1 = sorted_data[:, 0]
    CYCLES2 = sorted_data[:, 1]
    print(len(CYCLES1), CYCLES1[:10])

    return CYCLES1, CYCLES2

def plot_data(data, output):
    # 绘制ECDF散点图 和 斜率图
    # ECDF散点图：x为源数据，y为1-CDF
    from PWCETGenerator import DataFilter, EVTTool
    ecdf = DataFilter.CoordinatePoints(x=data)

    slopes, x_data = ecdf.slopes()
    slope = DataFilter.CoordinatePoints(x_data, slopes)
    slope.normalize()

    kcluster  = DataFilter.KMeansCluster(data, 3)
    centers, clusters = kcluster.cluster(0.1, 50)
    clusterx, clustery = list(), list()
    for center, cluster in zip(centers, clusters):
        clusterx.append(cluster[0][0])
        clusterx.append(center[0])
        clustery.append(cluster[0][1])
        clustery.append(center[1])

    spd_gen = EVTTool.MixedDistributionGenerator('GPD')
    spd_model = spd_gen.fit(data)
    print(f"混合分布拟合结果：\n{spd_model.expression()}\n")
    spd_ccdf = [1 - spd_model.cdf(i) for i in data]

    gev_gen = EVTTool.GEVGenerator()
    gev_model = gev_gen.fit(data, 200)
    print(f"GEV分布拟合结果：\n{gev_model.expression()}\n")
    sev_ccdf = [1 - gev_model.cdf(i) for i in data]

    plt.figure(figsize=(18, 9))
    plt.scatter(ecdf.getx(),ecdf.gety(),label='ecdf',marker='o',color=(0.,0.5,0.))
    # plt.scatter(slope.getx(),slope.gety(),label='slope',marker='.',color=(0.,0.,0.5))

    plt.plot(data,spd_ccdf,label='Mix-SPD',color=(0.5,0.,0.))
    plt.plot(data,sev_ccdf,label='GEV',color=(0.5,0.5,0.))
    plt.plot(clusterx, clustery, 'b*--', alpha=0.5, linewidth=1, label='acc')
    plt.legend(loc="best")
    plt.savefig(output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate and save scatter plot with probability density function fits')
    parser.add_argument('-o', '--output', type=str, default='output.png', help='Output file path')
    args = parser.parse_args()

    _, data = read_evt_data()
    plot_data(data, args.output)