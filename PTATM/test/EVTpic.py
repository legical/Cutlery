from matplotlib import pyplot as plt
import numpy as np
import argparse
import sys
import scipy.stats as stats
sys.path.append("..")

def BM(dataSet, blkSize:int=50):
    mVector, dataSize = [], len(dataSet)
    for i in range(blkSize):
        s = i * int(dataSize // blkSize)
        mVector.append(max(dataSet[s: s + int(dataSize // blkSize)]))
    return mVector

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

def plot_data2(data, output):
    # 绘制ECDF散点图 和 斜率图
    # ECDF散点图：x为源数据，y为1-CDF
    from PWCETGenerator import DataFilter, EVTTool
    ecdf_gen = EVTTool.ECDFGenerator()
    ecdf_model = ecdf_gen.fit(data)
    ecdf_prob = np.linspace(0, 1, 1000)
    ecdf_pwcet = [ecdf_model.isf(p) for p in ecdf_prob]

    kcluster  = DataFilter.KMeansCluster(data, 3)
    centers, clusters = kcluster.cluster(0.1, 50)
    clusterx, clustery = list(), list()
    for center, cluster in zip(centers, clusters):
        clusterx.append(cluster[0][0])
        clusterx.append(center[0])
        clustery.append(cluster[0][1])
        clustery.append(center[1])

    spd_gen = EVTTool.MixedDistributionGenerator('GPD', fix_c=0)
    spd_model = spd_gen.fit(data)
    print(f"混合分布拟合结果：\n{spd_model.expression()}\n")
    spd_ccdf = [1 - spd_model.cdf(i) for i in data]

    gev_gen = EVTTool.GEVGenerator(fix_c=0)
    gev_model = gev_gen.fit(data, 200)
    print(f"GEV分布拟合结果：\n{gev_model.expression()}\n")
    sev_ccdf = [1 - gev_model.cdf(i) for i in data]

    mVector = BM(data)
    # 使用 Gumbel 分布进行拟合
    evt_params = stats.gumbel_r.fit(mVector)
    EVTTool.EVT.show_cvm(mVector, stats.gumbel_r, evt_params)
    print(f"Gumbel拟合参数：{evt_params}")

    plt.figure(figsize=(18, 9))
    plt.scatter(ecdf_pwcet,ecdf_prob,label='ecdf',marker='o',color=(0.,0.5,0.))
    # plt.scatter(slope.getx(),slope.gety(),label='slope',marker='.',color=(0.,0.,0.5))

    plt.plot(data,spd_ccdf,label='Mix-SPD',color=(0.5,0.,0.))
    plt.plot(data,sev_ccdf,label='GEV',color=(0.5,0.5,0.))
    plt.plot(clusterx, clustery, 'b*--', alpha=0.5, linewidth=1, label='acc')
    plt.legend(loc="best")
    plt.savefig(output)

def plot_data(data, output):
    # 绘制ECDF散点图 和 斜率图
    # ECDF散点图：x为源数据，y为1-CDF
    from PWCETGenerator import DataFilter, EVTTool
    ecdf_gen = EVTTool.ECDFGenerator()
    ecdf_model = ecdf_gen.fit(data)
    ecdf_prob = np.logspace(np.log10(0.1), np.log10(1e-9), num=500)
    ecdf_pwcet = [ecdf_model.isf(p) for p in ecdf_prob]
    sorted_indices = sorted(range(len(ecdf_pwcet)), key=lambda k: ecdf_pwcet[k])
    x_sorted = [ecdf_pwcet[i] for i in sorted_indices]
    y_sorted = [ecdf_prob[i] for i in sorted_indices]

    plt.figure(figsize=(18, 9))
    plt.plot(x_sorted, y_sorted)

    # plt.legend(loc="best")
    plt.savefig(output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate and save scatter plot with probability density function fits')
    parser.add_argument('-o', '--output', type=str, default='output.png', help='Output file path')
    args = parser.parse_args()

    _, data = read_evt_data()
    plot_data(data, args.output)