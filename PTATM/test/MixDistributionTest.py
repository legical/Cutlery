import argparse
import sys
from matplotlib import pyplot as plt
import numpy as np
sys.path.append("..")
from PWCETGenerator import EVTTool

def read_evt_data(datafile: str):
    # 从CSV文件加载数据，跳过标题行，指定数据类型为float
    data = np.genfromtxt(datafile, delimiter=',', skip_header=1, dtype=float)

    # 对数据按列进行排序
    sorted_data = np.sort(data, axis=0)

    # 分别保存到NumPy数组中
    CYCLES1 = sorted_data[:, 0]
    CYCLES2 = sorted_data[:, 1]
    # print(len(CYCLES1), CYCLES1[:10])

    return CYCLES1, CYCLES2


def plot_data(raw_data, output: str):
    # 绘制ECDF散点图 和 斜率图
    # ECDF散点图：x为源数据，y为1-CDF
    from PWCETGenerator import DataFilter
    # data = np.sort(raw_data)
    data = raw_data
    ecdf = DataFilter.CoordinatePoints(x=data)
    plt.figure(figsize=(36, 18))
    plt.scatter(ecdf.getx(), ecdf.gety(), label='ECDF_raw', marker='.', color=(0., 0.5, 0.))

    # 绘制拟合的SPD模型    TODO: test mix GEV
    genSPD = EVTTool.MixedDistributionGenerator('GEV', nr_sample=200)
    SPDmodel = genSPD.fit(data)
    print(f"混合分布拟合结果：\n{SPDmodel.expression()}\n")
    data = np.sort(raw_data)
    ccdf_spd = [1-SPDmodel.cdf(i) for i in data]
    plt.scatter(data, ccdf_spd, label='SEV', marker='.', color=(0., 0., 0.5))

    # evt_data = [x for x in data if x >= SPDmodel.threshold]    
    # ecdf = DataFilter.CoordinatePoints(x=evt_data)
    # plt.scatter(ecdf.getx(), ecdf.gety(), label='ECDF_evt', marker='.', color=(0.5, 0.5, 0.))

    GEV_gen = EVTTool.GEVGenerator()
    GEVmodel = GEV_gen.fit(raw_data, 200)
    ccdf_gev = [1-GEVmodel.cdf(i) for i in data]
    plt.scatter(data, ccdf_gev, label='GEV', marker='.', color=(0.5, 0., 0.))

    # GPDgen = EVTTool.GPDGenerator()
    # GPD = GPDgen.fit(data)
    # ccdf_gpd = [1-GPD.cdf(i) for i in data]
    # # plt.scatter(data, ccdf_gpd, label='GPD', marker='.', color=(0., 0.5, 0.5))
    # plt.plot(data, ccdf_gpd, label='GPD')

    plt.legend(loc="best")
    plt.title('1-CDF')
    plt.savefig(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SPD generate test.')
    parser.add_argument('-i', '--input', type=str, default='EVTdata.csv', help='Input excution time file path')
    parser.add_argument('-o', '--output', type=str, default='output.png', help='Output file path')
    args = parser.parse_args()

    data, _ = read_evt_data(args.input)

    plot_data(data, args.output)
