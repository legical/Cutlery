# 声明所使用的第三方库
import pyvinecopulib as pv
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import weibull_min
from scipy.stats import norm, gaussian_kde
from scipy.special import ndtr
from sklearn.neighbors import KernelDensity
from sklearn.model_selection import GridSearchCV
 
# 为数据导出做准备
import os
import xlrd
import xlsxwriter
import numpy as np
 
# 读取输入数据所存放的文件夹路径
folderpath = r"D:\data"
file_list = os.listdir(folderpath)
 
# 光伏出力受温度影响故而也需要生成相应的温度场景
folderpatht = r"D:\温度data"
file_listt = os.listdir(folderpatht)
 
na = xlsxwriter.Workbook(r"D:\文件\NC\CJSC.xlsx") # 场景生成的结果保存路径
 
# 生成的数据是逐小时，24小时，h=24
for h in range(24):
 
    # X存储excel中导入的数据
    x = []
 
    # 为导出的数据添加sheet，以小时命名。
    worksheet_cjsc = na.add_worksheet('{}hour'.format(h)) 
 
    # 读取输入数据，存放在X
    for w in file_list:
        workbook = xlrd.open_workbook(r"D:\文件\NC\data\{}".format(w))
        sheet = workbook.sheet_by_index(0)
        cells = np.zeros((sheet.nrows, sheet.ncols))
        for i in range(sheet.nrows):
            for j in range(sheet.ncols):
                cells[i, j] = sheet.cell_value(i, j)
        hang = cells.shape[0]
        lie = cells.shape[1]
        temp = cells[:,h]
        x.append(temp)
 
    for weee in file_listt:
        workbookwe = xlrd.open_workbook(r"D:\文件\NC\温度data\{}".format(weee))
        sheetwe = workbookwe.sheet_by_index(0)
        cellswe = np.zeros((sheetwe.nrows, sheetwe.ncols))
        for i in range(sheetwe.nrows):
            for j in range(sheetwe.ncols):
                cellswe[i, j] = sheetwe.cell_value(i, j)
        hang = cellswe.shape[0]
        lie = cellswe.shape[1]
        tempwe = cellswe[:,h]
        x.append(tempwe)
 
    x = np.array(x).T   # 例子中有五个电站，X的第1、3是风数据，0、2、4是光，5、6、7是温度
 
    # 风拟合威布尔分布，并求出对应的cdf（概率分布函数）
    c1, loc1, scale1 = weibull_min.fit(x[:, 1])
    c3, loc3, scale3 = weibull_min.fit(x[:, 3])
 
    dist1 = weibull_min(c1, loc1, scale1)    # 这里是pdf
    dist3 = weibull_min(c3, loc3, scale3)
 
    cdf1 = dist1.cdf(x[:, 1])
    cdf3 = dist3.cdf(x[:, 3])
 
 
    # 光伏用NPKDE进行拟合,并求出对应的cdf（概率分布函数）
 
    # 经验法选择带宽
    STDEV0 = np.std(x[:, 0], ddof=1)
    STDEV2 = np.std(x[:, 2], ddof=1)
    STDEV4 = np.std(x[:, 4], ddof=1)
 
    h0 = 1.0592*STDEV0*(len(x[:, 0])**-0.2)
    h2 = 1.0592*STDEV2*(len(x[:, 2])**-0.2)
    h4 = 1.0592*STDEV4*(len(x[:, 4])**-0.2)
 
    kde0 = gaussian_kde(x[:, 0],bw_method = h0)
    kde2 = gaussian_kde(x[:, 2],bw_method = h2)
    kde4 = gaussian_kde(x[:, 4],bw_method = h4)
 
    # 根据kde计算cdf
 
    cdf_temp0 = tuple(ndtr(np.ravel(item - kde0.dataset) / kde0.factor).mean()for item in x[:, 0])
    cdf_temp2 = tuple(ndtr(np.ravel(item - kde2.dataset) / kde2.factor).mean()for item in x[:, 2])
    cdf_temp4 = tuple(ndtr(np.ravel(item - kde4.dataset) / kde4.factor).mean()for item in x[:, 4])
 
    # 转为array
    cdf0 = []
    cdf2 = []
    cdf4 = []
 
    for iii in range(len(cdf_temp0)):
        cdf0.append(cdf_temp0[iii])
    cdf0 = np.array(cdf0)
 
    for iii in range(len(cdf_temp2)):
        cdf2.append(cdf_temp2[iii])
    cdf2 = np.array(cdf2)
 
    for iii in range(len(cdf_temp4)):
        cdf4.append(cdf_temp4[iii])
    cdf4 = np.array(cdf4)
 
    # 温度用NPKDE进行拟合,并求出对应的cdf（概率分布函数）
 
    # 选择带宽
    STDEV5 = np.std(x[:, 5], ddof=1)
    STDEV6 = np.std(x[:, 6], ddof=1)
    STDEV7 = np.std(x[:, 7], ddof=1)
 
    h5 = 1.0592 * STDEV5 * (len(x[:, 5]) ** -0.2)
    h6 = 1.0592 * STDEV6 * (len(x[:, 6]) ** -0.2)
    h7 = 1.0592 * STDEV7 * (len(x[:, 7]) ** -0.2)
 
    kde5 = gaussian_kde(x[:, 5], bw_method=h5)
    kde6 = gaussian_kde(x[:, 6], bw_method=h6)
    kde7 = gaussian_kde(x[:, 7], bw_method=h7)
 
    # 根据kde计算cdf
    cdf_temp5 = tuple(ndtr(np.ravel(item - kde5.dataset) / kde5.factor).mean() for item in x[:, 5])
    cdf_temp6 = tuple(ndtr(np.ravel(item - kde6.dataset) / kde6.factor).mean() for item in x[:, 6])
    cdf_temp7 = tuple(ndtr(np.ravel(item - kde7.dataset) / kde7.factor).mean() for item in x[:, 7])
 
    # 转为array
    cdf5 = []
    cdf6 = []
    cdf7 = []
 
    for iii in range(len(cdf_temp5)):
        cdf5.append(cdf_temp5[iii])
    cdf5 = np.array(cdf5)
 
    for iii in range(len(cdf_temp6)):
        cdf6.append(cdf_temp6[iii])
    cdf6 = np.array(cdf6)
 
    for iii in range(len(cdf_temp7)):
        cdf7.append(cdf_temp7[iii])
    cdf7 = np.array(cdf7)
 
    # 藤coupla输入
    u = []
    u.append(cdf0)
    u.append(cdf1)
    u.append(cdf2)
    u.append(cdf3)
    u.append(cdf4)
    u.append(cdf5)
    u.append(cdf6)
    u.append(cdf7)
    u = np.array(u).T
 
    # 这里Gaussian vine是合适的,因为原数据是多元正态分布
    controls = pv.FitControlsVinecop()
    cop = pv.Vinecop(u, controls=controls)
 
    n_sim = 2000 # 生成2000个场景
    u_sim = cop.simulate(n_sim) # 从copula模型中生成模拟数据
 
    # 将模拟的u_sim转换回原尺度x，蒙特卡罗生成逐小时的场景
    d = x.shape[1]
    x_sim = np.asarray([np.quantile(x[:, i], u_sim[:, i]) for i in range(0, d)])
    x_sim = x_sim.T
    lieshu_x = x_sim.shape[1]
    for usjssu in range(lieshu_x):
        worksheet_cjsc.write_column(0,usjssu,x_sim[:,usjssu])
 
# 结果保存完毕
na.close()