import numpy as np
from statsmodels.distributions.empirical_distribution import ECDF
from typing import Union


class DataTool:
    @staticmethod
    def ecdf_ccdf_data(data):
        if data is None:
            raise ValueError('data is None')
        ecdf_func = ECDF(data)
        ccdf_data = [1-ecdf_func(value) for value in data]
        return ccdf_data

    @staticmethod
    def slope(points, points_sort: bool = False, sample_interval: int = 20):
        data_points = np.array(points)
        if points_sort:
            # 如果选择排序，那么按照x升序排列
            sorted_indices = np.argsort(data_points[:, 0])
            # 使用索引重新排列数组
            data_points = data_points[sorted_indices]

        # 去除具有相同x轴值的元素
        # 获取第一列数据（x坐标）
        x_values = data_points[:, 0]
        # 找到x值相邻的索引位置
        diff_index = np.where(np.diff(x_values) == 0)[0]
        # 删除相邻行中x值相同的行
        data_unique = np.delete(data_points, diff_index + 1, axis=0)

        # 每sample_interval个点计算一次斜率
        data_unique = data_unique[::sample_interval]

        # 计算斜率
        dx = np.diff(data_unique[:, 0])
        dy = np.diff(data_unique[:, 1])
        slopes = dy*1e5 / dx

        # 提取x值
        x_values = data_unique[:-1, 0]

        # 构建结果数组
        # result = np.array([x_values, slopes])
        return slopes, x_values


class CoordinatePoints:
    def __init__(self, x, y=None):
        """CoordinatePoints构造函数

        Args:
            x: x轴数据
            y: y轴数据.如果为None，自动对x升序排序且y=1-CDF(x). Defaults to None.
        """
        if y is None:
            self.x = np.sort(x)
            self.y = DataTool.ecdf_ccdf_data(self.x)
        else:
            self.x = np.array(x)
            self.y = np.array(y)
        # 截断，保证x、y长度一致
        self.lenth = min(len(self.x), len(self.y))
        self.x = self.x[:self.lenth]
        self.y = self.y[:self.lenth]

        self.points = np.array([self.x, self.y])

    def getx(self):
        return self.x

    def gety(self):
        return self.y

    def get_number(self):
        return self.lenth

    def get_point(self, idx: int = None, x=None, y=None, strict: bool = False):
        """使用索引下标、x轴、y轴查找点的坐标

        Args:
            idx (int, optional): 索引下标. Defaults to None.
            x (float, optional): 查找横坐标等于x的坐标点. Defaults to None.
            y (float, optional): 查找纵坐标等于y的坐标点. Defaults to None.
            strict (bool, optional): 是否开启严格模式. Defaults to False.

        Raises:
            ValueError: 开启严格模式下，idx超过self.points数量
            ValueError: 开启严格模式下，未找到横坐标等于x的坐标点
            ValueError: 开启严格模式下，未找到纵坐标等于y的坐标点

        Returns:
            Tuple(float, float): 横坐标和纵坐标
        """
        if idx is not None:
            if idx >= self.lenth:
                if strict:
                    raise ValueError('Index out of range')
            if idx < 0:
                idx = self.lenth - (abs(idx) % self.lenth)
            else:
                idx = idx % self.lenth
        elif x is not None:
            if x not in self.points[0]:
                if strict:
                    raise ValueError('x not in data')
                else:
                    # find first >= x
                    idx = np.argmax(self.points[0] >= x)
            idx = np.where(self.points[0] == x)
        elif y is not None:
            if y not in self.points[1]:
                if strict:
                    raise ValueError('y not in data')
                else:
                    # find first >= y
                    idx = np.argmax(self.points[1] >= y)
            idx = np.where(self.points[1] == y)
        return (self.points[0][idx], self.points[1][idx])

    def get_points(self):
        return zip(self.x, self.y)

    def normalize(self, axis: int = 1) -> np.ndarray:
        """归一化坐标点。默认对y轴数据归一化

        Args:
            axis (int, optional): 选择坐标轴，0是x轴，1是y轴. Defaults 1.

        Returns:
            np.ndarray: 归一化后的坐标点
        """
        self.points[axis] = (self.points[axis] - np.min(self.points[axis])) / \
            (np.max(self.points[axis]) - np.min(self.points[axis]))
        self.x = self.points[0]
        self.y = self.points[1]
        return self.points

    def slopes(self, points_sort: bool = False):
        """计算坐标点之间的斜率，去除相邻x值相等的元素"""
        return DataTool.slope(self.points.T, points_sort)

    def sort(self, axis: int = 0) -> np.ndarray:
        """按照指定轴排序

        Args:
            axis (int, optional): 选择坐标轴，0是x轴，1是y轴. Defaults 0.

        Returns:
            np.ndarray: 排序后的坐标点
        """
        # 默认按照第一行（x值）排序后的索引
        sorted_indices = np.argsort(self.points[axis])

        # 使用索引重新排列数组
        self.points = self.points[:, sorted_indices]
        self.x = self.points[0]
        self.y = self.points[1]

        return self.points


class KMeansCluster:
    # K均值聚类算法
    def __init__(self, data, k: int):
        self.points = CoordinatePoints(data)
        self.k = k

    def choose_center(self):
        """选择初始中心点

        Returns:
            list(Tuple(x,y)): k center point
        """
        if self.k > self.points.get_number():
            raise ValueError('k must less than data length')
        if self.k == 2:
            return [self.points.get_point(idx=0), self.points.get_point(idx=-1)]
        elif self.k == 3:
            return [self.points.get_point(idx=0), self.points.get_point(idx=int(self.points.get_number()/2)), self.points.get_point(idx=-1)]
        else:
            # random choose k center point
            centers_idx = np.random.choice(self.points.get_number(), self.k, replace=False)
            centers = [self.points.get_point(idx=i) for i in centers_idx]
            return centers

    def assign_to_clusters(self, centers):
        """将数据点分配到最近的聚类中心

        Returns:
            list(list(Tuple(x,y))): k list[list(point)]
        """
        clusters = [[] for _ in range(self.k)]
        for point in self.points.get_points():
            distances = [np.linalg.norm(np.array(point) - np.array(centroid)) for centroid in centers]
            closest_centroid_idx = np.argmin(distances)
            clusters[closest_centroid_idx].append(point)
        return clusters

    def update_centers(self, clusters):
        """
        更新聚类中心
        """
        centers = []
        for cluster in clusters:
            if cluster:
                new_centroid = np.mean(cluster, axis=0)
                centers.append(new_centroid)
        return centers

    def cluster(self, tolerance: float = 0.1, max_iter: int = 50):
        """K聚类算法

        Args:
            tolerance (float, optional): 容忍度，当两次过程的中心点距离差小于tolerance，结束聚类. Defaults to 0.1.
            max_iter (int, optional): 最大迭代次数，超过max_iter次后，聚类终止. Defaults to 50.

        Returns:
            list, list: 两个list，分别代表聚类中心和聚类结果
        """
        # 初始中心点
        centers = self.choose_center()
        for _ in range(max_iter):
            prev_centers = centers[:]
            clusters = self.assign_to_clusters(centers)
            centers = self.update_centers(clusters)
            # 计算聚类中心的移动距离
            movement = max(np.linalg.norm(np.array(prev_centers[i]) -
                           np.array(centers[i])) for i in range(len(centers)))
            if movement < tolerance:
                break
        return centers, clusters


class MeanChangePointDetector:
    def __init__(self, data: np.ndarray):
        """
        Initializes the MeanChangePointDetector with the given data.

        Args:
            data (np.ndarray): 一列原始数据
        """
        self.data = data
        self.total_mean = np.mean(data)
        self.total_variance = np.var(data)

    def find_change_point(self):
        """
        Finds the change point (index) in the data where the total variance is minimized.

        Returns:
            int or None: The index of the change point, or None if no change point is detected.
        """
        min_diff = float('inf')
        change_point = None

        # Initialize cumulative sums for X1 and X2
        sum_X1 = 0
        sum_X2 = np.sum(self.data)

        for i, x in enumerate(self.data):
            # Update cumulative sums
            sum_X1 += x
            sum_X2 -= x

            # Calculate means and variances for X1 and X2
            mean1 = sum_X1 / (i + 1)
            mean2 = sum_X2 / (len(self.data) - i - 1)
            variance1 = sum((xi - mean1) ** 2 for xi in self.data[:i + 1]) / (i + 1)
            variance2 = sum((xi - mean2) ** 2 for xi in self.data[i + 1:]) / (len(self.data) - i - 1)

            # Calculate total variance difference
            total_variance_diff = self.total_variance - (variance1 + variance2)

            if total_variance_diff < min_diff:
                min_diff = total_variance_diff
                change_point = i

        return change_point


class PoT:
    def __init__(self, data: list):
        self.data = data
        self.threshold = None

    def threshold(self):
        return self.threshold

    def cluster(self, k: int = 3):
        """Clusters the data using K-means clustering algorithm and chooses a threshold.

        Args:
        - k (int, optional): The number of clusters to create. Defaults to 3.

        Returns: tuple
        - threshold: float, threshold value
        - EVT_value: the values above the threshold
        - below_threshold: the values below or equal to the threshold
        """
        if k is None:
            k = 3
        kcluster = KMeansCluster(self.data, k)
        centers, _ = kcluster.cluster()
        self.threshold = max(coord[0] for coord in centers)
        return self.normal(self.threshold)

    def maxn(self, n: int = 4):
        """
        Return the maximum n values from the data.

        Parameters:
        - n (int): The number of maximum values to return. Default is 4.

        Returns:
        - EVT_value: the values above the threshold
        """
        if n is None:
            n = 4
        sorted_data = np.sort(self.data)
        nr_ext = abs(n)
        self.threshold = sorted_data[-nr_ext]
        return self.normal(self.threshold)

    def percent_of_max(self, percent_max: float = 0.95):
        """
        Calculates the threshold value based on the given percentage of the maximum value in the data.

        Args:
        - percent_max (float, optional): The percentage of the maximum value to use as the threshold. Defaults to 0.95.

        Returns:
        - EVT_value: the values above the threshold
        """
        if percent_max is None:
            percent_max = 0.95
        self.threshold = np.percentile(self.data, percent_max * 100)
        return self.normal(self.threshold)

    def normal(self, threshold: float = None):
        """
        Applies the classic Peaks-over-Threshold (PoT) thresholding method.

        Args:
        - threshold (float): The threshold value for PoT. Defaults to None.

        Returns:
        - EVT_values: the values above the threshold

        Raises:
        - ValueError: if the threshold is None.
        """
        if threshold is not None:
            self.threshold = threshold
        if self.threshold is None:
            raise ValueError(f'Wrong PoT config without threshold!')
        return self.threshold
        # EVT_values = [x for x in self.data if x > self.threshold]
        # return EVT_values

    def filter(self, method: str = 'cluster', arg=None):
        """
        Filter data using the specified method.

        Parameters:
        - method (str): ['cluster', 'maxn', 'percent'].The method to use for filtering. Default is 'cluster'.
        - *arg: Additional arguments specific to the selected method.

        Returns:
        - EVT_value: the values above the threshold

        Raises:
        - ValueError: If an invalid method is provided.
        """
        if method is None:
            method = 'cluster'
            
        if method == 'cluster':
            return self.cluster(arg)
        elif method == 'maxn':
            return self.maxn(arg)
        elif method == 'percent':
            return self.percent_of_max(arg)
        else:
            raise ValueError(f'Wrong PoT selection method: {method}!')
