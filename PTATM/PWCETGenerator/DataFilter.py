import numpy as np
from . import EVTTool


class KMeansCluster:
    # K均值聚类算法
    def __init__(self, data: list, k: int):
        self.data = self.ecdf_data(data)
        self.k = k

    def ecdf_data(self, data: list):
        data = data.sort()
        ecdf_gen = EVTTool.ECDFGenerator()
        self.ecdf = ecdf_gen.fit(data)
        cdf_data = self.ecdf.cdf(data)
        return list(zip(data, cdf_data))

    def choose_center(self):
        """选择初始中心点

        Returns:
            list: k center point
        """
        if self.k > len(self.data):
            raise ValueError('k must less than data length')
        if self.k == 2:
            return [self.data[0], self.data[-1]]
        elif self.k == 3:
            return [self.data[0], self.data[int(len(self.data)/2)], self.data[-1]]
        else:
            # random choose k center point
            centers_idx = np.random.choice(len(self.data), self.k, replace=False)
            centers = [self.data[i] for i in centers_idx]
            return centers

    def assign_to_clusters(self):
        """
        将数据点分配到最近的聚类中心
        """
        clusters = [[] for _ in range(self.k)]
        for point in self.data:
            distances = [np.linalg.norm(np.array(point) - np.array(centroid)) for centroid in self.centers]
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

    def fit(self, tolerance: float = 0.01, max_iter: int = 300):
        centers = self.choose_center()
        for _ in range(max_iter):
            prev_centers = centers[:]
            clusters = self.assign_to_clusters()
            centers = self.update_centers(clusters)
            # 计算聚类中心的移动距离
            movement = max(np.linalg.norm(np.array(prev_centers[i]) -
                           np.array(centers[i])) for i in range(len(centers)))
            if movement < tolerance:
                break
        return centers, clusters
