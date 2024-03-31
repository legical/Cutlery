from collections import OrderedDict
import json
import os
import numpy as np
import pyvinecopulib as pv
from . import EVTTool


class DataProcess:
    KEY_EXTRACT = 'dump'
    KEY_EXCLUDE = 'fullcost'
    KEY_NORMCOST = 'normcost'
    KEY_TIME = 'time'

    @staticmethod
    def json2data(json_file: str, extract_func: str = 'main') -> OrderedDict:
        """transform seginfo json to d*n data.

        Args:
            json_file (str): path to save seginfo json file.
            extract_func (str, optional): Extract information about the execution time of the function. Defaults to 'main'.

        Raises:
            FileNotFoundError: seginfo json file not found.

        Returns:
            OrderedDict: d*n time cost data.
        """
        # check json file is exist?
        if not os.path.exists(json_file):
            raise FileNotFoundError(f"{json_file} not found")

        with open(json_file, 'r') as file:
            data = json.load(file)

        extracted_data = OrderedDict()
        # process data
        if extract_func in data[DataProcess.KEY_EXTRACT]:
            for seg_name, seg_cost in data[DataProcess.KEY_EXTRACT][extract_func].items():
                if seg_name != DataProcess.KEY_EXCLUDE:
                    time_values = seg_cost[DataProcess.KEY_NORMCOST][DataProcess.KEY_TIME]
                    extracted_data.setdefault(seg_name, list()).extend(time_values)

        return DataProcess.makeValid(extracted_data)

    @staticmethod
    # delete key-value in data
    def dropData(data: OrderedDict, key: str) -> OrderedDict:
        # check data is exist?
        if data is None:
            return None
        # if key exist in data, remove it's values
        if key in data:
            del data[key]

        return data

    @staticmethod
    def makeValid(data: OrderedDict):
        """
        对于data中所有key对应的list，执行以下操作：
        1. 如果list长度不一致，以最短的长度为基准，截断所有list。
        2. 如果某个list中的某个元素<=0，删除所有list中该元素下标的元素。
        """
        # 找到所有列表中最短的长度
        min_length = min(map(len, filter(lambda x: isinstance(x, list), data.values())))

        # 截断所有列表为最小长度
        data = {k: v[:min_length] if isinstance(v, list) else v for k, v in data.items()}

        # 删除所有列表中元素<=0的项
        idx = 0
        while idx < min_length:
            if any(lst[idx] <= 0 for lst in data.values() if isinstance(lst, list)):
                data = {k: [v[i] for i in range(min_length) if i != idx] if isinstance(
                    v, list) else v for k, v in data.items()}
                min_length -= 1  # 删除元素后列表长度减1
            else:
                idx += 1    # 只有在不删除元素的情况下，才增加索引

        return data

    @staticmethod
    def merge_simulate_obsdata(raw_data: OrderedDict, inverse_simulate_data: list) -> OrderedDict:
        """Merge raw_data and inverse_simulate_data to a new OrderedDict.

        Args:
            raw_data (OrderedDict): d*n Raw data.
            inverse_simulate_data (list): d*n matrix.

        Returns:
            OrderedDict: d*n matrix.
        """
        if raw_data is None and inverse_simulate_data is None:
            raise ValueError("Raw data or inverse_simulate_data is None.")
        else:
            if len(raw_data) != len(inverse_simulate_data):
                raise ValueError(
                    f"Raw data number[{len(raw_data)}] not equal to inverse_simulate_data dimension[{len(inverse_simulate_data)}].")

            for key, inverse_values in zip(raw_data.keys(), inverse_simulate_data):
                raw_data[key].extend(inverse_values)

            return raw_data

    @staticmethod
    def combine(raw_data: OrderedDict) -> list:
        """将相同下标的值相加并保存到一个列表中，作为任务执行时间"""
        min_length = min(len(value) for value in raw_data.values())
        task_costs = list()
        for idx in range(min_length):
            task_cost = sum(raw_data[key][idx] for key in raw_data if idx < len(raw_data[key]))
            task_costs.append(task_cost)
        return task_costs


class CopulaModel(EVTTool.PWCETInterface):
    def __init__(self, copula, raw_models, name: str = "[CopulaModel]"):
        super().__init__()
        self.copula = copula
        self.raw_models = raw_models
        self.name = name

    def isf(self, exceed_prob: float) -> float:
        """return inverse CDF value of exceed_prob. not implemented.

        Args:
            exceed_prob (float): probability of exceeding

        Returns:
            float: inverse CDF value
        """
        raise NotImplementedError
        return None

    def expression(self) -> str:
        return f"{self.name}\n{self.copula.str()}"

    def copy(self):
        return CopulaModel(self.copula, self.raw_models, self.name)

    def simulate(self, n: int, qrng: bool = False, num_threads: int = 1, seeds: list = []) -> np.ndarray:
        """simulate n samples from a vine copula model.

        Args:
            n (int): Number of observations
            qrng (bool, optional): Set to true for quasi-random numbers.. Defaults to False.
            num_threads (int, optional): The number of threads to use for computations; if greater than 1, the function will generate n samples concurrently in num_threads batches.. Defaults to 1.
            seeds (list, optional): Seeds of the random number generator; if empty (default), the random number generator is seeded randomly.. Defaults to [].

        Returns:
            np.ndarray: return d*n matrix. each row is a random variable of data.
        """
        # sim_values is  a continous n*d matrix. each column is a random variable of data.
        sim_values = self.copula.simulate(n, qrng, num_threads, seeds)
        # return d*n matrix. each row is a random variable of data.
        return sim_values.T

    def inverse_transform(self, data: np.ndarray) -> list:
        """Inverse transform the data to original distribution.

        Args:
            data (np.ndarray): d*n matrix. each row is a random variable observations.

        Returns:
            list(list(float)): d*n matrix. each row is a origin random variable data.
        """
        if self.raw_models is None or data is None:
            raise ValueError("Raw models or data is None.")
        else:
            if len(self.raw_models) != len(data):
                raise ValueError(
                    f"Model number[{len(self.raw_models)}] not equal to simulate-data dimension[{len(data)}].")
            inverse_data = list()
            for model, values in zip(self.raw_models, data):
                inverse_values = [model.isf(1-value) for value in values]
                inverse_data.append(inverse_values)

            return inverse_data


class CopulaGenerator:
    VineStructures = {
        'CVineStructure': 'Cc',
        'DVineStructure': 'Dd',
        'RVineStructure': 'Rr'
    }

    def __init__(self, models: list, raw_data: list):
        """Generate vine copula model from uniform_data.

        Args:
            models: list of fitted distribution models. Generally SPD or ECDF
            raw_data: d*n, list(list) of raw data. Each row is a random variable of data. Dimension equals number of row.
        """
        self.models = models
        self.dimension = len(raw_data)
        """uniform_data: d*n Pseudo-observation n*d data. Dimension equals number of column.
        """
        self.uniform_data = self.pseudo_obs_all(models, raw_data)

    def pseudo_obs_all(self, models: list, raw_data: list):
        """Gives pseudo-observations using model.cdf or empirical probability.

        Args:
            models (list): list of data distribution models.
            raw_data (list): d*n Raw data, consistent with the distribution represented by the model. Dimension equals number of row.

        Returns:
            np.array: 〜U(0,1). n*d CDF of raw_data. Dimension equals number of column.
        """
        if models is None:
            # Unspecified distribution type, empirical distributions are used to transform to pseudo-observations
            self.uniform_data = pv.to_pseudo_obs(np.array(raw_data).T)
        else:
            pseudo_obs_data = list()
            for model, data in zip(models, raw_data):
                pseudo_obs_data.append(self.pseudo_obs(model, data))

            self.uniform_data = np.array(pseudo_obs_data).T
        return self.uniform_data

    # change data to U(0,1). 1-row n-col
    def pseudo_obs(self, model, raw_data: list) -> np.ndarray:
        """Gives pseudo-observations using model.cdf or empirical probability.

        Args:
            model (PWCETInterface): data distribution model. Type is usually SPD denoted by MixedDistribution.
            raw_data (list): Raw data, consistent with the distribution represented by the model.

        Returns:
            np.array: A line of data, conforming to a uniform distribution.
        """
        try:
            # if model has cdf method
            if hasattr(model, 'cdf'):
                cdf_values = [model.cdf(value) for value in raw_data]
                return np.array(cdf_values)
            else:
                return pv.to_pseudo_obs(np.array(raw_data))
        except Exception as e:
            print(f'Error when getting observation with model[{model}]: {e}')
            return None

    def make_structure(self, **kwargs):
        selected_structure = kwargs.get('selected_structure', 'DVineStructure')
        order = kwargs.get('order', None)
        center = kwargs.get('center', 0)

        structure = selected_structure[:1]
        if structure in CopulaGenerator.VineStructures['CVineStructure']:
            if order is None:
                order = list(range(1, self.dimension+1))
                if center not in order:
                    raise ValueError(f"Invalid CVineStructure config with no order and default/wrong center[{center}].")
                else:
                    order = order.extend([order.pop(order.index(center))])
            return pv.CVineStructure(order)
        elif structure in CopulaGenerator.VineStructures['DVineStructure']:
            if order is None:
                order = list(range(1, self.dimension+1))
            return pv.DVineStructure(order)
        elif structure in CopulaGenerator.VineStructures['RVineStructure']:
            return pv.RVineStructure()
        else:
            raise ValueError(f"Invalid structure[{selected_structure}].")

    # Default fit D-vine copula
    def fit(self, **kwargs):
        selected_structure = kwargs.get('selected_structure', 'DVineStructure')
        structure = self.make_structure(**kwargs)
        cop = pv.Vinecop(data=self.uniform_data, structure=structure)
        return self.gen(cop, selected_structure)

    def gen(self, copula, name: str = "[CopulaModel]"):
        return CopulaModel(copula, self.models, name)
