from abc import abstractmethod
import numpy as np
from scipy.stats import genpareto
from statsmodels.distributions.empirical_distribution import ECDF
from scipy.stats import kstest
from scipy.stats import rv_discrete

class CDFInterface():
    @abstractmethod
    def isf(self, exceed_prob: float) -> float:
        """Given an exceed probability, return the value corresponding to that probability in the CDF."""
        pass

    @abstractmethod
    def expression(self) -> str:
        """Return a string representation of the CDF."""
        return str()

    @abstractmethod
    def copy(self):
        """Create a copy of the object."""
        pass

    @abstractmethod
    def gen_cdf(self, data):
        """Fit the distribution to the given data."""
        pass

    @abstractmethod
    def get_cdf(self):
        """Return the fitted CDF model."""
        pass

class GeneralizedParetoDistribution(CDFInterface):
    def __init__(self):
        self.params = None

    def isf(self, exceed_prob: float) -> float:
        return genpareto.isf(exceed_prob, *self.params)

    def expression(self) -> str:
        return "Generalized Pareto Distribution"

    def copy(self):
        new_dist = GeneralizedParetoDistribution()
        new_dist.params = self.params
        return new_dist

    def gen_cdf(self, data):
        self.params = genpareto.fit(data)

    def get_cdf(self):
        class GeneralizedPareto(rv_discrete):
            def _pmf(self, x):
                return genpareto.pdf(x, *self.params)
        return GeneralizedPareto(name='GeneralizedPareto')

    def check_fit_quality(self, data):
        _, p_value = kstest(data, 'genpareto', self.params)
        return p_value >= 0.05

class EmpiricalDistribution(CDFInterface):
    def __init__(self):
        self.ecdf = None

    def isf(self, exceed_prob: float) -> float:
        return self.ecdf.x[np.argmax(self.ecdf.y >= 1 - exceed_prob)]

    def expression(self) -> str:
        return f"Empirical Distribution: x={self.ecdf.x}, y={self.ecdf.y}"

    def copy(self):
        new_dist = EmpiricalDistribution()
        new_dist.ecdf = self.ecdf
        return new_dist

    def gen_cdf(self, data):
        self.ecdf = ECDF(data)

    def get_cdf(self):
        return rv_discrete(name='EmpiricalDistribution', values=(self.ecdf.x, self.ecdf.y))

class MixedDistribution(CDFInterface):
    def __init__(self):
        self.generalized_pareto = GeneralizedParetoDistribution()
        self.empirical = EmpiricalDistribution()
        self.p = None

    def isf(self, exceed_prob: float) -> float:
        if self.p is None:
            return self.empirical.isf(exceed_prob)
        else:
            if exceed_prob >= 1 - self.p:
                return self.generalized_pareto.isf(exceed_prob)
            else:
                return self.empirical.isf(exceed_prob)

    def expression(self) -> str:
        return "Mixed Distribution"

    def copy(self):
        new_dist = MixedDistribution()
        new_dist.generalized_pareto = self.generalized_pareto.copy()
        new_dist.empirical = self.empirical.copy()
        new_dist.p = self.p
        return new_dist

    def gen_cdf(self, data):
        self.p = 0.9 * np.max(data)
        self.generalized_pareto.gen_cdf(data[data > self.p])
        if self.generalized_pareto.check_fit_quality(data[data > self.p]):
            self.empirical.gen_cdf(data[data <= self.p])
        else:
            self.p = None
            self.empirical.gen_cdf(data)

    def get_cdf(self):
        class Mixed(rv_discrete):
            def _pmf(self, x):
                if self.p is None:
                    return self.empirical.get_cdf()._pmf(x)
                else:
                    return np.where(x > self.p, self.generalized_pareto.get_cdf()._pmf(x), self.empirical.get_cdf()._pmf(x))
        return Mixed(name='MixedDistribution')
