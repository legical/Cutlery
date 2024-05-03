from scipy import interpolate
import statsmodels.tsa.stattools as stattools
from abc import abstractmethod
import numpy as np
from scipy.stats import gamma, genpareto, genextreme, rv_discrete, gaussian_kde, kstest, cramervonmises
from scipy.special import ndtr
from statsmodels.distributions.empirical_distribution import ECDF
from . import DataFilter


# We can generate a pwcet estimate/plot from a PWCETInterface.
class PWCETInterface:
    def __init__(self) -> None:
        self.name = 'DistributionModel'

    # Return a value with exceedance probability(exceed_prob).
    @abstractmethod
    def isf(self, exceed_prob: float) -> float:
        """isf(1-CDF) = original data

        Args:
            exceed_prob (float): 1-CDF

        Returns:
            float: original data
        """
        pass

    # Return an expression.
    @abstractmethod
    def expression(self) -> str:
        return str()

    # Copy this object.
    @abstractmethod
    def copy(self):
        pass

    # Return distribution name.
    def getname(self) -> str:
        return self.name


class KernelDensityEstimation(PWCETInterface):
    def __init__(self, kde_func):
        super().__init__()
        self.kde_func = kde_func
        self.dataset = kde_func.dataset[0]
        self.cdf_values = self.cdfs()
        self.name = '[KDE]'

    def isf(self, exceed_prob: float) -> float:
        return self.inversefunction(1 - exceed_prob)

    def expression(self) -> str:
        return f"{self.getname()} x∈[{np.min(self.dataset)}, {np.max(self.dataset)}]"

    def copy(self):
        return KernelDensityEstimation(self.kde_func)

    def pdf(self, x):
        return self.kde_func.evaluate(x)

    def cdfs(self):
        samples = len(self.dataset)*2
        self.x = np.linspace(np.min(self.dataset),
                             np.max(self.dataset), samples)
        cdf_values = tuple(ndtr(np.ravel(item - self.dataset) / self.kde_func.factor).mean()
                           for item in self.x)
        # fix error: ValueError: Expect x to not have duplicates
        unique_cdf_values, unique_indices = np.unique(
            cdf_values, return_index=True)
        unique_x = self.x[unique_indices]
        self.inversefunction = interpolate.interp1d(
            unique_cdf_values, unique_x, kind='cubic', bounds_error=False, fill_value=(unique_x[0], unique_x[-1]))
        return cdf_values

    def cdf(self, x):
        return ndtr(np.ravel(x - self.dataset) / self.kde_func.factor).mean()

    def getCDF(self):
        class KDERT(rv_discrete):
            def _pmf(self, x):
                return self.kde_func.evaluate(x)
        return KDERT(name='KDERT')


class EmpiricalDistribution(PWCETInterface):
    def __init__(self, ecdf_func):
        super().__init__()
        self.ecdf_func = ecdf_func
        self.name = '[ECDF]'
        self.isf_func = EmpiricalDistribution.get_isf(ecdf_func)

    def isf(self, exceed_prob: float) -> float:
        # return self.isf_func(1-exceed_prob)
        return self.ecdf_func.x[np.argmax(self.ecdf_func.y >= 1 - exceed_prob)]

    def expression(self) -> str:
        return f"Empirical Distribution: x∈[{min(self.ecdf_func.x)}, {max(self.ecdf_func.x)}], y∈[{min(self.ecdf_func.y)}, {max(self.ecdf_func.y)}]"

    def copy(self):
        return EmpiricalDistribution(self.ecdf_func)

    def cdf(self, x):
        return self.ecdf_func(x)

    def getCDF(self):
        return rv_discrete(name='EmpiricalDistribution', values=(self.ecdf_func.x, self.ecdf_func.y))

    @staticmethod
    def get_isf(ecdf_func):
        unique_cdf_values, unique_indices = np.unique(
            ecdf_func.y, return_index=True)
        unique_x = ecdf_func.x[unique_indices]
        inversefunction = interpolate.interp1d(
            unique_cdf_values, unique_x, kind='cubic', bounds_error=False, fill_value=(unique_x[0], unique_x[-1]))
        return inversefunction


class ExtremeDistribution(PWCETInterface):
    PARAM_SHAPE = "c"
    PARAM_LOC = "loc"
    PARAM_SCALE = "scale"
    PARAM_THRESHOLD = "threshold"

    @staticmethod
    def validparam(params: dict) -> bool:
        return ExtremeDistribution.PARAM_SHAPE in params and ExtremeDistribution.PARAM_LOC in params and ExtremeDistribution.PARAM_SCALE in params

    def __init__(self, ext_class, params: dict) -> None:
        super().__init__()
        # Here ext_class is original generator from scipy.stat.
        self.ext_class = ext_class
        self.name = '[EVT]'
        # Here ext_func is original extreme distribution object from scipy.stat
        self.gen(params)

    def isf(self, exceed_prob: float) -> float:
        return self.ext_func.isf(exceed_prob)

    def expression(self) -> str:
        kwds = self.ext_func.kwds
        return f"[{ExtremeDistribution.PARAM_SHAPE}={kwds[ExtremeDistribution.PARAM_SHAPE]}, {ExtremeDistribution.PARAM_LOC}={kwds[ExtremeDistribution.PARAM_LOC]}, {ExtremeDistribution.PARAM_SCALE}={kwds[ExtremeDistribution.PARAM_SCALE]}]"
        # return "(%s=%s, %s=%s, %s=%s)" % (ExtremeDistribution.PARAM_SHAPE, str(round(kwds[ExtremeDistribution.PARAM_SHAPE], 4)),
        #                                   ExtremeDistribution.PARAM_LOC, str(
        #                                       round(kwds[ExtremeDistribution.PARAM_LOC], 4)),
        #                                   ExtremeDistribution.PARAM_SCALE, str(round(kwds[ExtremeDistribution.PARAM_SCALE], 4)))

    def copy(self):
        return ExtremeDistribution(self.ext_class, self.kwds())

    # Re-generate self.ext_func attribute with params.
    def gen(self, params: dict):
        c = params[ExtremeDistribution.PARAM_SHAPE]
        loc = params[ExtremeDistribution.PARAM_LOC]
        scale = params[ExtremeDistribution.PARAM_SCALE]
        self.ext_func = self.ext_class(c=c, loc=loc, scale=scale)
        return self

    # Return self.ext_func.kwds.
    def kwds(self) -> dict:
        return self.ext_func.kwds.copy()

    def cdf(self, x):
        return self.ext_func.cdf(x)

    def getCDF(self):
        class EVTCDF(rv_discrete):
            def _pmf(self, x):
                return self.ext_func._pdf(x)
        return EVTCDF(name='EVTCDF')


class GEV(ExtremeDistribution):
    def __init__(self, params: dict) -> None:
        super().__init__(genextreme, params)
        self.name = '[GEV]'

    def expression(self) -> str:
        return "GEV" + super().expression()

    def copy(self):
        return GEV(self.kwds())


class GPD(ExtremeDistribution):
    def __init__(self, params: dict) -> None:
        super().__init__(genpareto, params)
        self.name = '[GPD]'

    def expression(self) -> str:
        return "GPD" + super().expression()

    def copy(self):
        return GPD(self.kwds())


class MixedDistribution(PWCETInterface):
    """
    self.threshold = None : only ECDF
    self.threshold != None: EVT(tail) & KDE(kernel)
    """

    def __init__(self, **kwargs):
        super().__init__()
        self.EVTmodel = kwargs.get('EVT', None)
        self.KDEmodel = kwargs.get('KDE', None)
        self.ECDFmodel = kwargs.get('ECDF', None)
        self.threshold = kwargs.get('threshold', None)
        self.threshold_cdf = self.ECDFmodel.cdf(
            self.threshold) if self.threshold is not None else None
        self.name = kwargs.get('name', '[Mixed]')

    def onlyECDF(self):
        return self.threshold is None

    def isf(self, exceed_prob: float) -> float:
        if self.onlyECDF():
            return self.KDEmodel.isf(exceed_prob)
        else:
            # TODO: Return isf for different distributions selected according to the thresholds
            if exceed_prob >= 1-self.threshold_cdf:
                # exceed_prob = 1-(1-exceed_prob)/self.threshold_cdf
                # print(f"MIX KDE exceed_prob={exceed_prob}")
                return self.KDEmodel.isf(exceed_prob)
            else:
                exceed_prob = exceed_prob/(1-self.threshold_cdf)
                # print(f"MIX GPD exceed_prob={exceed_prob}")
                return self.EVTmodel.isf(exceed_prob)+self.threshold

    def expression(self) -> str:
        if self.onlyECDF():
            return f"\t{self.getname()}\t{self.KDEmodel.expression()}"
        else:
            return f"\t{self.getname()}\tThreshold[{self.threshold}]\n\t{self.KDEmodel.expression()}\t{self.EVTmodel.expression()}"

    def copy(self):
        params = dict(EVT=self.EVTmodel.copy(), KDE=self.KDEmodel.copy(),
                      threshold=self.threshold, ECDF=self.ECDFmodel.copy(), name=self.name)
        return MixedDistribution(**params)

    def getCDF(self):
        if self.onlyECDF():
            return self.ECDFmodel.getCDF()

        class Mixed(rv_discrete):
            def _pmf(self, x):
                return np.where(x > self.threshold, self.EVTmodel.getCDF()._pmf(x), self.KDEmodel.getCDF()._pmf(x))
        return Mixed(name='SPD')

    def cdf(self, x):
        if self.onlyECDF():
            return self.KDEmodel.cdf(x)
        else:
            if x <= self.threshold:
                # [0, self.threshold_cdf)
                return self.KDEmodel.cdf(x)
            else:
                # [self.threshold_cdf, 1]
                return self.threshold_cdf + (1 - self.threshold_cdf)*self.EVTmodel.cdf(x-self.threshold)


class LinearCombinedExtremeDistribution(PWCETInterface):
    def __init__(self) -> None:
        super().__init__()
        # A dict maps extd function(ExtremeDistribution object) to it's weight.
        self.weighted_extdfunc = dict()
        self.name = '[LinearCombined]'

    def expression(self) -> str:
        expr = str()
        for extd_func, weight in self.weighted_extdfunc.items():
            expr += str(weight) + '*' + extd_func.expression() + '+'
        return expr[:-1]

    def copy(self):
        linear_extd = LinearCombinedExtremeDistribution()
        for extd_func, weight in self.weighted_extdfunc.items():
            if not linear_extd.add(extd_func.copy(), weight):
                return None
        return linear_extd

    def add(self, extd_func: ExtremeDistribution, weight: int = 1) -> bool:
        if weight != 0:
            self.weighted_extdfunc.setdefault(extd_func, 0)
            self.weighted_extdfunc[extd_func] += weight
        return True

    def addLinear(self, linear_extd) -> bool:
        orig = self.weighted_extdfunc.copy()
        for extd_func, weight in linear_extd.weighted_extdfunc.items():
            if False == self.add(extd_func, weight):
                self.weighted_extdfunc = orig
                return False
        return True

    def mul(self, k: int):
        for extd_func, weight in self.weighted_extdfunc.items():
            self.weighted_extdfunc[extd_func] = weight * k
        return self

    def div(self, k: int):
        for extd_func, weight in self.weighted_extdfunc.items():
            self.weighted_extdfunc[extd_func] = weight / k
        return self

    def clear(self):
        self.weighted_extdfunc.clear()


class PositiveLinearGumbel(LinearCombinedExtremeDistribution):
    def __init__(self) -> None:
        super().__init__()
        self.name = '[PositiveLinearGumbel]'

    def copy(self):
        linear_extd = PositiveLinearGumbel()
        for extd_func, weight in self.weighted_extdfunc.items():
            if not linear_extd.add(extd_func.copy(), weight):
                return None
        return linear_extd

    def add(self, extd_func: GEV, weight: int = 1) -> bool:
        if not isinstance(extd_func, GEV) or weight <= 0 or extd_func.kwds()[ExtremeDistribution.PARAM_SHAPE] != 0:
            return False
        kwds = extd_func.kwds()
        kwds[ExtremeDistribution.PARAM_LOC] *= weight
        kwds[ExtremeDistribution.PARAM_SCALE] *= weight
        return super().add(extd_func.copy().gen(kwds), 1)

    # Return a value with exceedance probability(exceed_prob).
    def isf(self, exceed_prob: float) -> float:
        ans = 0.0
        for extd_func, weight in self.weighted_extdfunc.items():
            ans += weight * extd_func.isf(exceed_prob)
        return ans

# ExponentialPareto xi ~ GPD(c=0, loc=ui, scale=σi) ~ E(ui, σi), we assume ui > 0 and σi > 0 for i in 1 ~ n.
# Let yi = xi-ui/σi ~ E(0, 1), then ∑yi ~ Gamma(a=n, loc=0, scale=1).
# If p(∑yi < k) = pk, cause ∑yi = ∑[(xi-ui)/σi], then ∑(xi-ui) / max{σi} <= ∑yi <= ∑(xi-ui) / min{σi}.
# Thus, min{σi} * ∑yi + ∑ui <= ∑xi <= max{σi} * ∑yi + ∑ui and p(∑xi < max{σi}*k+∑ui) >= pk
# Finally, for exceedance probability ep = 1 - pk, cause  p(∑yi >= k) = 1 - pk = ep, then p(∑xi >= max{σi}*k+∑ui) <= 1 - pk = ep,
# we can promise the probability of pwcet=max{σi}*k+∑ui is smaller than the given probability ep.
# For weighted exponential variable x,  x ~ E(u, σ), then weight*x ~ E(weight*u, weight*σ).


class PositiveLinearExponentialPareto(LinearCombinedExtremeDistribution):
    def __init__(self) -> None:
        super().__init__()
        # Attributes works for isf according to self.weighted_evtfunc.
        # Those attrs should be re-generate if self.weighted_evtfunc is changed.
        self.gamma_func = None
        self.sum_loc = None
        self.max_scale = None
        self.should_gen = True
        self.name = '[PositiveLinearExponentialPareto]'

    def copy(self):
        linear_extd = PositiveLinearExponentialPareto()
        for extd_func, weight in self.weighted_extdfunc.items():
            if not linear_extd.add(extd_func.copy(), weight):
                return None
        linear_extd.gamma_func = self.gamma_func
        linear_extd.sum_loc = self.sum_loc
        linear_extd.max_scale = self.max_scale
        linear_extd.should_gen = self.should_gen
        return linear_extd

    # Return a value with exceedance probability(exceed_prob).
    def isf(self, exceed_prob: float) -> float:
        if self.should_gen:
            self.genArgs()
        return self.max_scale*self.gamma_func.isf(exceed_prob) + self.sum_loc

    # Generate helper attrs: gamma_func, max_scale, sum_loc.
    def genArgs(self):
        self.gamma_func = gamma(a=len(self.weighted_extdfunc), loc=0, scale=1)
        self.sum_loc = 0
        self.max_scale = 0
        for extd_func, weight in self.weighted_extdfunc.items():
            kwds = extd_func.kwds()
            self.sum_loc += weight * kwds[ExtremeDistribution.PARAM_LOC]
            self.max_scale = max(self.max_scale, weight *
                                 kwds[ExtremeDistribution.PARAM_SCALE])
        self.should_gen = False

    def add(self, extd_func: GPD, weight: int = 1) -> bool:
        if not isinstance(extd_func, GPD) or weight <= 0 or extd_func.kwds()[ExtremeDistribution.PARAM_SHAPE] != 0:
            return False
        return super().add(extd_func, weight)

    def addLinear(self, linear_extd) -> bool:
        if not super().addLinear(linear_extd):
            return False
        self.should_gen = True
        return True

    def mul(self, k: int):
        self.should_gen = True
        return super().mul(k)

    def div(self, k: int):
        self.should_gen = True
        return super().div(k)


class DistributionGenerator():
    # Return the Distribution obj by fitting data.
    @abstractmethod
    def fit(self, raw_data):
        pass

    # Generate the Distribution obj with DistributionFunction.
    @abstractmethod
    def gen(self, func):
        pass


class KDEGenerator(DistributionGenerator):
    def __init__(self) -> None:
        pass

    # return KernelDensityEstimation
    def fit(self, raw_data) -> KernelDensityEstimation:
        if raw_data is None:
            return None
        kde_func = gaussian_kde(raw_data)
        return self.gen(kde_func)

    # generate KernelDensityEstimation
    def gen(self, func) -> KernelDensityEstimation:
        return KernelDensityEstimation(func)


class ECDFGenerator(DistributionGenerator):
    def __init__(self) -> None:
        pass

    # return EmpiricalDistribution
    def fit(self, raw_data) -> EmpiricalDistribution:
        if raw_data is None:
            return None
        raw_data = np.sort(raw_data)
        ecdf_func = ECDF(raw_data)
        return self.gen(ecdf_func)

    # generate EmpiricalDistribution
    def gen(self, func) -> EmpiricalDistribution:
        return EmpiricalDistribution(func)

# A theory tool that helps to generate ExtremeDistribution object.


class EVT():
    # Confidence level for hypothesis test.
    # p_value < ConfidenceLevel means we can reject the null hypothesis.
    ConfidenceLevel = 0.05
    MIN_NDATA = 5

    def __init__(self) -> None:
        # A list saves extreme samples.
        self.ext_data = list()
        # Save error message.
        self.err_msg = str()
        self.threshold = None

    # Returns none if fit faled, otherwise returns an ExtremeDistribution object.
    @abstractmethod
    def fit(self, raw_data) -> ExtremeDistribution:
        # pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        return None

    @abstractmethod
    # Generate ExtremeDistribution object with params.
    def gen(self, params: dict) -> ExtremeDistribution:
        pass

    # Util.
    # Stationarity test for raw data.
    def kpss(self, raw_data: list):
        return stattools.kpss(raw_data)

    @staticmethod
    def passed_kpss(raw_data: list) -> bool:
        kps_result = stattools.kpss(raw_data)
        # print(f'KPSS test result: {kps_result}, type: {type(kps_result)}')
        return kps_result[1] > EVT.ConfidenceLevel

    # Independent and identically distributed test for raw data.
    def bds(self, raw_data: list):
        return stattools.bds(raw_data)

    @staticmethod
    def passed_bds(raw_data: list) -> bool:
        bds_result = stattools.bds(raw_data)
        # print(f'BDS test result: {bds_result}, type: {type(bds_result)}')
        return bds_result[1] > EVT.ConfidenceLevel

    # Long range dependence test.
    def lrd(self, raw_data: list):
        # TODO: fill this function.
        pass

    # Test for goodness of fit of a cumulative distribution function.
    def cvm(self, ext_data: list, ext_func):
        return cramervonmises(ext_data, ext_func.cdf)

    def passed_cvm(self, ext_data: list, ext_func) -> bool:
        return self.cvm(ext_data, ext_func)[1] > EVT.ConfidenceLevel

    @staticmethod
    def show_cvm(ext_data, ext_func, params) -> bool:
        result = cramervonmises(ext_data, ext_func.cdf, params)
        p_value = result.pvalue
        if p_value > EVT.ConfidenceLevel:
            # print(f"[INFO] p_value[{p_value}] > {EVT.ConfidenceLevel}, fit {len(ext_data)} samples succeed.")
            return True
        else:
            # print(f'[WARN] p_value[{p_value}] < {EVT.ConfidenceLevel}, try to get more than {len(ext_data)} samples.')
            return False

    def get_threshold(self, force=False):
        if self.threshold is None or force:
            self.threshold = np.min(self.ext_data) if len(
                self.ext_data) > 0 else None
        return self.threshold


class GEVGenerator(EVT):
    """Generate GEV distribution witl EVT tool."""
    MIN_NRSAMPLE = 2

    def __init__(self, **kwargs) -> None:
        super().__init__()
        self.fix_c = kwargs.get('fix_c', None)
        """Divide data into nr_sample blocks. Default is 2."""
        self.nr_sample = kwargs.get('nr_sample', GEVGenerator.MIN_NRSAMPLE)

    @staticmethod
    def BM(data: list, bs: int = 50) -> list:
        """
        Finds the maximum value in each block of data with a given block size.

        Args:
            data (list): The input data.
            bs (int): The block size.

        Returns:
            list: A list of maximum values in each block.
        """
        ext_vals, data_length = list(), len(data)
        for i in range(bs):
            s = i * int(data_length // bs)
            ext_vals.append(max(data[s: s + int(data_length // bs)]))
        return ext_vals

    def fit(self, raw_data: list, nr_sample: int = None, strict: bool = False) -> ExtremeDistribution:
        if nr_sample is not None:
            self.nr_sample = nr_sample
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < self.nr_sample:
            self.err_msg = "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg = "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        # Use BM to filter ext_data.
        max_bs = len(raw_data) // self.nr_sample
        # Divide {len(raw_data)} data into {self.nr_sample} blocks, max block size is {max_bs}.
        self.ext_data = GEVGenerator.BM(raw_data, max_bs)

        # TODO: pass test.

        # Fit args for evt class and build evt function.
        if self.fix_c is None:
            params = genextreme.fit(self.ext_data)
        else:
            params = genextreme.fit(self.ext_data, f0=self.fix_c)
            
        if not EVT.show_cvm(self.ext_data, genextreme, params):
            if strict:
                return None
        c, loc, scale = params
        return self.gen({ExtremeDistribution.PARAM_SHAPE: c, ExtremeDistribution.PARAM_LOC: loc, ExtremeDistribution.PARAM_SCALE: scale})

    def gen(self, params: dict) -> ExtremeDistribution:
        if not ExtremeDistribution.validparam(params):
            return None
        return GEV(params)


class GPDGenerator(EVT):
    """Generate GPD distribution witl EVT tool."""
    MIN_NRSAMPLE = 40
    FIT_STEP = 5

    def __init__(self, **kwargs) -> None:
        super().__init__()
        self.fix_c = kwargs.get('fix_c', None)
        self.pot_method = kwargs.get('pot_method', 'cluster')
        self.pot_arg = kwargs.get('pot_arg', None)
        self.nr_sample = kwargs.get('nr_sample', EVT.MIN_NDATA)
        self.subtract_threshold = kwargs.get('sub_thresh', False)

    @staticmethod
    def POT(data: list, pot_method: str = 'cluster', pot_arg=None):
        """
        Calculate Peaks-over-Threshold (POT) for a given dataset.

        Args:
            data (list): The input dataset.
            pot_method (str, optional): The method used to calculate the threshold. Defaults to 'cluster'.
            pot_arg (optional): Additional argument for the pot_method. Defaults to None.

        Returns:
            np.ndarray: The sorted array of extreme value data.
        """
        pot = DataFilter.PoT(data)
        threshold = pot.filter(pot_method, pot_arg)
        # threshold = pot.filter('percent')
        evt_data = [x for x in data if x >= threshold]
        # if len(evt_data) < 4:
        #     data = np.sort(data)
        #     evt_data = data[-4:]
        return np.sort(evt_data), threshold

    @staticmethod
    def fitGPD(ext_data, fix_c=None):
        # Fit args for evt class and build evt function.
        if fix_c is None:
            params = genpareto.fit(ext_data)
        else:
            params = genpareto.fit(ext_data, f0=fix_c)
        return params

    def fit(self, raw_data, strict: bool = False) -> ExtremeDistribution:
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < GPDGenerator.MIN_NRSAMPLE:
            self.err_msg += "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg += "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        self.ext_data, self.threshold = self.POT(
            raw_data, self.pot_method, self.pot_arg)
        # print(f'Use PoT method [{self.pot_method}] to get {len(self.ext_data)} samples from {len(raw_data)} samples.')
        step = GPDGenerator.FIT_STEP
        loops, params = int(len(self.ext_data) / step) + 1, None
        for _ in range(loops):
            if len(self.ext_data) < self.nr_sample:
                # Too less {len(self.ext_data)} samples. fit failed
                if strict:
                    return None
                break
            if self.subtract_threshold:
                # self.threshold = self.get_threshold(self.subtract_threshold)
                GPDdata = [x - self.threshold for x in self.ext_data]
            else:
                GPDdata = self.ext_data
            params = GPDGenerator.fitGPD(GPDdata, self.fix_c)
            if EVT.show_cvm(GPDdata, genpareto, params):
                break
            # pass test. Failed reduce EVT-data and re-fit.
            self.threshold = self.ext_data[step-1]
            self.ext_data = self.ext_data[step:]

        c, loc, scale = GPDGenerator.fitGPD(
            self.ext_data, self.fix_c) if params is None else params
        # print(f'c={c}, loc={loc}, scale={scale}\tparams={params}')
        return self.gen({ExtremeDistribution.PARAM_SHAPE: c, ExtremeDistribution.PARAM_LOC: loc, ExtremeDistribution.PARAM_SCALE: scale})

    def gen(self, params: dict) -> ExtremeDistribution:
        if not ExtremeDistribution.validparam(params):
            return None
        return GPD(params)


class GumbelGenerator(GEVGenerator):
    def __init__(self) -> None:
        super().__init__(fix_c=0)


class ExponentialParetoGenerator(GPDGenerator):
    def __init__(self) -> None:
        super().__init__(fix_c=0)


class MixedDistributionGenerator():
    """
    A class that generates mixed distributions using EVT (Extreme Value Theory) & KDE (Kernel Density Estimation),
    or only ECDF (Empirical Cumulative Distribution Function) methods.

    self.threshold = None : only ECDF
    self.threshold != None: EVT(tail) & KDE(kernel)
    """

    EVT_TYPE = {'GEV': GEVGenerator, 'GPD': GPDGenerator}

    def __init__(self, evt_type: str = 'GPD', **kwargs):
        """
        Initializes a MixedDistributionGenerator object.

        Parameters:
        - evt_type (str): The type of EVT distribution to use. Default is 'GPD'.
        - **kwargs: Additional keyword arguments to be passed to the EVT generator.

        """
        if 'sub_thresh' not in kwargs:
            kwargs['sub_thresh'] = True
        self.threshold = None
        self.gen_EVT = MixedDistributionGenerator.EVT_TYPE.get(
            evt_type, GPDGenerator)(**kwargs)
        self.gen_KDE = KDEGenerator()
        self.gen_ECDF = ECDFGenerator()

    def fit(self, raw_data) -> MixedDistribution:
        """
        Fits the mixed distribution to the given raw data.

        Parameters:
        - raw_data: The raw data to fit the distribution to.

        Returns:
        - MixedDistribution: The fitted mixed distribution.

        """
        # model_EVT, model_KDE, model_ECDF, mix_name = self.gen_EVT.fit(raw_data), None, self.gen_ECDF.fit(raw_data), '[Mixed only ECDF]'
        model_EVT, model_KDE, model_ECDF, mix_name = self.gen_EVT.fit(
            raw_data), self.gen_KDE.fit(raw_data), self.gen_ECDF.fit(raw_data), '[Mixed only KDE]'

        if model_EVT is not None:
            self.threshold = self.gen_EVT.get_threshold()
            # below_data = [x for x in raw_data if x < self.threshold]
            # model_KDE = self.gen_KDE.fit(below_data)
            mix_name = '[SPD]' if 'GPD' in model_EVT.getname(
            ) else '[Mixed GEV]'

        # params = dict(EVT=model_EVT, KDE=model_KDE, threshold=self.threshold, ECDF=model_ECDF, name=mix_name)
        params = dict(EVT=model_EVT, KDE=model_KDE,
                      threshold=self.threshold, ECDF=model_ECDF, name=mix_name)
        return self.gen(**params)

    def gen(self, **kwargs) -> MixedDistribution:
        """
        Generates a mixed distribution using the given parameters.

        Parameters:
        - **kwargs: The parameters for generating the mixed distribution.

        Returns:
        - MixedDistribution: The generated mixed distribution.

        """
        KDE = kwargs.get('KDE', None)
        if KDE is None:
            # fit failed.
            return None
        return MixedDistribution(**kwargs)
