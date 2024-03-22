from scipy import interpolate
import statsmodels.tsa.stattools as stattools
from abc import abstractmethod
import numpy as np
from scipy.stats import gamma, genpareto, genextreme, rv_discrete, gaussian_kde, cramervonmises
from scipy.special import ndtr
from statsmodels.distributions.empirical_distribution import ECDF
from typing import Union


# We can generate a pwcet estimate/plot from a PWCETInterface.
class PWCETInterface:
    def __init__(self, name: str = "") -> None:
        self.name = name

    # Return a value with exceedance probability(exceed_prob).
    @abstractmethod
    def isf(self, exceed_prob: float) -> float:
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
    def name(self) -> str:
        return self.name


class KernelDensityEstimation(PWCETInterface):
    def __init__(self, kde_func, name: str = None):
        super().__init__(name)
        self.kde_func = kde_func
        self.name += '[KDE]'

    def isf(self, exceed_prob: float) -> float:
        x = self.kde_func.dataset
        cdf_values = self.cdf(x)
        # Interpolate to get inverse CDF
        inversefunction = interpolate.interp1d(cdf_values, x, kind='cubic', bounds_error=False)
        return inversefunction(1 - exceed_prob)

    def expression(self) -> str:
        return f"Kernel Density Estimation: x={self.kde_func.dataset}, y={self.kde_func.density}"

    def copy(self):
        return KernelDensityEstimation(self.kde_func)

    def pdf(self, x):
        return self.kde_func.evaluate(x)

    def cdf(self, x):
        return tuple(ndtr(np.ravel(item - self.kde_func.dataset) / self.kde_func.factor).mean()
                     for item in x)

    def getCDF(self):
        class KDERT(rv_discrete):
            def _pmf(self, x):
                return self.kde_func.evaluate(x)
        return KDERT(name='KDERT')


class EmpiricalDistribution(PWCETInterface):
    def __init__(self, ecdf_func, name: str = None):
        super().__init__(name)
        self.ecdf_func = ecdf_func
        self.name += '[ECDF]'

    def isf(self, exceed_prob: float) -> float:
        return self.ecdf_func.x[np.argmax(self.ecdf_func.y >= 1 - exceed_prob)]

    def expression(self) -> str:
        return f"Empirical Distribution: x={self.ecdf_func.x}, y={self.ecdf_func.y}"

    def copy(self):
        return EmpiricalDistribution(self.ecdf_func)

    def cdf(self, x):
        return self.ecdf_func(x)

    def getCDF(self):
        return rv_discrete(name='EmpiricalDistribution', values=(self.ecdf_func.x, self.ecdf_func.y))


class ExtremeDistribution(PWCETInterface):
    PARAM_SHAPE = "c"
    PARAM_LOC = "loc"
    PARAM_SCALE = "scale"

    @staticmethod
    def validparam(params: dict) -> bool:
        return ExtremeDistribution.PARAM_SHAPE in params and ExtremeDistribution.PARAM_LOC in params and ExtremeDistribution.PARAM_SCALE in params

    def __init__(self, ext_class, params: dict, name: str = None) -> None:
        super().__init__(name)
        # Here ext_class is original generator from scipy.stat.
        self.ext_class = ext_class
        self.name += '[EVT]'
        # Here ext_func is original extreme distribution object from scipy.stat
        self.gen(params)

    def isf(self, exceed_prob: float) -> float:
        return self.ext_func.isf(exceed_prob)

    def expression(self) -> str:
        kwds = self.ext_func.kwds
        return "(%s=%s, %s=%s, %s=%s)" % (ExtremeDistribution.PARAM_SHAPE, str(round(kwds[ExtremeDistribution.PARAM_SHAPE], 4)),
                                          ExtremeDistribution.PARAM_LOC, str(
                                              round(kwds[ExtremeDistribution.PARAM_LOC], 4)),
                                          ExtremeDistribution.PARAM_SCALE, str(round(kwds[ExtremeDistribution.PARAM_SCALE], 4)))

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
    def __init__(self, params: dict, name: str = None) -> None:
        super().__init__(genextreme, params, name)
        self.name += '[GEV]'

    def expression(self) -> str:
        return "GEV" + super().expression()

    def copy(self):
        return GEV(self.kwds())


class GPD(ExtremeDistribution):
    def __init__(self, params: dict, name: str = None) -> None:
        super().__init__(genpareto, params, name)
        self.name += '[GPD]'

    def expression(self) -> str:
        return "GPD" + super().expression()

    def copy(self):
        return GPD(self.kwds())


class MixedDistribution(PWCETInterface):
    def __init__(self, EVT: ExtremeDistribution, KDE: KernelDensityEstimation, threshold: float = None, ECDF: EmpiricalDistribution = None, name: str = None):
        super().__init__(name)
        self.evt = EVT
        self.kde = KDE
        self.threshold = threshold
        self.ecdf = ECDF
        self.name += '[Mixed]'

    def isf(self, exceed_prob: float) -> float:
        if self.threshold is None:
            return self.ecdf.isf(exceed_prob)
        else:
            # TODO: Return isf for different distributions selected according to the thresholds
            return max(self.kde.isf(exceed_prob) ,self.evt.isf(exceed_prob))

    def expression(self) -> str:
        if self.threshold is None:
            return f"****** Mixed Distribution ******\n{self.ecdf.expression()}"
        else:
            return f"****** Mixed Distribution ******\nThreshold: {self.threshold}\n{self.kde.expression()}\n{self.evt.expression()}"

    def copy(self):
        return MixedDistribution(self.evt.copy(), self.kde.copy(), self.threshold, self.ecdf.copy())

    def getCDF(self):
        if self.threshold is None:
            return self.ecdf.getCDF()

        class Mixed(rv_discrete):
            def _pmf(self, x):
                return np.where(x > self.threshold, self.evt.getCDF()._pmf(x), self.kde.getCDF()._pmf(x))
        return Mixed(name='SPD')

    def cdf(self, x):
        if self.threshold is None:
            return self.ecdf.cdf(x)
        return np.where(x > self.threshold, self.evt.cdf(x), self.kde.cdf(x))


class LinearCombinedExtremeDistribution(PWCETInterface):
    def __init__(self, name: str = None) -> None:
        super.__init__(name)
        # A dict maps extd function(ExtremeDistribution object) to it's weight.
        self.weighted_extdfunc = dict()
        self.name += '[LinearCombined]'

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
    def __init__(self, name: str = None) -> None:
        super().__init__(name)
        self.name += '[PositiveLinearGumbel]'

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
    def __init__(self, name: str = None) -> None:
        super().__init__(name)
        # Attributes works for isf according to self.weighted_evtfunc.
        # Those attrs should be re-generate if self.weighted_evtfunc is changed.
        self.gamma_func = None
        self.sum_loc = None
        self.max_scale = None
        self.should_gen = True
        self.name += '[PositiveLinearExponentialPareto]'

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
            self.max_scale = max(self.max_scale, weight * kwds[ExtremeDistribution.PARAM_SCALE])
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
    def fit(self, raw_data: list):
        pass

    # Generate the Distribution obj with DistributionFunction.
    @abstractmethod
    def gen(self, func):
        pass


class KDEGenerator(DistributionGenerator):
    def __init__(self) -> None:
        pass

    # return KernelDensityEstimation
    def fit(self, raw_data: list) -> KernelDensityEstimation:
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
    def fit(self, raw_data: list) -> EmpiricalDistribution:
        if raw_data is None:
            return None
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

    def __init__(self) -> None:
        # A list saves extreme samples.
        self.ext_data = list()
        # Save error message.
        self.err_msg = str()

    # Returns none if fit faled, otherwise returns an ExtremeDistribution object.
    @abstractmethod
    def fit(self, raw_data: list) -> ExtremeDistribution:
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

    def passed_kpss(self, raw_data: list) -> bool:
        return self.kpss(raw_data)[1] > EVT.ConfidenceLevel

    # Independent and identically distributed test for raw data.
    def bds(self, raw_data: list):
        return stattools.bds(raw_data)

    def passed_bds(self, raw_data: list) -> bool:
        return self.bds(raw_data)[1] > EVT.ConfidenceLevel

    # Long range dependence test.
    def lrd(self, raw_data: list):
        # TODO: fill this function.
        pass

    # Test for goodness of fit of a cumulative distribution function.
    def cvm(self, ext_data: list, ext_func):
        return cramervonmises(ext_data, ext_func.cdf)

    def passed_cvm(self, ext_data: list, ext_func) -> bool:
        return self.cvm(ext_data, ext_func)[1] > EVT.ConfidenceLevel

# Generate GEV distribution witl EVT tool.


class GEVGenerator(EVT):
    MIN_NRSAMPLE = 2

    def __init__(self, fix_c=None) -> None:
        super().__init__()
        self.fix_c = fix_c

    @staticmethod
    def BM(data: list, bs: int, filter: int = MIN_NRSAMPLE) -> list:
        ext_vals, nr_sample = list(), len(data)
        for i in range(nr_sample//bs + 1):
            s = i * bs
            e = s + bs
            if s >= nr_sample:
                break
            ext_vals.append(max(data[s:] if e > nr_sample else data[s:e]))
        return ext_vals

    def fit(self, raw_data: list) -> ExtremeDistribution:
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < filter:
            self.err_msg = "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg = "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        # Use BM to filter ext_data.
        max_bs = len(raw_data) // filter
        self.ext_data = GEVGenerator.BM(raw_data, max_bs)

        # TODO: pass test.

        # Fit args for evt class and build evt function.
        if self.fix_c is None:
            c, loc, scale = genextreme.fit(self.ext_data)
        else:
            c, loc, scale = genextreme.fit(self.ext_data, f0=self.fix_c)
        return self.gen({ExtremeDistribution.PARAM_SHAPE: c, ExtremeDistribution.PARAM_LOC: loc, ExtremeDistribution.PARAM_SCALE: scale})

    def gen(self, params: dict) -> ExtremeDistribution:
        if not ExtremeDistribution.validparam(params):
            return None
        return GEV(params)

# Generate GPD distribution witl EVT tool.


class GPDGenerator(EVT):
    MIN_NRSAMPLE = 1

    def __init__(self, fix_c=None, filter: Union[int, float] = 4) -> None:
        super().__init__()
        self.fix_c = fix_c
        self.filter = filter

    # return 2 list: PoT data & rest data
    @staticmethod
    def POT(data: list, nr_ext: Union[int, float] = 4):
        nr_sample = len(data)
        if nr_ext < 0 or nr_ext >= nr_sample:
            return data[:], None
        filter_data = data.copy()
        filter_data.sort()
        # if type(nr_ext) is int, choos max nr_ext
        if isinstance(nr_ext, int):
            return filter_data[-nr_ext:], filter_data[:-nr_ext]
        elif isinstance(nr_ext, float):
            if nr_ext < 1.0:
                # choose max nr_sample * nr_ext
                threshold = int(nr_sample * nr_ext)
                return filter_data[threshold:], filter_data[:threshold]
        else:
            return data[:], None

    def fit(self, raw_data: list) -> ExtremeDistribution:
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < GPDGenerator.MIN_NRSAMPLE:
            self.err_msg += "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg += "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        # Use POT to filter ext_data.
        self.ext_data, _ = GPDGenerator.POT(raw_data, self.filter)

        # TODO: pass test. Failed return None.

        # Fit args for evt class and build evt function.
        if self.fix_c is None:
            c, loc, scale = genpareto.fit(self.ext_data)
        else:
            c, loc, scale = genpareto.fit(self.ext_data, f0=self.fix_c)
        return self.gen({ExtremeDistribution.PARAM_SHAPE: c, ExtremeDistribution.PARAM_LOC: loc, ExtremeDistribution.PARAM_SCALE: scale})

    def gen(self, params: dict) -> ExtremeDistribution:
        if not ExtremeDistribution.validparam(params):
            return None
        return GPD(params)


class GumbelGenerator(GEVGenerator):
    def __init__(self) -> None:
        super().__init__(0)


class ExponentialParetoGenerator(GPDGenerator):
    def __init__(self) -> None:
        super().__init__(0)


class MixedDistributionGenerator():
    EVT_TYPE = {'GEV': GEVGenerator, 'GPD': GPDGenerator}

    def __init__(self, evt_type: str = 'GPD', filter: Union[int, float] = 4):
        self.threshold = None
        self.filter = filter

    # Fit GPD and KDE.
    # TODO: Fit GEV and KDE.
    def fit(self, raw_data: list) -> MixedDistribution:
        gpdgen, kdegen, ecdfgen = GPDGenerator(filter=self.filter), KDEGenerator(), ECDFGenerator()
        gpd = gpdgen.fit(raw_data)
        if gpd is None:
            # use ECDF fit all data.  MixedDistribution: None None None ECDF
            kde = None
            ecdf = ecdfgen.fit(raw_data)
        else:
            gpd_data, ecdf_data = GPDGenerator.POT(raw_data, self.filter)
            self.threshold = gpd_data[0]
            # use KDE fit rest data. MixedDistribution: gpd KDE self.threshold None
            kde = kdegen.fit(ecdf_data)
            ecdf = None
            # TODO: if KDE fit not good， use ECDF to fit all data

        return self.gen(gpd, kde, self.threshold, ecdf)

    def gen(self, EVT: ExtremeDistribution, KDE: KernelDensityEstimation, threshold: float = None, ECDF: EmpiricalDistribution = None) -> MixedDistribution:
        if EVT is None and ECDF is None:
            return None
        return MixedDistribution(EVT, KDE, threshold, ECDF)
