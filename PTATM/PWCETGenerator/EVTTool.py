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
    def name(self) -> str:
        return self.name


class KernelDensityEstimation(PWCETInterface):
    def __init__(self, kde_func):
        super().__init__()
        self.kde_func = kde_func
        self.cdf_values = self.cdfs()
        self.name = '[KDE]'

    def isf(self, exceed_prob: float, samples: int = None) -> float:
        if samples is None:
            samples = len(self.kde_func.dataset)*2

        x = np.linspace(np.min(self.kde_func.dataset), np.max(self.kde_func.dataset), samples)
        inversefunction = interpolate.interp1d(self.cdf_values, x, kind='cubic', bounds_error=False)
        return inversefunction(1 - exceed_prob)

    def expression(self) -> str:
        return f"Kernel Density Estimation"

    def copy(self):
        return KernelDensityEstimation(self.kde_func)

    def pdf(self, x):
        return self.kde_func.evaluate(x)

    def cdfs(self, samples: int = None):
        if samples is None:
            samples = len(self.kde_func.dataset)*2
        x = np.linspace(np.min(self.kde_func.dataset), np.max(self.kde_func.dataset), samples)
        cdf_values = tuple(ndtr(np.ravel(item - self.kde_func.dataset) / self.kde_func.factor).mean()
                           for item in x)
        return cdf_values

    def cdf(self, x):
        return ndtr(np.ravel(x - self.kde_func.dataset) / self.kde_func.factor).mean()

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
        self.threshold = kwargs.get('threshold', None)
        self.ECDFmodel = kwargs.get('ECDF', None)
        self.name = '[Mixed]'

    def isf(self, exceed_prob: float) -> float:
        if self.threshold is None:
            return self.ECDFmodel.isf(exceed_prob)
        else:
            # TODO: Return isf for different distributions selected according to the thresholds
            return max(self.KDEmodel.isf(exceed_prob), self.EVTmodel.isf(exceed_prob))

    def expression(self) -> str:
        if self.threshold is None:
            return f"****** Mixed Distribution ******\n{self.ECDFmodel.expression()}"
        else:
            return f"****** Mixed Distribution ******\nThreshold: {self.threshold}\n{self.KDEmodel.expression()}\n{self.EVTmodel.expression()}"

    def copy(self):
        return MixedDistribution(self.EVTmodel.copy(), self.KDEmodel.copy(), self.threshold, self.ECDFmodel.copy())

    def getCDF(self):
        if self.threshold is None:
            return self.ECDFmodel.getCDF()

        class Mixed(rv_discrete):
            def _pmf(self, x):
                return np.where(x > self.threshold, self.EVTmodel.getCDF()._pmf(x), self.KDEmodel.getCDF()._pmf(x))
        return Mixed(name='SPD')

    def cdf(self, x):
        if self.threshold is None:
            return self.ECDFmodel.cdf(x)
        elif x >= self.threshold:
            return self.EVTmodel.cdf(x)
        else:
            return self.KDEmodel.cdf(x)


class LinearCombinedExtremeDistribution(PWCETInterface):
    def __init__(self) -> None:
        super.__init__()
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

    def get_threshold(self):
        return np.min(self.ext_data) if len(self.ext_data) > 0 else None


class GEVGenerator(EVT):
    """Generate GEV distribution witl EVT tool."""
    MIN_NRSAMPLE = 2

    def __init__(self, **kwargs) -> None:
        super().__init__()
        self.fix_c = kwargs.get('fix_c', None)

    @staticmethod
    def BM(data: list, bs: int) -> list:
        ext_vals, nr_sample = list(), len(data)
        for i in range(nr_sample//bs + 1):
            s = i * bs
            e = s + bs
            if s >= nr_sample:
                break
            ext_vals.append(max(data[s:] if e > nr_sample else data[s:e]))
        return ext_vals

    def fit(self, raw_data: list, nr_sample: int = MIN_NRSAMPLE) -> ExtremeDistribution:
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < nr_sample:
            self.err_msg = "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg = "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        # Use BM to filter ext_data.
        max_bs = len(raw_data) // nr_sample
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


class GPDGenerator(EVT):
    """Generate GPD distribution witl EVT tool."""
    MIN_NRSAMPLE = 1

    def __init__(self, **kwargs) -> None:
        super().__init__()
        self.fix_c = kwargs.get('fix_c', None)
        self.pot_method = kwargs.get('pot_method', 'cluster')
        self.pot_arg = kwargs.get('pot_arg', None)

    # return list: PoT data
    @staticmethod
    def POT(data: list, pot_method: str = 'cluster', pot_arg=None):
        data = np.sort(data)
        pot = DataFilter.PoT(data)
        threshold = pot.filter(pot_method, pot_arg)
        evt_data = [x for x in data if x >= threshold]
        if len(evt_data) < 4:
                evt_data = data[-4:]
        return np.sort(evt_data)

    def fit(self, raw_data) -> ExtremeDistribution:
        # Pick raw samples until we pass kpss,bds,lrd test -> pick extreme value & EVT fit until we pass cvm test.
        if len(raw_data) < GPDGenerator.MIN_NRSAMPLE:
            self.err_msg += "Too few samples[%d] to fit.\n" % len(raw_data)
            return None
        if max(raw_data) <= 0:
            self.err_msg += "Max(raw_data)[%f]<=0.\n" % max(raw_data)
            return None

        self.ext_data = self.POT(raw_data, self.pot_method, self.pot_arg)
        # print(f"get {len(self.ext_data)} samples from {len(raw_data)} samples.")
        step = 5
        loops = int(len(self.ext_data) / step)
        for i in range(loops):
            if len(self.ext_data) < 4:
                # print(f"Too less {len(self.ext_data)} samples.")
                break
            # TODO: pass test. Failed return None.

            # Fit args for evt class and build evt function.
            if self.fix_c is None:
                params = genpareto.fit(self.ext_data)
            else:
                params = genpareto.fit(self.ext_data, f0=self.fix_c)

            _, p_value = kstest(self.ext_data, 'genpareto', args=params)
            if p_value > EVT.ConfidenceLevel:
                # print(f"using GPD fit {len(self.ext_data)} samples from {len(raw_data)} data succeed.")
                break
            self.ext_data = self.ext_data[step:]

        c, loc, scale = params
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
        self.threshold = None
        self.gen_EVT = MixedDistributionGenerator.EVT_TYPE.get(evt_type, GPDGenerator)(**kwargs)
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
        model_EVT, model_KDE, model_ECDF = self.gen_EVT.fit(raw_data), None, self.gen_ECDF.fit(raw_data)

        if model_EVT is not None:
            self.threshold = self.gen_EVT.get_threshold()
            below_data = [x for x in raw_data if x < self.threshold]
            model_KDE = self.gen_KDE.fit(below_data)

        params = dict(EVT=model_EVT, KDE=model_KDE, threshold=self.threshold, ECDF=model_ECDF)
        return self.gen(**params)

    def gen(self, **kwargs) -> MixedDistribution:
        """
        Generates a mixed distribution using the given parameters.

        Parameters:
        - **kwargs: The parameters for generating the mixed distribution.

        Returns:
        - MixedDistribution: The generated mixed distribution.

        """
        ECDF = kwargs.get('ECDF', None)
        if ECDF is None:
            return None
        return MixedDistribution(**kwargs)
