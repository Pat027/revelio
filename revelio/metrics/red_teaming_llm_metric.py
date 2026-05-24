"""Shared base classes for red-teaming metrics.

Historically every metric (``BiasMetric``, ``ToxicityMetric``, ...) re-declared
an identical ``measure`` / ``a_measure`` / ``evaluate`` / ``_a_evaluate`` /
``generate_purpose`` / ``is_successful`` implementation — only the template
class, a display name, and a handful of constructor arguments differed.

``RedTeamingLLMMetric`` carries that shared logic; concrete metrics become thin
shells declaring class attributes:

* ``_template``        -- the per-metric ``*Template`` class (required)
* ``_display_name``    -- human name used by ``__name__`` (required)
* ``_category_param``  -- name of a category attribute passed to the eval
  template (e.g. ``"toxicity_category"``); ``None`` for metrics with no category
* ``_eval_uses_purpose`` -- whether ``purpose`` is forwarded to the eval template
* ``_measure_generates_purpose`` -- whether ``measure`` derives ``purpose`` from
  the system prompt before evaluating (RBAC / PII behaviour)

``EntityRedTeamingMetric`` adds the entity-extraction step used by BOLA, PII and
Imitation.
"""

from typing import Optional, Tuple, Union

from deepeval.metrics.indicator import metric_progress_indicator
from deepeval.metrics.utils import (
    construct_verbose_logs,
    initialize_model,
    trimAndLoadJson,
)
from deepeval.models import DeepEvalBaseLLM
from deepeval.utils import get_or_create_event_loop

from revelio.metrics.base_red_teaming_metric import BaseRedTeamingMetric
from revelio.metrics.schema import Entities, Purpose, ReasonScore
from revelio.test_case import RTTestCase
from revelio.utils import format_turns


class RedTeamingLLMMetric(BaseRedTeamingMetric):
    # --- subclass configuration -------------------------------------------
    _template = None
    _display_name: str = ""
    _category_param: Optional[str] = None
    _eval_uses_purpose: bool = True
    _eval_includes_input: bool = True
    _measure_generates_purpose: bool = False

    # --- construction ------------------------------------------------------
    def __init__(
        self,
        purpose: Optional[str] = None,
        model: Optional[Union[str, DeepEvalBaseLLM]] = None,
        async_mode: bool = True,
        verbose_mode: bool = False,
    ):
        self.purpose = purpose
        self._init_model(model, async_mode, verbose_mode)

    def _init_model(self, model, async_mode, verbose_mode):
        """Shared constructor tail: model init + system prompt extraction."""
        self.model, self.using_native_model = initialize_model(model)
        self.evaluation_model = self.model.get_model_name()
        self.async_mode = async_mode
        self.verbose_mode = verbose_mode
        try:
            self.system_prompt = model.get_system_prompt()
        except Exception:
            self.system_prompt = ""

    # --- measurement -------------------------------------------------------
    def measure(self, test_case: RTTestCase) -> float:
        self.evaluation_cost = 0 if self.using_native_model else None
        with metric_progress_indicator(self, _show_indicator=False):
            if self.async_mode:
                loop = get_or_create_event_loop()
                loop.run_until_complete(
                    self.a_measure(test_case, _show_indicator=False)
                )
            else:
                prefix = self._prepare_measurement()
                score, reason = self.evaluate(test_case)
                self.reason = reason
                self.score = score
                self.success = self.score == 1
                self.verbose_logs = construct_verbose_logs(
                    self,
                    steps=[
                        f"{prefix}Score: {self.score}\nReason: {self.reason}"
                    ],
                )
                return self.score

    async def a_measure(
        self,
        test_case: RTTestCase,
        _show_indicator: bool = False,
    ) -> float:
        self.evaluation_cost = 0 if self.using_native_model else None
        with metric_progress_indicator(
            self, async_mode=True, _show_indicator=_show_indicator
        ):
            prefix = await self._a_prepare_measurement()
            score, reason = await self._a_evaluate(test_case)
            self.reason = reason
            self.score = score
            self.success = self.score == 1
            self.verbose_logs = construct_verbose_logs(
                self,
                steps=[f"{prefix}Score: {self.score}\nReason: {self.reason}"],
            )
            return self.score

    def _prepare_measurement(self) -> str:
        """Populate derived attributes before ``evaluate``; return a verbose
        log prefix. Default: optionally derive ``purpose`` (RBAC behaviour)."""
        if self._measure_generates_purpose:
            self.purpose = self.generate_purpose()
        return ""

    async def _a_prepare_measurement(self) -> str:
        if self._measure_generates_purpose:
            self.purpose = await self.a_generate_purpose()
        return ""

    # --- evaluation --------------------------------------------------------
    def _eval_template_kwargs(self, test_case: RTTestCase) -> dict:
        """Keyword arguments forwarded to ``generate_evaluation_results``."""
        kwargs: dict = {"actual_output": self._actual_output(test_case)}
        if self._eval_includes_input:
            kwargs["input"] = test_case.input
        if self._category_param:
            kwargs[self._category_param] = getattr(self, self._category_param)
        if self._eval_uses_purpose:
            kwargs["purpose"] = self.purpose
        return kwargs

    @staticmethod
    def _actual_output(test_case: RTTestCase) -> str:
        if test_case.turns is not None:
            return format_turns(test_case.turns)
        return (
            "AI'S ACTUAL OUTPUT TO EVALUATE: \n"
            + test_case.actual_output
            + "\n"
        )

    async def _a_evaluate(
        self, test_case: RTTestCase
    ) -> Tuple[Union[int, float], str]:
        prompt = self._template.generate_evaluation_results(
            **self._eval_template_kwargs(test_case)
        )
        if self.using_native_model:
            res, cost = await self.model.a_generate(
                prompt=prompt, schema=ReasonScore
            )
            self.evaluation_cost += cost
            return res.score, res.reason
        try:
            res: ReasonScore = await self.model.a_generate(
                prompt=prompt, schema=ReasonScore
            )
            return res.score, res.reason
        except TypeError:
            res = await self.model.a_generate(prompt)
            data = trimAndLoadJson(res, self)
            return data["score"], data["reason"]

    def evaluate(self, test_case: RTTestCase) -> Tuple[Union[int, float], str]:
        prompt = self._template.generate_evaluation_results(
            **self._eval_template_kwargs(test_case)
        )
        if self.using_native_model:
            res, cost = self.model.generate(prompt=prompt, schema=ReasonScore)
            self.evaluation_cost += cost
            return res.score, res.reason
        try:
            res: ReasonScore = self.model.generate(
                prompt=prompt, schema=ReasonScore
            )
            return res.score, res.reason
        except TypeError:
            res = self.model.generate(prompt)
            data = trimAndLoadJson(res, self)
            return data["score"], data["reason"]

    # --- purpose extraction ------------------------------------------------
    async def a_generate_purpose(self):
        if self.purpose is not None:
            return self.purpose
        prompt = self._template.extract_purpose(self.system_prompt)
        if self.using_native_model:
            res, cost = await self.model.a_generate(
                prompt=prompt, schema=Purpose
            )
            self.evaluation_cost += cost
            return res.purpose
        try:
            res: Purpose = await self.model.a_generate(
                prompt=prompt, schema=Purpose
            )
            return res.purpose
        except TypeError:
            res = await self.model.a_generate(prompt)
            data = trimAndLoadJson(res, self)
            return data["purpose"]

    def generate_purpose(self):
        if self.purpose is not None:
            return self.purpose
        prompt = self._template.extract_purpose(self.system_prompt)
        if self.using_native_model:
            res, cost = self.model.generate(prompt=prompt, schema=Purpose)
            self.evaluation_cost += cost
            return res.purpose
        try:
            res: Purpose = self.model.generate(prompt=prompt, schema=Purpose)
            return res.purpose
        except TypeError:
            res = self.model.generate(prompt)
            data = trimAndLoadJson(res, self)
            return data["purpose"]

    # --- status ------------------------------------------------------------
    def is_successful(self) -> bool:
        if self.error is not None:
            self.success = False
        else:
            try:
                self.score == 1
            except Exception:
                self.success = False
        return self.success

    @property
    def __name__(self):
        return f"{self._display_name} (Red Teaming)"


class EntityRedTeamingMetric(RedTeamingLLMMetric):
    """Metrics that extract named entities from the system prompt before
    evaluating (BOLA, PII, Imitation)."""

    def _prepare_measurement(self) -> str:
        prefix = super()._prepare_measurement()
        if self._measure_generates_purpose:
            prefix += f"Purpose: {self.purpose}\n"
        self.entities = self.generate_entities()
        return prefix + f"Entities: {self.entities}\n"

    async def _a_prepare_measurement(self) -> str:
        prefix = await super()._a_prepare_measurement()
        if self._measure_generates_purpose:
            prefix += f"Purpose: {self.purpose}\n"
        self.entities = await self.a_generate_entities()
        return prefix + f"Entities: {self.entities}\n"

    def _eval_template_kwargs(self, test_case: RTTestCase) -> dict:
        kwargs = super()._eval_template_kwargs(test_case)
        kwargs["entities"] = self.entities
        return kwargs

    async def a_generate_entities(self):
        prompt = self._template.extract_entities(self.system_prompt)
        if self.using_native_model:
            res, cost = await self.model.a_generate(
                prompt=prompt, schema=Entities
            )
            self.evaluation_cost += cost
            return res.entities
        try:
            res: Entities = await self.model.a_generate(
                prompt=prompt, schema=Entities
            )
            return res.entities
        except TypeError:
            res = await self.model.a_generate(prompt)
            data = trimAndLoadJson(res, self)
            return data["entities"]

    def generate_entities(self):
        prompt = self._template.extract_entities(self.system_prompt)
        if self.using_native_model:
            res, cost = self.model.generate(prompt=prompt, schema=Entities)
            self.evaluation_cost += cost
            return res.entities
        try:
            res: Entities = self.model.generate(prompt=prompt, schema=Entities)
            return res.entities
        except TypeError:
            res = self.model.generate(prompt)
            data = trimAndLoadJson(res, self)
            return data["entities"]
