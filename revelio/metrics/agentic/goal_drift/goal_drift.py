from revelio.metrics.red_teaming_llm_metric import RedTeamingLLMMetric
from revelio.metrics.agentic.goal_drift.template import GoalDriftTemplate


class GoalDriftMetric(RedTeamingLLMMetric):
    _template = GoalDriftTemplate
    _display_name = "Goal Drift"
