# Revelio

LLM Red Teaming & Safety Testing Framework. Systematically discover vulnerabilities in large language models through adversarial attacks and automated evaluation.

## Install

```bash
pip install revelio
```

## Quick Start

```python
from revelio import red_team
from revelio.vulnerabilities import Bias, Toxicity, SQLInjection
from revelio.attacks.single_turn import PromptInjection, Roleplay
from revelio.attacks.multi_turn import LinearJailbreaking

async def target(input: str) -> str:
    # Your LLM call here
    return "model response"

results = red_team(
    model_callback=target,
    vulnerabilities=[Bias(), Toxicity(), SQLInjection()],
    attacks=[PromptInjection(), Roleplay(), LinearJailbreaking()],
)
```

## CLI

```bash
revelio run config.yaml
revelio run config.yaml --attacks-per-vuln 5 --max-concurrent 20
```

## Vulnerabilities (35+)

| Category | Vulnerabilities |
|----------|----------------|
| **Data Privacy** | PII Leakage, Prompt Leakage |
| **Responsible AI** | Bias, Toxicity, Fairness, Ethics |
| **Security** | BFLA, BOLA, RBAC, Debug Access, Shell Injection, SQL Injection, SSRF |
| **Safety** | Illegal Activity, Graphic Content, Personal Safety, Child Protection |
| **Business** | Misinformation, Intellectual Property, Competition |
| **Agentic** | Goal Theft, Recursive Hijacking, Excessive Agency, Robustness, Agent Identity Abuse, Autonomous Agent Drift, Tool Orchestration Abuse, Tool Metadata Poisoning, Insecure Inter-Agent Communication, Indirect Instruction, Unexpected Code Execution |
| **Custom** | Define your own vulnerability criteria |

## Attacks (25+)

**Single-turn**: Base64, Gray Box, Leetspeak, Math Problem, Multilingual, Prompt Injection, Prompt Probing, Roleplay, ROT13, Adversarial Poetry, Authority Escalation, Character Stream, Context Flooding, Context Poisoning, Embedded Instruction JSON, Emotional Manipulation, Goal Redirection, Input Bypass, Permission Escalation, Semantic Manipulation, Synthetic Context Injection, System Override

**Multi-turn**: Crescendo Jailbreaking, Linear Jailbreaking, Tree Jailbreaking, Sequential Jailbreak, Bad Likert Judge

## Guardrails

```python
from revelio import Guardrails

guard = Guardrails(vulnerabilities=[Bias(), Toxicity()])
result = guard.guard(input="user prompt", response="model response")
```

## License

Apache-2.0. See [LICENSE.md](LICENSE.md).
