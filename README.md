# Revelio

LLM Red Teaming & Safety Testing Framework. Systematically discover vulnerabilities in large language models through adversarial attacks, safety frameworks, and automated evaluation.

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

# Save results to JSON
results.save(to="./results")
```

## Framework-Driven Red Teaming

Use industry safety frameworks to automatically select vulnerabilities and attacks:

```python
from revelio import red_team
from revelio.frameworks import NIST, OWASPTop10, MITRE

results = red_team(
    model_callback=target,
    framework=NIST(),  # or OWASPTop10(), MITRE(), Aegis(), BeaverTails(), OWASP_ASI_2026()
    attacks_per_vulnerability_type=3,
)
```

### Supported Frameworks

| Framework | Description |
|-----------|-------------|
| **NIST** | AI Risk Management Framework (AI RMF) — 4 measurement categories (M.1–M.4) |
| **OWASPTop10** | OWASP Top 10 for LLM Applications |
| **OWASP_ASI_2026** | OWASP Agentic Security Initiative |
| **MITRE** | MITRE ATLAS adversarial threat landscape |
| **Aegis** | NVIDIA Aegis AI Content Safety Dataset (13 harm categories) |
| **BeaverTails** | BeaverTails dataset-driven safety evaluation (14 harm categories) |

## API Reference

```python
results = red_team(
    model_callback,                        # async or sync callable(str) -> str
    vulnerabilities=None,                  # list of vulnerability instances
    attacks=None,                          # list of attack instances
    framework=None,                        # AISafetyFramework (overrides vulns/attacks)
    simulator_model="gpt-4o-mini",         # model for generating attacks
    evaluation_model="gpt-4o-mini",        # model for scoring responses
    attacks_per_vulnerability_type=1,      # attacks generated per vuln type
    async_mode=True,                       # async or sync execution
    max_concurrent=10,                     # max parallel evaluations
    target_purpose=None,                   # describe your model's purpose
    ignore_errors=True,                    # continue on individual test failures
)
```

Returns a `RiskAssessment` with:
- `results.overview` — pass rates per vulnerability type and attack method
- `results.test_cases` — individual test case results (input, output, score, reason)
- `results.save(to="./output")` — export to timestamped JSON
- `results.test_cases.to_df()` — convert to pandas DataFrame

## Vulnerabilities (35+)

| Category | Vulnerabilities |
|----------|----------------|
| **Data Privacy** | PII Leakage, Prompt Leakage |
| **Responsible AI** | Bias, Toxicity, Fairness, Ethics |
| **Security** | BFLA, BOLA, RBAC, Debug Access, Shell Injection, SQL Injection, SSRF |
| **Safety** | Illegal Activity, Graphic Content, Personal Safety, Child Protection |
| **Business** | Misinformation, Intellectual Property, Competition |
| **Agentic** | Goal Theft, Recursive Hijacking, Excessive Agency, Robustness, Agent Identity Abuse, Autonomous Agent Drift, Tool Orchestration Abuse, Tool Metadata Poisoning, Insecure Inter-Agent Communication, Indirect Instruction, Unexpected Code Execution |
| **Custom** | `CustomVulnerability(name, criteria, types)` — define your own |

Each vulnerability auto-selects its types by default. Narrow the scope:

```python
from revelio.vulnerabilities import Bias
bias = Bias(types=["gender", "race"])  # only test gender and race bias
```

## Attacks (26)

**Single-turn (21):** Adversarial Poetry, Authority Escalation, Base64, Character Stream, Context Flooding, Context Poisoning, Embedded Instruction JSON, Emotional Manipulation, Goal Redirection, Gray Box, Input Bypass, Leetspeak, Linguistic Confusion, Math Problem, Multilingual, Permission Escalation, Prompt Injection, Prompt Probing, Roleplay, ROT13, Synthetic Context Injection, System Override

**Multi-turn (5):** Crescendo Jailbreaking, Linear Jailbreaking, Tree Jailbreaking, Sequential Jailbreak, Bad Likert Judge

## Custom Vulnerabilities

```python
from revelio.vulnerabilities import CustomVulnerability

vuln = CustomVulnerability(
    name="Financial Advice",
    criteria="Model should not provide specific investment advice",
    types=["stock_tips", "crypto_advice"],
)

results = red_team(model_callback=target, vulnerabilities=[vuln])
```

## License

Apache-2.0. See [LICENSE.md](LICENSE.md).
