# Risk Scoring Methodology

## Overview

Sentinel's risk scoring engine quantifies the actual risk a vulnerability poses to a specific project by incorporating dependency graph topology into the calculation. This goes beyond raw CVSS scores, which only measure the vulnerability's intrinsic severity without considering how it reaches your application.

## The Problem with CVSS Alone

Consider a vulnerability with CVSS 7.5 (HIGH). Is it equally dangerous in these two scenarios?

| Scenario | CVSS | Depth | Transitive Paths |
|----------|:----:|:-----:|:----------------:|
| Direct dependency of your app | 7.5 | 1 | 1 |
| 4 levels deep, reachable via 12 paths | 7.5 | 4 | 12 |

CVSS says yes — both are "7.5 HIGH". But in practice, the second scenario is far more concerning because:
- **12 paths** means 12 different ways the vulnerability could be triggered
- Even at depth 4, the **attack surface is amplified** by the fan-out topology
- Patching requires updating multiple dependency chains

Sentinel captures this with a multi-factor scoring model.

---

## Scoring Formula

```
RiskScore = CVSS × DepthDecay × FanOutBoost × FreshnessDecay × DirectBoost
```

The final score is clamped to the range [0, 10].

---

## Factor Breakdown

### 1. CVSS Base Score (0–10)

The raw CVSS v3.1 score from NVD, OSV, or GitHub Advisory. This serves as the foundation — all other factors modulate it.

### 2. Depth Decay

```
DepthDecay = 1 / (1 + 0.3 × depth)
```

| Depth | Factor | Intuition |
|:-----:|:------:|-----------|
| 1 (direct) | 0.77 | High risk — one hop away |
| 2 | 0.63 | Moderate — requires transitive exploitation |
| 3 | 0.53 | Lower — attacker needs multi-step chain |
| 5 | 0.40 | Diminished — deeply buried |
| 10 | 0.25 | Minimal — extremely unlikely exploitation path |

**Why not zero at high depth?** Even deeply nested vulnerabilities can be exploited if the code path is reachable. The decay is asymptotic, never reaching zero.

### 3. Fan-Out Boost

```
FanOutBoost = 1 + log₂(pathCount)
```

| Paths | Factor | Intuition |
|:-----:|:------:|-----------|
| 1 | 1.0 | Baseline — single dependency chain |
| 2 | 2.0 | Double exposure |
| 4 | 3.0 | Significant amplification |
| 8 | 4.0 | Major concern — widespread reach |
| 16 | 5.0 | Critical amplifier — dominates the graph |

**This is Sentinel's most distinctive factor.** A moderate CVE reachable via 16 paths is more dangerous than a critical CVE behind a single path. Traditional tools completely miss this pattern.

### 4. Freshness Decay

```
FreshnessDecay = e^(-0.001 × daysSincePublished)
```

| Age | Factor | Intuition |
|-----|:------:|-----------|
| Just disclosed | 1.0 | Maximum urgency |
| 30 days | 0.97 | Still urgent |
| 180 days | 0.84 | Moderate urgency |
| 1 year | 0.69 | Reduced — likely already patched |
| 2 years | 0.48 | Low — well-known, mitigations exist |

**Purpose:** Recent disclosures warrant immediate attention. Older vulnerabilities have had time for patches, mitigations, and community response.

### 5. Direct Boost

```
DirectBoost = 1.5  (if direct dependency)
DirectBoost = 1.0  (if transitive)
```

Direct dependencies are explicitly chosen by the project. A vulnerability in a direct dependency is more likely to be in the critical code path, and patching is straightforward (upgrade the dependency).

---

## Worked Example

### Log4Shell (CVE-2021-44228) in `payment-api`

```
CVSS:         10.0  (Critical — remote code execution)
Depth:        1     (log4j-core is a direct dependency)
Path count:   1     (single dependency chain)
Published:    2021-12-10 (assume ~1500 days ago)
Direct:       No    (in GraphBuilder, only root is "direct")
```

```
DepthDecay    = 1 / (1 + 0.3 × 1)     = 0.769
FanOutBoost   = 1 + log₂(1)           = 1.0
FreshnessDecay = e^(-0.001 × 1500)    = 0.223
DirectBoost   = 1.0

RiskScore = 10.0 × 0.769 × 1.0 × 0.223 × 1.0 = 1.71
```

> Note: The freshness decay significantly reduces the score for this old CVE. When first disclosed, the score would have been **7.69** — triggering an immediate alert.

### Same CVE, but with 4 transitive paths

```
FanOutBoost   = 1 + log₂(4)           = 3.0
RiskScore = 10.0 × 0.769 × 3.0 × 0.223 × 1.0 = 5.14
```

The fan-out boost triples the score, correctly identifying that 4 paths of exposure represent a significantly greater risk.

---

## Alert Thresholds

Risk scores trigger alerts based on configurable thresholds:

| Threshold | Score Range | Action |
|-----------|:-----------:|--------|
| Critical alert | ≥ 8.0 | Immediate notification |
| High alert | ≥ 6.0 | Priority notification |
| Medium alert | ≥ 4.0 | Standard notification |
| Low / Info | < 4.0 | Logged, no alert |

---

## Research Foundation

The scoring model draws from research on cross-level risk propagation in software supply chains, particularly:

- The observation that transitive dependencies create **hidden risk amplifiers** not captured by direct CVSS scoring
- Graph-theoretic approaches to quantifying how vulnerability impact propagates through dependency trees
- Empirical analysis of real-world supply chain attacks (SolarWinds, Log4Shell, event-stream) showing that attack surface scales with dependency fan-out, not just severity

---

## Implementation

The scoring engine is implemented in [`RiskScorer.java`](../sentinel-analysis/src/main/java/com/sentinel/analysis/scoring/RiskScorer.java) with comprehensive unit tests in [`RiskScorerTest.java`](../sentinel-analysis/src/test/java/com/sentinel/analysis/scoring/RiskScorerTest.java).

The graph traversal (BFS min-depth, path counting) is implemented in [`DependencyGraph.java`](../sentinel-analysis/src/main/java/com/sentinel/analysis/graph/DependencyGraph.java).
