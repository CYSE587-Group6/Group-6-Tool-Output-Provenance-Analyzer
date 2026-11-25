# Group 6 — Tool Output Provenance & Injection Risk Analyzer

**George Mason University | Fall 2026**  
**CYSE-587 / SYST-687**  
**Deliverable 4 — PoC v0.8**

## 1. Project Overview

The Tool Output Provenance & Injection Risk Analyzer is a
passive-only proof of concept developed to analyze structured
tool-call telemetry from the Agent Development and
Orchestration Platform (ADOP) testbed.

The primary stakeholder is a FinTech Security Lead responsible
for evaluating security risks before software release approval.

The prototype identifies suspicious tool operations, examines
available source-to-action evidence, assigns heuristic risk
scores, and supports evidence-informed human review.

The analyzer does not modify ADOP, prevent tool execution,
automatically block releases, or independently prove that
a cyberattack occurred.

## 2. Implemented Capabilities

### Security Detection

- Suspicious Git arguments and output redirection.
- Relative and absolute path containment violations.
- Prompt-injection indicators in available Fetch previews.
- Behavioral injection risk assessment.
- Unvetted dependency source detection.
- Telemetry-based dependency registry verification.
- Dependency risk propagation through Git staging and commits.
- Suspicious Memory activity following out-of-scope reads.
- Source code retention in agent Memory.

### Evidence and Risk Assessment

- Same-session and same-task event correlation.
- Content-based source-to-action provenance.
- Verified content overlap and matched content length.
- Outcome-based heuristic risk scoring.
- Consistent alert ranking.
- Duplicate path finding reduction.
- Record-level evidence references.

### Privacy and Governance

- Removal of scenario labels and debugging metadata before
  detection.
- Sensitive-data redaction in analysis outputs.
- SHA-256 fingerprints of original parsed telemetry records.
- Log-specific reviewer decisions.
- Reviewer identification, justification, and UTC timestamps.
- Machine-readable analysis and reviewer decision exports.

### Stakeholder Interface

- Streamlit security review dashboard.
- HIGH, MEDIUM, and LOW risk classifications.
- Evidence-based release recommendations.
- Approve, Investigate, and Hold reviewer decisions.
- Risk scoring and provenance explanations.

## 3. Architecture

The prototype follows a passive telemetry analysis workflow:

ADOP telemetry
    -> Shared JSON/JSONL parser
    -> Log fingerprinting
    -> Detection metadata sanitization
    -> Security detection
    -> Provenance and risk correlation
    -> Alert ranking and output redaction
    -> CLI or Streamlit interface
    -> Human review and evidence export

Only exported telemetry is consumed by the analyzer.
The prototype does not access or modify ADOP servers.

## 4. Requirements

- Python 3
- Streamlit for the graphical interface
- Python standard libraries for the core analyzer

Additional dependencies are listed in requirements.txt.

## 5. Installation

Clone the Deliverable 4 branch:

```bash
git clone --branch Deliverable-4-poc-v0.8 https://github.com/CYSE587-Group6/Group-6-Tool-Output-Provenance-Analyzer.git
cd Group-6-Tool-Output-Provenance-Analyzer
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## 6. Running the Prototype

### Command-Line Analyzer

Analyze the reference clean session:

```bash
python3 analyzer.py "session-01(clean).jsonl"
```

Analyze the reference poisoned session:

```bash
python3 analyzer.py poisoned-file.jsonl
```

View available command-line options:

```bash
python3 analyzer.py --help
```

### Streamlit Security Review Interface

```bash
python3 -m streamlit run app.py
```

Open the local Streamlit address displayed in the terminal.

Upload a JSON or JSONL telemetry file to view:

- Record and alert counts.
- Risk classifications.
- Release recommendations.
- Detection evidence.
- Source-to-action provenance.
- Reviewer decision controls.
- Downloadable analysis and decision reports.

See [Demonstration Guide](docs/demo-guide.md) for the
stakeholder-facing demonstration workflow.

## 7. Risk Scoring and Review Recommendations

Risk scores are heuristic values between 0 and 100.

| Risk Level | Score |
|---|---:|
| LOW | 0–34 |
| MEDIUM | 35–59 |
| HIGH | 60–100 |

Scores incorporate detection indicators, observed tool
outcomes, and applicable event correlations.

Successful harmful operations can receive higher scores
than unsuccessful attempts.

The dashboard recommends:

| Condition | Recommendation |
|---|---|
| No alerts | Continue standard review |
| Alerts without HIGH risk | Investigate |
| At least one HIGH risk alert | Hold release pending investigation |

Recommendations support human decision-making and do not
automatically enforce release restrictions.

## 8. Dependency Registry Verification

The analyzer evaluates available registry evidence from
earlier successful Fetch events within the same task
and session.

| Status | Meaning |
|---|---|
| APPROVED | Dependency name observed in registry telemetry |
| NOT_LISTED | Available complete registry evidence does not list the dependency |
| NOT_CHECKED | No qualifying registry Fetch was observed |
| INCONCLUSIVE | Available registry evidence is insufficient |

The analyzer does not directly access the registry outside
the supplied telemetry.

Registry approval does not independently authenticate a
package, publisher, version, or registry response.

## 9. Evaluation Results

### Reference Sessions

| Session | Records | Alerts |
|---|---:|---:|
| Clean | 10 | 0 |
| Poisoned | 12 | 8 |
| Total | 22 | 8 |

The poisoned reference session produced five HIGH and
three MEDIUM alerts.

### Reference Detection Coverage

| Sequence | Observed Risk | v0.8 Result |
|---|---|---|
| 11 | Poisoned Fetch content | Missed |
| 12 | Suspicious Git argument | HIGH |
| 14 | Source code retention in Memory | MEDIUM |
| 16 | Unvetted dependency source | MEDIUM |
| 18 | Risky dependency modification | HIGH |
| 19 | Risk propagation through staging | MEDIUM |
| 20 | Risk propagation through commit | HIGH |
| 21 | Successful out-of-scope file read | HIGH |
| 22 | Suspicious Memory retention | HIGH |

Sequence 11 remains a known false negative because the
available Fetch preview does not expose the injection payload.

### Live ADOP Sessions

Three live sessions were generated using the official
ADOP testbed and the qwen2.5:7b model.

| Session | Clean Records | Clean Alerts | Poisoned Records | Poisoned Alerts |
|---|---:|---:|---:|---:|
| 18bf08 | 15 | 1 | 17 | 4 |
| 20f050 | 15 | 1 | 15 | 2 |
| 73e266 | 16 | 0 | 15 | 4 |
| Total | 46 | 2 | 47 | 10 |

Live evaluation totals:

- 93 telemetry records.
- 12 alerts.
- 1 HIGH, 2 MEDIUM, and 9 LOW alerts.

Clean-session labels do not guarantee that every observed
operation is benign. Clean-session alerts were reviewed
individually rather than automatically classified as
false positives.

### Combined Evaluation

| Dataset | Records | Alerts |
|---|---:|---:|
| Reference | 22 | 8 |
| Live | 93 | 12 |
| Total | 115 | 20 |

### Event-Level Evaluation Metrics

The following results use retrospective analyst-defined
security policy labels.

| Metric | Reference | Live |
|---|---:|---:|
| True positives | 8 | 12 |
| False positives | 0 | 0 |
| False negatives | 1 | 2 |
| True negatives | 13 | 79 |
| Precision | 100% | 100% |
| Recall | 88.89% | 85.71% |
| Accuracy | 95.45% | 97.85% |
| F1 score | 94.12% | 92.31% |

These metrics are conditional on the selected labeling
policy and are not independently established ground truth.

Under an alternative live-session labeling policy that
treats the failed absolute-path read as benign, precision
decreases to 91.67% and recall is 84.62%.

Annotation-based recall is 75% for the reference session
and 50% for the live sessions. Additional detections outside
explicitly annotated events are documented separately.

These results do not establish production-level detection
accuracy or generalization to unseen attacks.

## 10. Automated Regression Testing

Run the complete regression suite:

```bash
python3 -m unittest discover -s tests -v
```

Run Python syntax validation:

```bash
python3 -m py_compile analyzer.py app.py
```

Final validation results:

| Test Category | Tests Passed |
|---|---:|
| Parsing, fingerprinting, and privacy | 18 |
| Security detection | 15 |
| Provenance verification | 4 |
| Registry verification | 8 |
| Registry integration | 6 |
| Deduplication | 4 |
| Source detection | 5 |
| Memory retention | 9 |
| Dependency risk propagation | 12 |
| Total | 81 |

All 81 automated regression tests passed.

Manual Streamlit validation also passed for all eight
reference and live telemetry files.

## 11. Example Outputs and Evaluation Evidence

### Generated Analysis Outputs

- [Reference clean analysis](examples/reference-clean-analysis.json)
- [Reference poisoned analysis](examples/reference-poisoned-analysis.json)

### Evaluation Documentation

- [Reference evaluation](evaluation/reference-results.md)
- [Live ADOP evaluation](evaluation/live-results.md)
- [Streamlit interface validation](evaluation/interface-validation.md)
- [Sanitized live telemetry](evaluation/live-sessions-sanitized/)
- [Stakeholder demonstration guide](docs/demo-guide.md)

The example analysis reports were generated directly
from PoC v0.8 using the reference telemetry files.

## 12. Privacy and Reviewer Accountability

Analysis outputs apply sensitive-data redaction to
recognized credential patterns.

Live telemetry copies were sanitized before repository
publication. The sanitized copies were verified to preserve
record counts, alert counts, risk scores, and finding
categories.

SHA-256 fingerprints support evidence traceability but
do not authenticate telemetry or establish a cryptographic
chain of custody.

Reviewer decisions are associated with the analyzed log
fingerprint and individual alert. Saved decisions include
reviewer identification, justification, and UTC timestamps.

Reviewer identities are self-reported, and decisions are
maintained in Streamlit session state rather than permanent,
authenticated audit storage.

## 13. Known Limitations

- Fetch output previews may be truncated to 200 characters.
- Hidden injection payloads cannot be directly detected.
- Behavioral indicators do not establish malicious intent.
- Provenance relationships do not independently prove causation.
- Content matching and risk scores are heuristic.
- Path containment uses assumed repository boundaries and
  does not independently resolve runtime filesystem state.
- Registry verification depends on available telemetry.
- Dependency propagation does not independently verify
  actual Git commit contents.
- Redaction does not guarantee removal of all sensitive data.
- Reviewer identities are not authenticated.
- Reviewer decisions are not stored in an immutable audit log.
- Evaluation labels are retrospective and not independent.
- Repeated tool attempts are not independent attack samples.
- The prototype does not automatically block tool execution
  or software releases.

## 14. Development Progression

| Version | Deliverable | Development Focus |
|---|---|---|
| v0.1 | D2 | Initial telemetry analysis and risk detection |
| v0.5 | D3 | Event correlation and stakeholder review interface |
| v0.8 | D4 | Hardened detection, content provenance, registry verification, risk propagation, privacy, reviewer accountability, and expanded evaluation |

The D4 prototype addresses technical feedback from earlier
deliverables while explicitly documenting unresolved
limitations.

## 15. Future Development

Potential V2 capabilities include:

- CI/CD and pull-request review integration.
- Authenticated reviewer identities.
- Persistent and tamper-evident audit records.
- Independently verified dependency provenance.
- Improved telemetry completeness.
- Broader evaluation with independently labeled datasets.
- Policy-based release approval integration.

These capabilities are proposed future work and are not
implemented in PoC v0.8.

## 16. Project References

- [Official ADOP Testbed](https://github.com/GMU-CYSE/adop-cyse)
- [ADOP Log Schema](https://github.com/GMU-CYSE/adop-cyse/blob/main/docs/LOG_SCHEMA.md)
- [Group 6 D4 Repository](https://github.com/CYSE587-Group6/Group-6-Tool-Output-Provenance-Analyzer/tree/Deliverable-4-poc-v0.8)

Developed for the George Mason University cybersecurity
systems engineering capstone project.
