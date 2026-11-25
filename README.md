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

## 17. Feedback-to-Change Traceability

The following tables document the team's response to
Deliverable 2 and Deliverable 3 feedback.

Commit references identify implemented repository changes.
Feedback involving the report, pitch, or future architecture
is identified separately rather than attributed to unrelated
code changes.

### 17.1 Deliverable 2 Feedback

| ID | Instructor Feedback | Change or Response | Commit Evidence | Status |
|---|---|---|---|---|
| D2-01 | Demonstrate provenance on real ADOP logs rather than relying on non-schema mock data. | Implemented behavioral correlation and content overlap using actual telemetry. Evaluated reference sessions and three live sessions. Mock data is not used for the reported evaluation metrics. Direct detection of hidden injection payloads remains limited. | `9761baa`, `d446973`, `0961df8`, `106e06d`, `414c7fe` | Partial |
| D2-02 | Make the code match the report by removing scenario labels and debugging annotations before detection and from analysis outputs. | Implemented recursive detection metadata sanitization and regression tests for annotation-independent detection. | `85e8792`, `4c5e6f5` | Addressed |
| D2-03 | Do not repeat sensitive content in alerts. | Added evidence references and sensitive-data redaction. Sanitized published live telemetry and verified that detection results were preserved. Redaction remains pattern-based. | `4d925cb`, `821224a`, `8f453d6` | Partial |
| D2-04 | Restrict injection keyword checks to appropriate content fields and report true and false positives. | Restricted injection-text analysis to Fetch previews, improved argument-specific detection, and added behavioral assessment and evaluation metrics. Complete independent per-rule confusion matrices are not available. | `97fb18a`, `c366288`, `9761baa`, `eba4424`, `414c7fe` | Partial |
| D2-05 | Design a stakeholder-facing security review experience instead of raw JSON. | Implemented a Streamlit dashboard with ranked alerts, provenance evidence, review recommendations, reviewer decisions, and exports. Validated eight telemetry files. | `3482e64`, `921bf71`, `cf0c0c2`, `29a69fe`, `0e59c1d` | Addressed |
| D2-06 | Incorporate FinTech regulatory constraints into the report. | PCI DSS change-management considerations inform the pre-release review workflow. Regulatory applicability and governance reasoning belong in the architecture report. The prototype does not establish compliance. | `cf0c0c2`, `921bf71` support the review workflow | Partial; report-level requirement |
| D2-07 | Apply STRIDE per interface and justify likelihood, impact, and threat ranking. | Outcome-based scoring distinguishes unsuccessful attempts from successful out-of-scope access. Interface-specific threat classification and likelihood-impact justification belong in the threat model and architecture report. | `300e5d5`, `0470a63` | Partial; report-level requirement |
| D2-08 | Expand and align ATLAS, OWASP Agentic, and LLM framework mappings across the report and slides. | Detection coverage and limitations are documented to support accurate framework mappings. Framework alignment must be verified in the final report and pitch. | `eba4424`, `414c7fe` provide detection evidence | Report-level requirement |
| D2-09 | Improve presentation details, readable diagrams, measurable validation targets, ownership, and team development history. | Added structured evaluation documentation, 81 regression tests, interface validation, and a demonstration guide. Report formatting and team ownership require separate verification. Repository maintenance remains centralized. | `eba4424`, `414c7fe`, `0e59c1d`, `1c28af5` | Partial |
| D2-10 | Share the repository directly with the instructor. | The D4 repository link and full repository archive are required submission artifacts. Instructor access must be verified before submission. | Not a code change | Submission verification pending |

### 17.2 Deliverable 3 Technical Feedback

| ID | Instructor Feedback | Change or Response | Commit Evidence | Status |
|---|---|---|---|---|
| D3-T01 | Replace reliance on phrase matching with behavioral injection signals and content overlap. | Added behavioral assessment for suspicious argument and path operations following Fetch events in the same task and session. Added content-based provenance matching. The reference poisoned Fetch remains undetected because its payload is outside the preview. | `9761baa`, `d446973`, `0961df8`, `106e06d` | Partial |
| D3-T02 | Restrict output-redirection checks to arguments and match dangerous Git options specifically. | Restricted suspicious argument checks to relevant Git and shell argument fields. Added regression coverage for harmless documentation content. | `c366288`, `4c5e6f5` | Addressed |
| D3-T03 | Detect absolute paths and resolve paths against appropriate working-directory boundaries. | Implemented relative and absolute path containment checks, including Windows paths and special handling for git_init. Reduced duplicate path findings while preserving evidence fields. Actual runtime filesystem state is not independently verified. | `300e5d5`, `8fa3c3b`, `91606f6`, `351a935` | Partial |
| D3-T04 | Incorporate operation outcomes into risk scoring. | Added outcome adjustments for unsuccessful operations, uncertain Git results, and successful out-of-scope reads. Reference sequence 21 scores 75 and sequence 12 scores 65. Added scoring explanations to the interface. | `0470a63`, `947fe2a` | Addressed |
| D3-T05 | Cover unvetted dependencies, registry verification, suspicious Memory activity, and report TP, FP, and FN across annotated events. | Added dependency registry checks, manifest baseline comparison, explicit unvetted-source warnings, Memory retention detection, content overlap verification, and downstream Git risk propagation. Reported analyst-defined and annotation-based evaluation results, including missed events. | `0ee3a7c`, `34cfd76`, `00f1ed2`, `392511f`, `6becbdf`, `976e73c`, `5e5099a`, `5944d7e`, `eba4424`, `414c7fe` | Partial |
| D3-T06 | Centralize alert ranking in the analyzer so CLI, JSON, and UI agree. | Moved score-based ranking into the shared analyzer with deterministic tie-breaking. | `98e77cf`, `921bf71` | Addressed |
| D3-T07 | Make reviewer decisions durable and include reviewer identity, timestamp, and SHA-256 log fingerprint. | Added log-specific reviewer decisions, required reviewer identification and justification, UTC timestamps, SHA-256 fingerprints, and downloadable JSON decision records. Permanent authenticated audit storage is not implemented. | `a0debe1`, `cf0c0c2`, `0e59c1d` | Partial |
| D3-T08 | Remove duplicated parsing between the analyzer and Streamlit. | Implemented a shared JSON/JSONL parser and reused it in the graphical interface. | `db98849`, `0dd0e9f`, `007b6e4` | Addressed |
| D3-T09 | Add deterministic unit tests and reproducible reference-session tests. | Implemented 81 regression tests covering parsing, privacy, detection, provenance, registry verification, deduplication, source detection, Memory retention, and dependency risk propagation. | `65ddacf`, `4c5e6f5`, `1b757bd`, `2ea79eb`, `939560c`, `351a935`, `d5724f7`, `64adbda`, `7716995`, `4b0db13` | Addressed |

### 17.3 Deliverable 3 Architecture and Formative Feedback

| ID | Instructor Feedback | Change or Response | Commit Evidence | Status |
|---|---|---|---|---|
| D3-F01 | Include actual CVSS scores and vectors and explain their limitations in ADOP. | Outcome-based scoring provides contextual evidence beyond static vulnerability severity. CVSS vectors and contextual comparison must be documented in the final report. | `0470a63`, `eba4424` support contextual comparison | Report-level requirement |
| D3-F02 | Apply NIST AI RMF at the subcategory level. | Privacy, evidence traceability, evaluation, and reviewer accountability provide implementation evidence for governance and measurement mappings. Specific subcategory mappings belong in the report. | `821224a`, `a0debe1`, `cf0c0c2`, `eba4424`, `414c7fe` | Report-level requirement |
| D3-F03 | Trace mitigations to individual D2 threats rather than only STRIDE categories. | Added record-level evidence, specific detection findings, and regression tests. The final architecture report must explicitly map individual D2 threats to these controls and identify uncovered threats. | `29a69fe`, `eba4424`, `4c5e6f5` | Partial |
| D3-F04 | Correct the contradiction claiming coverage of all six STRIDE categories. | README describes implemented capabilities and limitations without claiming complete STRIDE coverage. Denial-of-service detection is not an implemented capability. | Final D4 README | Repository documentation addressed; report verification pending |
| D3-F05 | Show untrusted content entry points and the Streamlit interface in the architecture diagram. | Implemented source-to-action evidence presentation and a stakeholder-facing interface. The revised architecture diagram must show these components and trust boundaries. | `36beb04`, `29a69fe`, `0e59c1d` | Report-level requirement |
| D3-F06 | Distinguish proposed architecture from implemented architecture. | README separates implemented v0.8 capabilities from future V2 capabilities. The report must preserve the same distinction. | `4075756`, `fc48d59`; final D4 README | Repository documentation addressed; report verification pending |
| D3-F07 | Replace generic V2 roadmap phases with concrete future development milestones. | Existing testing and review-interface capabilities are treated as completed PoC work. Future development focuses on authenticated review, persistent audit storage, verified provenance, and CI/CD integration. | `0e59c1d`; final D4 README | Roadmap-level requirement |
| D3-F08 | Identify the release control point, its owner, and failure behavior. | The proposed V2 control point is a CI/CD or pull-request approval gate owned by the release security function. Current v0.8 provides recommendations only. Ownership and failure policy require further design. | `921bf71`, `cf0c0c2` support the current review workflow | Future V2 |
| D3-F09 | Provide a stronger justification for Static mode. | Passive retrospective analysis aligns with the stakeholder's pre-release evidence review and preserves the fixed ADOP environment. Live-generated telemetry expands evaluation without requiring active enforcement or testbed modification. | `414c7fe`, `0e59c1d` | Repository documentation addressed |
| D3-F10 | Improve repository contribution history and team participation. | Repository history now documents incremental development, regression testing, evaluation, and interface improvements. Repository maintenance remains centralized and does not independently demonstrate contributions from every member. | D4 Git history | Partial |

### 17.4 Deliverable 3 Demonstration and Shark Feedback

| ID | Instructor Feedback | Change or Response | Commit Evidence | Status |
|---|---|---|---|---|
| D3-V01 | Demonstrate installation from a clean checkout. | Added current installation instructions and validated the cloned D4 repository. Recording installation evidence remains a presentation requirement. | Final D4 README | Partial |
| D3-V02 | Present TP, FP, FN, and missed detections. | Documented reference and live evaluation metrics, alternative labeling assumptions, and known false negatives. | `eba4424`, `414c7fe` | Repository evidence addressed |
| D3-V03 | Explain development progress and lessons learned since v0.1. | Documented the progression from v0.1 to v0.5 and v0.8, including expanded detection and unresolved limitations. The pitch must communicate this progression. | Final D4 README; `1c28af5` | Repository documentation addressed |
| D3-V04 | Replace raw terminal JSON with an intentional stakeholder-facing demonstration. | Enhanced Streamlit scoring, evidence presentation, registry status, provenance, and reviewer workflow. Added a three-minute demonstration guide. | `947fe2a`, `29a69fe`, `0e59c1d`, `1c28af5` | Interface addressed; recording pending |
| D3-V05 | Include the required results table in the report appendix. | Created reference, live, and interface validation tables for consistent reuse in the final report and pitch. | `eba4424`, `414c7fe`, `0e59c1d` | Repository evidence addressed |
| D3-S01 | Deliver on the product name with a real content provenance link. | Reference sequence 18 contains dependency-name overlap with sequence 16. Sequence 22 contains verified content overlap with the out-of-scope read at sequence 21. These relationships support provenance but do not prove causation. | `0961df8`, `106e06d`, `1b757bd` | Addressed within available telemetry |
| D3-S02 | Expand detection beyond the two Git CVE-pattern alerts. | Added unvetted dependency source detection, registry checks, dependency risk propagation, and Memory retention detection. Reference alerts increased from two in v0.5 to eight in v0.8. | `976e73c`, `392511f`, `5944d7e`, `34cfd76`, `5e5099a`, `eba4424` | Addressed |
| D3-S03 | Show the release gate as a compelling product direction. | The demonstration shows a Security Lead placing a release recommendation on Hold with supporting evidence and reviewer justification. Actual CI/CD enforcement remains proposed V2 work. | `cf0c0c2`, `921bf71`, `1c28af5` | Partial |
| D3-S04 | Show detection misses openly. | Explicitly documented the missed reference Fetch event and two missed live Fetch events, along with the 200-character preview limitation and annotation-based recall. | `eba4424`, `414c7fe` | Addressed |

### 17.5 Traceability Summary

The D4 implementation expands the prototype beyond the
original two Git-related detections.

Key improvements include:

- Behavioral injection risk assessment.
- Content-based provenance evidence.
- Outcome-based risk scoring.
- Dependency registry verification.
- Dependency risk propagation.
- Suspicious Memory retention detection.
- Privacy and evidence fingerprinting controls.
- Reviewer accountability.
- Automated regression testing.
- Expanded reference and live telemetry evaluation.
- Stakeholder-facing interface improvements.

The final prototype remains passive-only. Unresolved
limitations and future development requirements are
documented rather than presented as completed capabilities.

The repository evidence supports the final report and
pitch, but does not independently verify their completion.
