# Group 6 — Tool Output Provenance & Injection Risk Analyzer

**CYSE-587 — Cybersecurity Systems Engineering**  
**George Mason University | Fall 2026**  
**Deliverable 3 — PoC v0.5**

## 1. Project Overview

The Tool Output Provenance & Injection Risk Analyzer is a passive-only proof of concept (PoC) developed to analyze structured tool-call logs from the Agent Development and Orchestration Platform (ADOP) testbed.

The analyzer identifies potentially suspicious tool operations, including prompt-injection-like language, suspicious Git arguments, and path traversal patterns.

PoC v0.5 extends the initial Deliverable 2 prototype with improved event correlation, ADOP sequence-number tracking, same-session provenance context, and human-readable security review reports.

The analyzer does not modify ADOP, block tool execution, or prove that a cyberattack occurred.

## 2. Features

- Supports JSON and JSONL input files.
- Analyzes structured tool-call records and available event metadata.
- Detects suspicious path traversal patterns.
- Identifies potentially unsafe command arguments and output redirection.
- Searches available Fetch content previews for predefined prompt-injection phrases.
- Assigns heuristic scores and HIGH, MEDIUM, or LOW risk classifications.
- Correlates earlier source events with suspicious tool operations using task identifiers and sequence numbers.
- Separately reports earlier Fetch events from different tasks within the same session.
- Removes scenario labels and debugging metadata before detection.
- Generates machine-readable JSON results.
- Generates human-readable security-lead review reports.
- Operates in passive-only mode.

## 3. Requirements

- Python 3
- No additional third-party Python packages required.

The implementation uses Python's standard libraries.

## 4. Setup

1. Clone or download the repository.
2. Open a terminal in the project directory.
3. Verify that Python 3 is installed:

   ```bash
   python3 --version
   ```

4. Ensure `analyzer.py` and the ADOP test logs are available in the project directory, or provide their correct file paths.

## 5. How to Run

### Analyze the Clean ADOP Session

```bash
python3 analyzer.py 'session-01(clean).jsonl'
```

### Analyze the Poisoned ADOP Session

```bash
python3 analyzer.py poisoned-file.jsonl
```

### Generate JSON Results

```bash
python3 analyzer.py poisoned-file.jsonl -o results.json
```

### Generate JSON and Security-Lead Reports

```bash
python3 analyzer.py poisoned-file.jsonl -o results.json --review security_review.txt
```

This command generates two output files:

- **results.json:** Structured alerts containing risk classifications, heuristic scores, findings, evidence references, and provenance information.
- **security_review.txt:** Human-readable report summarizing detected operations, severity levels, supporting evidence, and recommendations for human review.

### Analyze the Clean Session and Save Reports

```bash
python3 analyzer.py 'session-01(clean).jsonl' -o clean_results.json --review clean_review.txt
```

The analyzer reads the input logs without modifying ADOP, the agent, the model, MCP tools, or the execution environment.

## 6. Detection and Provenance Analysis

### Detection Rules

The analyzer applies three primary detection categories:

1. **Path Traversal Detection:** Identifies parent-directory traversal patterns in path-related fields.
2. **Suspicious Tool Argument Detection:** Identifies command-output and redirection patterns in tool-related records.
3. **Prompt-Injection Phrase Detection:** Searches available Fetch `result_summary` previews for predefined instruction-override phrases.

Detected findings receive heuristic scores and risk classifications.

### Provenance Correlation

The analyzer examines earlier source events using available ADOP task identifiers and sequence numbers.

Source events within the same task are recorded as possible provenance relationships. Earlier Fetch events from different tasks within the same session are reported separately as contextual information.

When valid sequence numbers are unavailable, the analyzer falls back to input record order.

**Important:** Correlation identifies possible relationships for investigation. It does not prove that retrieved content caused a subsequent tool operation.

## 7. Testing and Evaluation

PoC v0.5 was evaluated using two ADOP JSONL test sessions.

| Test Session | Records Analyzed | Alerts Generated |
|---|---:|---:|
| Clean ADOP session | 10 | 0 |
| Poisoned ADOP session | 12 | 2 |

### Detected Suspicious Operations

| Tool Operation | Risk Level | Heuristic Score |
|---|---|---:|
| `git_diff` | HIGH | 70 |
| `git_show_worktree` | MEDIUM | 45 |

Both annotated suspicious operations were detected.

For these annotated test cases, the evaluation produced:

- **True Positives (TP):** 2
- **False Positives (FP):** 0 observed in the clean session
- **False Negatives (FN):** 0 for the two annotated suspicious operations

These results apply only to the evaluated test corpus and should not be interpreted as a general detection accuracy rate.

### Provenance Evaluation

The analyzer identified an earlier same-task source event associated with the `git_diff` alert.

For `git_show_worktree`, the analyzer identified earlier Fetch events in the same session but belonging to different tasks.

The available Fetch content previews did not establish that malicious retrieved instructions caused either suspicious operation.

## 8. Limitations

- Detection relies on heuristic patterns and may produce false positives or false negatives.
- Risk scores are indicators, not probabilities of an attack.
- Prompt-injection phrase detection is limited to the available Fetch content previews.
- Malicious instructions outside the available preview may not be detected.
- Source-to-action correlation does not prove causation.
- Sequence-number correlation may fall back to input record order when sequence values are unavailable.
- The evaluation corpus is small and does not establish production-level detection accuracy.
- The analyzer does not block suspicious actions or modify the ADOP environment.
- All alerts require human review.

## 9. Future Improvements

Potential improvements include:

- Expanding detection rules for additional prompt-injection techniques.
- Improving source-to-action provenance verification.
- Evaluating additional clean and poisoned ADOP sessions.
- Refining heuristic scoring to reduce false positives.
- Supporting more comprehensive retrieved-content analysis.
- Improving security-review reporting and evidence presentation.

## 10. Project Scope

This repository contains the Group 6 Tool Output Provenance & Injection Risk Analyzer.

The initial prototype was developed for Deliverable 2. PoC v0.5 builds on that work for Deliverable 3 by introducing stronger provenance context, sequence-aware event correlation, expanded evaluation documentation, and human-readable security review output.

The implementation remains a passive monitoring prototype intended for security analysis and human review.

## 11. Course Information

**Course:** CYSE-587 — Cybersecurity Systems Engineering  
**Institution:** George Mason University  
**Semester:** Fall 2026  
**Project:** Group 6 — Tool Output Provenance & Injection Risk Analyzer
