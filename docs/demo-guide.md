# PoC v0.8 — Stakeholder Demonstration Guide

## Demonstration Objective

Demonstrate how the Tool Output Provenance and Injection
Risk Analyzer helps a FinTech Security Lead make
evidence-informed release decisions using ADOP telemetry.

Duration: 3 minutes.

## Preparation

1. Install the dependencies listed in requirements.txt.
2. Launch the interface using:
   python3 -m streamlit run app.py
3. Prepare the reference clean and poisoned JSONL files.
4. Rehearse the demonstration before recording.
5. Record the Streamlit interface rather than the terminal
   or Python source code.

## Demonstration Timeline

### 0:00–0:25 — Clean Baseline

Upload session-01(clean).jsonl.

Show:
- 10 records analyzed.
- 0 alerts.
- Recommendation to continue standard review.

Explain that the clean reference session establishes
a baseline for expected behavior.

### 0:25–0:50 — Poisoned Session

Upload poisoned-file.jsonl.

Show:
- 12 records analyzed.
- 8 alerts.
- 5 HIGH and 3 MEDIUM alerts.
- Recommendation to hold release pending investigation.

### 0:50–1:20 — Path Containment Violation

Expand the alert for sequence 21.

Show:
- Successful out-of-scope file access.
- HIGH risk with a score of 75.
- Base score of 45.
- Outcome adjustment of +30.

Explain why successful access presents greater risk
than an unsuccessful attempt.

### 1:20–1:55 — Memory Retention and Provenance

Expand the alert for sequence 22.

Show:
- HIGH risk with a score of 80.
- Source event: sequence 21.
- Verified content overlap.
- Matched content length of 119 characters.

Explain that v0.5 missed this Memory event.
Version 0.8 connects the earlier out-of-scope read
to the subsequent Memory write using content evidence.

Content overlap supports provenance analysis but
does not independently establish causation.

### 1:55–2:20 — Dependency Supply-Chain Risk

Expand the alert for sequence 18.

Show:
- Missing registry verification.
- Unvetted dependency risk.
- Content provenance evidence.

Briefly explain how sequences 19 and 20 demonstrate
downstream risk propagation through Git staging
and committing.

### 2:20–2:50 — Reviewer Accountability

Return to sequence 22.

Enter reviewer ID:
SecurityLead-01

Select:
Hold

Enter reviewer notes:
Release approval withheld pending investigation of
out-of-scope data access and subsequent Memory retention.

Save the decision.

Explain how the interface records the reviewer identity,
decision, justification, timestamp, and log fingerprint.

### 2:50–3:00 — Evidence Export

Show the analysis report and reviewer decision
export controls.

Conclude that the prototype supports evidence-informed
release decisions without modifying the monitored
environment or automatically blocking releases.

## Important Limitations

- Risk scores are heuristic, not attack probabilities.
- Provenance relationships do not prove causation.
- Registry verification depends on available telemetry.
- Truncated tool output can prevent injection detection.
- Reviewer identities are self-reported.
- The prototype is passive-only.

## Recording Checklist

- Use the stakeholder-facing Streamlit interface.
- Show both clean and poisoned reference sessions.
- Demonstrate at least one attack story end to end.
- Explain an improvement made in response to D3 feedback.
- Demonstrate a reviewer decision.
- Avoid exposing raw sensitive content.
- Keep the recording within three minutes.
