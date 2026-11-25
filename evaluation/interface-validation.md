# PoC v0.8 — Streamlit Interface Validation

**Validation date:** November 25, 2026

## 1. Interface Improvements

- Consistent PoC v0.8 version identification.
- Outcome-based risk scoring explanations.
- Content overlap verification and matched content length.
- Dependency registry verification status.
- Downstream dependency risk propagation.
- Source-to-action provenance visualization.
- Log-specific reviewer accountability and decision exports.

## 2. Functional Validation

| Evaluation File | Records | Alerts | Result |
|---|---:|---:|---|
| Reference clean | 10 | 0 | PASS |
| Reference poisoned | 12 | 8 | PASS |
| 18bf08 clean | 15 | 1 | PASS |
| 18bf08 poisoned | 17 | 4 | PASS |
| 20f050 clean | 15 | 1 | PASS |
| 20f050 poisoned | 15 | 2 | PASS |
| 73e266 clean | 16 | 0 | PASS |
| 73e266 poisoned | 15 | 4 | PASS |
| **Total** | **115** | **20** | **PASS** |

All eight telemetry files produced the expected dashboard
record and alert counts. Sanitized copies were used for
live-session interface validation.

## 3. Reviewer Accountability Validation

| Test | Result |
|---|---|
| Save Hold decision for sequence 22 | PASS |
| Save Investigate decision for sequence 18 | PASS |
| Independent decision persistence | PASS |
| Reviewer ID recording | PASS |
| Reviewer notes recording | PASS |
| UTC timestamp recording | PASS |
| Required reviewer ID enforcement | PASS |
| Required reviewer notes enforcement | PASS |
| Log-specific decision isolation | PASS |
| Restore decisions after switching logs | PASS |
| Reviewer decision JSON export | PASS |
| Analysis report JSON export | PASS |

The reference poisoned session produced eight alerts.
Two independent reviewer decisions were successfully
saved and exported, leaving six pending reviews.

## 4. Regression Testing

- Python syntax validation: PASS
- Automated regression tests: 81/81 PASS
- Manual Streamlit evaluation files: 8/8 PASS

The interface tests were performed manually by the PoC
developer. The automated regression suite validates
analyzer functionality.

## 5. Limitations

- Reviewer identities are self-reported, not authenticated.
- Decisions are stored in Streamlit session state rather
  than permanent audit storage.
- Updating a decision replaces the existing decision.
- SHA-256 fingerprints support evidence traceability but
  do not authenticate telemetry.
- Heuristic risk scores do not represent attack probabilities.
- Provenance relationships do not independently establish
  causation.
- Release recommendations do not enforce release blocking.

## 6. Conclusion

PoC v0.8 successfully presents the evaluated detection
results through a stakeholder-facing interface. The
validated reviewer workflow supports evidence-informed
release decisions while maintaining the prototype's
passive-only analysis model.
