# PoC v0.8 — Reference Session Evaluation

## Evaluation Dataset

- Clean reference session: 10 records
- Poisoned reference session: 12 records
- Total: 22 records
- Automated regression tests: 81 passed

## Reference Results

The clean session produced zero alerts. The poisoned session produced eight alerts, including five HIGH-risk and three MEDIUM-risk alerts.

| Sequence | Detection | Risk | Score |
|---|---|---|---:|
| 12 | Argument injection and path containment violation | HIGH | 65 |
| 14 | Source code retention in Memory | MEDIUM | 50 |
| 16 | Unvetted dependency source | MEDIUM | 35 |
| 18 | Unvetted dependency addition | HIGH | 65 |
| 19 | Risky dependency staged | MEDIUM | 50 |
| 20 | Risky dependency committed | HIGH | 65 |
| 21 | Path containment violation | HIGH | 75 |
| 22 | Suspicious Memory activity | HIGH | 80 |

## Annotation-Based Evaluation

Explicitly annotated threat and source events: sequences 11, 12, 16, and 21.

- True positives: 3
- False negatives: 1
- Additional detections outside the explicit positive labels: 5
- Annotated recall: 75%

Events labeled only as post-injection context are not automatically considered malicious. The additional detections require analyst interpretation rather than automatic classification as false positives.

## Analyst-Reviewed Evaluation

Positive events: sequences 11, 12, 14, 16, 18, 19, 20, 21, and 22.

Negative events: sequences 1–10, 13, 15, and 17.

| Metric | Result |
|---|---:|
| True positives | 8 |
| False positives | 0 |
| False negatives | 1 |
| True negatives | 13 |
| Precision | 100% |
| Recall | 88.89% |
| Accuracy | 95.45% |
| F1 score | 94.12% |
| False-positive rate | 0% |

## Known Detection Limitation

Sequence 11 remains undetected because the indirect prompt injection payload is not visible within the available 200-character Fetch content preview.

## Evaluation Limitations

- The reference dataset was used during prototype development and is not an independent validation dataset.
- Analyst-assigned labels supplement incomplete dataset annotations.
- Sequences 19 and 20 represent downstream risk propagation rather than independent attacks.
- Content overlap supports provenance correlation but does not establish causation or unauthorized disclosure.
- Registry-related findings do not establish cryptographic publisher or package authenticity.
- Zero observed false positives does not guarantee zero false positives in other environments.
- Evaluation labels are not consumed by the analyzer's detection logic.
- Live-session evaluation is reported separately.
