# Security Detector Evaluation Report

_Dataset: `data\security_tests\detector_dataset.json` — labeled cases per detector. All credential values in the dataset are FAKE test values._

## Per-detector results

| Detector | TP | TN | FP | FN | Precision | Recall | F1 | FP rate | FN rate | Avg ms | P95 ms |
|---|---|---|---|---|---|---|---|---|---|---|---|
| prompt_injection | 7 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0.32 | 2.41 |
| jailbreak | 4 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0.07 | 0.09 |
| secret_detection | 7 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0.12 | 0.4 |
| pii_detection | 5 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0.14 | 0.44 |
| rag_poisoning | 5 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0.12 | 0.18 |

## Input security end-to-end latency (all 5 detectors per case)

- average: 1.32 ms
- P50: 0.39 ms
- P95: 1.57 ms
- P99: 33.34 ms

## Misclassified cases

- none

## Limitations (read before trusting these numbers)

- This dataset is small and hand-labeled; it demonstrates the evaluation
  methodology and gives *initial* measurements. It is NOT a benchmark of
  real-world attack diversity.
- Deterministic detectors miss paraphrased/novel attacks (see FN cases);
  an LLM-based classifier hook exists (LLM_SECURITY_CLASSIFIER_ENABLED)
  for semantic double-checking at the cost of latency.
- False positives matter: an FPR above ~5% on legitimate security
  documentation will erode trust in the gateway.
- Thresholds in the default policy are initial values and REQUIRE
  empirical tuning per deployment.

Re-run with: `python scripts/evaluate_detectors.py`
