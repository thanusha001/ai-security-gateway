#!/usr/bin/env python3
"""Detector evaluation (spec §39-§40, §47).

Runs the labeled dataset in data/security_tests/detector_dataset.json through
each security detector and reports, per detector:

  TP, TN, FP, FN, precision, recall, F1, false positive rate,
  false negative rate, average and P95 detection latency.

Usage:
    python scripts/evaluate_detectors.py            # from repo root or backend/

Writes docs/evaluation-report.md. This script makes NO claims of perfection;
measured numbers are the only output. Thresholds are initial values that
require empirical tuning on real traffic.
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.security.detectors import (  # noqa: E402
    JailbreakDetector,
    PIIDetector,
    PromptInjectionDetector,
    RagPoisoningDetector,
    SecretDetector,
)
from app.security.pipeline import run_input_security  # noqa: E402

DATASET = ROOT / "data" / "security_tests" / "detector_dataset.json"

DETECTORS = {
    "prompt_injection": PromptInjectionDetector,
    "jailbreak": JailbreakDetector,
    "secret_detection": SecretDetector,
    "pii_detection": PIIDetector,
    "rag_poisoning": RagPoisoningDetector,
}


def evaluate() -> dict:
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    cases = data["cases"]

    per_detector: dict[str, dict] = defaultdict(lambda: {
        "tp": 0, "tn": 0, "fp": 0, "fn": 0, "latencies": [], "fp_cases": [], "fn_cases": [],
    })

    for case in cases:
        det_name = case["detector"]
        detector = DETECTORS[det_name]()
        result = detector.analyze_timed(case["text"])
        detected = result.detected
        expected = case["should_detect"]
        stats = per_detector[det_name]
        stats["latencies"].append(result.latency_ms)
        if expected and detected:
            stats["tp"] += 1
        elif expected and not detected:
            stats["fn"] += 1
            stats["fn_cases"].append(case["id"])
        elif not expected and detected:
            stats["fp"] += 1
            stats["fp_cases"].append(case["id"])
        else:
            stats["tn"] += 1

    report: dict = {"per_detector": {}}
    for name, s in per_detector.items():
        tp, tn, fp, fn = s["tp"], s["tn"], s["fp"], s["fn"]
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall else None)
        fpr = fp / (fp + tn) if (fp + tn) else None
        fnr = fn / (fn + tp) if (fn + tp) else None
        lat = s["latencies"]
        lat_sorted = sorted(lat)
        p95 = lat_sorted[int(len(lat_sorted) * 0.95)] if lat else None
        report["per_detector"][name] = {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "false_positive_rate": round(fpr, 3) if fpr is not None else None,
            "false_negative_rate": round(fnr, 3) if fnr is not None else None,
            "avg_latency_ms": round(statistics.mean(lat), 2) if lat else None,
            "p95_latency_ms": round(p95, 2) if p95 is not None else None,
            "fp_case_ids": s["fp_cases"],
            "fn_case_ids": s["fn_cases"],
        }

    # end-to-end input-security latency over the whole dataset
    e2e_latencies = []
    for case in cases:
        result = run_input_security(case["text"])
        e2e_latencies.append(sum(r.latency_ms for r in result.results))
    e2e = sorted(e2e_latencies)
    report["input_security_e2e"] = {
        "avg_latency_ms": round(statistics.mean(e2e), 2),
        "p50_latency_ms": round(e2e[len(e2e) // 2], 2),
        "p95_latency_ms": round(e2e[int(len(e2e) * 0.95)], 2),
        "p99_latency_ms": round(e2e[min(len(e2e) - 1, int(len(e2e) * 0.99))], 2),
    }
    return report


def render_markdown(report: dict) -> str:
    lines = [
        "# Security Detector Evaluation Report",
        "",
        f"_Dataset: `{DATASET.relative_to(ROOT)}` — labeled cases per detector. "
        "All credential values in the dataset are FAKE test values._",
        "",
        "## Per-detector results",
        "",
        "| Detector | TP | TN | FP | FN | Precision | Recall | F1 | FP rate | FN rate | Avg ms | P95 ms |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, s in report["per_detector"].items():
        fmt = lambda v: f"{v:.3f}" if isinstance(v, float) else ("—" if v is None else str(v))
        lines.append(
            f"| {name} | {s['tp']} | {s['tn']} | {s['fp']} | {s['fn']} "
            f"| {fmt(s['precision'])} | {fmt(s['recall'])} | {fmt(s['f1'])} "
            f"| {fmt(s['false_positive_rate'])} | {fmt(s['false_negative_rate'])} "
            f"| {s['avg_latency_ms']} | {s['p95_latency_ms']} |"
        )

    lines += [
        "",
        "## Input security end-to-end latency (all 5 detectors per case)",
        "",
        f"- average: {report['input_security_e2e']['avg_latency_ms']} ms",
        f"- P50: {report['input_security_e2e']['p50_latency_ms']} ms",
        f"- P95: {report['input_security_e2e']['p95_latency_ms']} ms",
        f"- P99: {report['input_security_e2e']['p99_latency_ms']} ms",
        "",
    ]

    fp_lines, fn_lines = [], []
    for name, s in report["per_detector"].items():
        if s["fp_case_ids"]:
            fp_lines.append(f"- **{name}** false positives: {', '.join(s['fp_case_ids'])}")
        if s["fn_case_ids"]:
            fn_lines.append(f"- **{name}** false negatives: {', '.join(s['fn_case_ids'])}")
    lines.append("## Misclassified cases")
    lines.append("")
    lines += fp_lines or ["- none"] + fn_lines or []
    if fp_lines and fn_lines:
        lines += fn_lines

    lines += [
        "",
        "## Limitations (read before trusting these numbers)",
        "",
        "- This dataset is small and hand-labeled; it demonstrates the evaluation",
        "  methodology and gives *initial* measurements. It is NOT a benchmark of",
        "  real-world attack diversity.",
        "- Deterministic detectors miss paraphrased/novel attacks (see FN cases);",
        "  an LLM-based classifier hook exists (LLM_SECURITY_CLASSIFIER_ENABLED)",
        "  for semantic double-checking at the cost of latency.",
        "- False positives matter: an FPR above ~5% on legitimate security",
        "  documentation will erode trust in the gateway.",
        "- Thresholds in the default policy are initial values and REQUIRE",
        "  empirical tuning per deployment.",
        "",
        "Re-run with: `python scripts/evaluate_detectors.py`",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    report = evaluate()
    out = ROOT / "docs" / "evaluation-report.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nReport written to {out}")


if __name__ == "__main__":
    main()
