"""Run PhishGuard AI rules on the labeled demonstration dataset and report metrics.

Decision rule: an example is predicted "suspicious" when its concern index is at least
the threshold. For messages the highest of the text index and each URL index is used
(scores are never summed across unrelated links).

Usage:
    python experiments/evaluate.py [--threshold 25] [--output-dir experiments/results]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from message_analyzer import analyze_message, redact_text, strongest_score  # noqa: E402
from scoring import load_catalog, load_json  # noqa: E402
from url_analyzer import UrlInputError, analyze_url  # noqa: E402

DISCLAIMER = (
    "Оценка выполнена на небольшом учебном наборе примеров и не отражает точность "
    "на реальном интернет-трафике."
)
POSITIVE = "suspicious"
NEGATIVE = "benign"


@dataclass(frozen=True)
class ExampleResult:
    example_id: str
    subset: str
    input_type: str
    label: str
    sanitized_input: str
    score: int
    predicted: str
    triggered_rules: tuple[str, ...]
    expected_rules: tuple[str, ...]
    error: str | None

    @property
    def rules_match(self) -> bool:
        return set(self.triggered_rules) == set(self.expected_rules)


def run_example(example: dict[str, Any], threshold: int) -> ExampleResult:
    error = None
    if example["input_type"] == "url":
        try:
            analysis = analyze_url(example["input"])
            score = analysis.score.total
            rules = [f.rule_id for f in analysis.findings]
            sanitized = analysis.parsed.sanitized
        except UrlInputError as exc:
            score, rules, sanitized, error = 0, [], "[ошибка разбора]", str(exc)
    else:
        analysis = analyze_message(example["input"])
        score = strongest_score(analysis)
        rules = [f.rule_id for f in analysis.findings]
        for result in analysis.url_results:
            if result.analysis is not None:
                rules += [f.rule_id for f in result.analysis.findings]
        sanitized = redact_text(example["input"])
    return ExampleResult(
        example_id=example["id"],
        subset=example["subset"],
        input_type=example["input_type"],
        label=example["label"],
        sanitized_input=sanitized,
        score=score,
        predicted=POSITIVE if score >= threshold else NEGATIVE,
        triggered_rules=tuple(dict.fromkeys(rules)),
        expected_rules=tuple(example.get("expected_rules", ())),
        error=error,
    )


def safe_divide(numerator: int, denominator: int) -> float | None:
    """Return None when the metric is undefined (zero denominator) instead of guessing 0 or 1."""
    return None if denominator == 0 else numerator / denominator


def confusion_matrix(results: list[ExampleResult]) -> dict[str, int]:
    matrix = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for r in results:
        if r.label == POSITIVE:
            matrix["tp" if r.predicted == POSITIVE else "fn"] += 1
        else:
            matrix["fp" if r.predicted == POSITIVE else "tn"] += 1
    return matrix


def compute_metrics(matrix: dict[str, int]) -> dict[str, float | None]:
    precision = safe_divide(matrix["tp"], matrix["tp"] + matrix["fp"])
    recall = safe_divide(matrix["tp"], matrix["tp"] + matrix["fn"])
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def undefined_reasons(matrix: dict[str, int], metrics: dict[str, float | None]) -> list[str]:
    reasons = []
    if metrics["precision"] is None:
        reasons.append("precision не определена: нет примеров, предсказанных как подозрительные (TP + FP = 0).")
    if metrics["recall"] is None:
        reasons.append("recall не определена: в подмножестве нет подозрительных примеров (TP + FN = 0).")
    if metrics["f1"] is None:
        reasons.append("F1 не определена, так как не определена precision или recall.")
    return reasons


def summarize(results: list[ExampleResult]) -> dict[str, Any]:
    matrix = confusion_matrix(results)
    metrics = compute_metrics(matrix)
    return {
        "count": len(results),
        "suspicious": sum(r.label == POSITIVE for r in results),
        "benign": sum(r.label == NEGATIVE for r in results),
        "confusion_matrix": matrix,
        "metrics": metrics,
        "undefined": undefined_reasons(matrix, metrics),
        "rule_expectation_matches": sum(r.rules_match for r in results),
    }


def fmt(value: float | None) -> str:
    return "не определена" if value is None else f"{value:.3f}"


def write_outputs(results: list[ExampleResult], summary: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "evaluation_results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "id", "subset", "input_type", "label", "predicted", "score",
            "triggered_rules", "expected_rules", "rules_match", "error", "sanitized_input",
        ])
        for r in results:
            writer.writerow([
                r.example_id, r.subset, r.input_type, r.label, r.predicted, r.score,
                " ".join(r.triggered_rules), " ".join(r.expected_rules), r.rules_match, r.error or "", r.sanitized_input,
            ])
    (output_dir / "evaluation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    catalog = load_catalog()
    parser = argparse.ArgumentParser(description="Оценка PhishGuard AI на учебном наборе примеров")
    parser.add_argument("--threshold", type=int, default=catalog.thresholds["evaluation_threshold"],
                        help="порог индекса для класса «подозрительный» (по умолчанию из rules.json)")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "experiments" / "results")
    args = parser.parse_args(argv)

    dataset = load_json("evaluation_examples.json")
    results = [run_example(example, args.threshold) for example in dataset["examples"]]
    subsets = {
        name: summarize([r for r in results if r.subset == name])
        for name in ("development", "evaluation")
    }
    summary = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "engine_version": catalog.engine_version,
        "threshold": args.threshold,
        "decision_rule": "suspicious, если индекс >= порога; для сообщений берётся наибольший из индексов текста и отдельных ссылок",
        "disclaimer": DISCLAIMER,
        "subsets": subsets,
    }
    write_outputs(results, summary, args.output_dir)

    print(f"PhishGuard AI — движок правил {catalog.engine_version}, порог {args.threshold}")
    print(DISCLAIMER)
    for name, title in (("development", "Подмножество разработки правил"), ("evaluation", "Оценочное подмножество")):
        s = subsets[name]
        cm = s["confusion_matrix"]
        m = s["metrics"]
        print(f"\n{title}: {s['count']} примеров ({s['suspicious']} подозрительных, {s['benign']} безопасных)")
        print("                      предсказано: подозр.   безопасн.")
        print(f"  размечено: подозр.          TP = {cm['tp']:<3}    FN = {cm['fn']}")
        print(f"  размечено: безопасн.        FP = {cm['fp']:<3}    TN = {cm['tn']}")
        print(f"  precision = {fmt(m['precision'])}, recall = {fmt(m['recall'])}, F1 = {fmt(m['f1'])}")
        for reason in s["undefined"]:
            print(f"  {reason}")
        print(f"  Совпадение сработавших правил с ожидаемыми: {s['rule_expectation_matches']} из {s['count']}")

    errors = [r for r in results if r.label != r.predicted or not r.rules_match]
    if errors:
        print("\nРасхождения (ошибки классификации или неожиданные правила):")
        for r in errors:
            parts = []
            if r.label != r.predicted:
                parts.append(f"разметка {r.label}, предсказание {r.predicted} (индекс {r.score})")
            if not r.rules_match:
                missing = sorted(set(r.expected_rules) - set(r.triggered_rules))
                extra = sorted(set(r.triggered_rules) - set(r.expected_rules))
                parts.append(f"не сработали: {missing or '-'}; лишние: {extra or '-'}")
            print(f"  {r.example_id}: " + "; ".join(parts))
    print(f"\nРезультаты сохранены в {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
