"""Rule catalog, findings and the heuristic concern index for PhishGuard AI.

The index is a sum of explicit per-rule weights, clamped to 0..100. It reflects
which rules fired; it is not a probability of phishing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

CONTENT_DIR = Path(__file__).resolve().parent / "content"

SCORE_MIN = 0
SCORE_MAX = 100

SEVERITY_LABELS: dict[str, str] = {
    "strong": "Сильный",
    "moderate": "Умеренный",
    "weak": "Слабый",
}

SCORE_DISCLAIMER = (
    "Индекс отражает сработавшие правила. Это не вероятность фишинга и не гарантия безопасности."
)

NO_FINDINGS_NOTE = (
    "Локальные правила не обнаружили признаков, но они не способны выявить все попытки фишинга. "
    "Отсутствие срабатываний не означает, что ссылка или сообщение безопасны."
)


@dataclass(frozen=True)
class ScoreBand:
    level: str
    label: str
    min_score: int
    max_score: int


SCORE_BANDS: tuple[ScoreBand, ...] = (
    ScoreBand("none", "Признаки по текущим правилам не обнаружены", 0, 0),
    ScoreBand("low", "Есть признаки для проверки", 1, 24),
    ScoreBand("medium", "Требуется внимательная проверка", 25, 49),
    ScoreBand("high", "Обнаружено несколько существенных признаков", 50, 100),
)


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    category: str
    severity: str
    weight: int
    title: str
    explanation: str
    action: str
    recommendation: str
    patterns: tuple[str, ...] = ()
    all_of: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    evidence: str
    explanation: str
    action: str
    recommendation: str
    score: int

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, self.severity)


@dataclass(frozen=True)
class Contribution:
    rule_id: str
    title: str
    severity: str
    points: int


@dataclass(frozen=True)
class ScoreResult:
    total: int
    raw_total: int
    contributions: tuple[Contribution, ...]
    band: ScoreBand

    @property
    def was_clamped(self) -> bool:
        return self.raw_total != self.total

    @property
    def rule_count(self) -> int:
        return len(self.contributions)


@dataclass(frozen=True)
class RuleCatalog:
    engine_version: str
    severity_weights: dict[str, int]
    thresholds: dict[str, int]
    threshold_notes: dict[str, str]
    recommendations: dict[str, str]
    url_rules: dict[str, RuleDefinition]
    message_rules: dict[str, RuleDefinition]
    extra: dict[str, Any] = field(default_factory=dict)

    def rule(self, rule_id: str) -> RuleDefinition:
        if rule_id in self.url_rules:
            return self.url_rules[rule_id]
        if rule_id in self.message_rules:
            return self.message_rules[rule_id]
        raise KeyError(f"Неизвестное правило: {rule_id}")

    def make_finding(self, rule_id: str, evidence: str) -> Finding:
        rule = self.rule(rule_id)
        return Finding(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=rule.severity,
            title=rule.title,
            evidence=evidence,
            explanation=rule.explanation,
            action=rule.action,
            recommendation=rule.recommendation,
            score=rule.weight,
        )


def load_json(name: str) -> dict[str, Any]:
    with (CONTENT_DIR / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def _parse_rule(raw: dict[str, Any], severity_weights: dict[str, int]) -> RuleDefinition:
    severity = raw["severity"]
    weight = int(raw["weight"])
    if severity not in severity_weights:
        raise ValueError(f"Правило {raw['id']}: неизвестная степень «{severity}»")
    if weight != severity_weights[severity]:
        raise ValueError(
            f"Правило {raw['id']}: вес {weight} не соответствует степени «{severity}» "
            f"({severity_weights[severity]})"
        )
    return RuleDefinition(
        rule_id=raw["id"],
        category=raw["category"],
        severity=severity,
        weight=weight,
        title=raw["title"],
        explanation=raw["explanation"],
        action=raw["action"],
        recommendation=raw["recommendation"],
        patterns=tuple(raw.get("patterns", ())),
        all_of=tuple(tuple(group) for group in raw.get("all_of", ())),
    )


@lru_cache(maxsize=1)
def load_catalog() -> RuleCatalog:
    data = load_json("rules.json")
    weights = {key: int(value) for key, value in data["severity_weights"].items()}
    recommendations = data["recommendations"]
    url_rules = {r["id"]: _parse_rule(r, weights) for r in data["url_rules"]}
    message_rules = {r["id"]: _parse_rule(r, weights) for r in data["message_rules"]}
    for rule in [*url_rules.values(), *message_rules.values()]:
        if rule.recommendation not in recommendations:
            raise ValueError(f"Правило {rule.rule_id}: нет рекомендации «{rule.recommendation}»")
    return RuleCatalog(
        engine_version=data["engine_version"],
        severity_weights=weights,
        thresholds={key: int(value) for key, value in data["thresholds"].items()},
        threshold_notes=data.get("threshold_notes", {}),
        recommendations=recommendations,
        url_rules=url_rules,
        message_rules=message_rules,
    )


def band_for(score: int) -> ScoreBand:
    for band in SCORE_BANDS:
        if band.min_score <= score <= band.max_score:
            return band
    raise ValueError(f"Индекс вне диапазона: {score}")


def compute_score(findings: Iterable[Finding]) -> ScoreResult:
    """Sum rule weights, counting each rule once, and clamp to 0..100."""
    seen: set[str] = set()
    contributions: list[Contribution] = []
    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        contributions.append(
            Contribution(finding.rule_id, finding.title, finding.severity, finding.score)
        )
    raw_total = sum(c.points for c in contributions)
    total = max(SCORE_MIN, min(SCORE_MAX, raw_total))
    return ScoreResult(total, raw_total, tuple(contributions), band_for(total))


def recommendations_for(findings: Iterable[Finding], catalog: RuleCatalog | None = None) -> list[str]:
    """Return unique recommendations linked to actual findings, in order of first appearance."""
    catalog = catalog or load_catalog()
    keys: list[str] = []
    for finding in findings:
        if finding.recommendation not in keys:
            keys.append(finding.recommendation)
    return [catalog.recommendations[key] for key in keys]
