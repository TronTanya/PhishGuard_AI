"""Rule-based analysis of message text for PhishGuard AI.

Phrase rules use curated Russian and English patterns with word-boundary checks.
URLs found in the text are analyzed with the URL engine but never opened.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

from scoring import Finding, RuleCatalog, RuleDefinition, ScoreResult, compute_score, load_catalog, recommendations_for
from url_analyzer import UrlAnalysis, UrlContext, UrlInputError, analyze_url, default_context, parse_url

URL_PATTERN = re.compile(r"https?://[^\s<>\"'«»`]+", re.IGNORECASE)
TRAILING_PUNCTUATION = ".,;:!?…\"'»”’"
BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}
MAX_EVIDENCE_FRAGMENTS = 3
CODE_LIKE_DIGITS = re.compile(r"(?<!\d)\d(?:[ -]?\d){3,}(?!\d)")


class MessageInputError(ValueError):
    """Raised for message inputs that cannot be analyzed; the message is user-facing Russian text."""


@dataclass(frozen=True)
class ExtractedUrls:
    urls: tuple[str, ...]
    omitted: int
    total_unique: int


@dataclass(frozen=True)
class MessageUrlResult:
    raw: str
    analysis: UrlAnalysis | None
    error: str | None
    display: str


@dataclass(frozen=True)
class MessageAnalysis:
    char_count: int
    sanitized_text: str
    findings: tuple[Finding, ...]
    score: ScoreResult
    recommendations: tuple[str, ...]
    url_results: tuple[MessageUrlResult, ...]
    omitted_urls: int
    analyzed_at: datetime
    engine_version: str


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def decode_upload(data: bytes, catalog: RuleCatalog | None = None) -> str:
    """Decode an uploaded .txt file as UTF-8 with size and content checks."""
    catalog = catalog or load_catalog()
    limit = catalog.thresholds["max_upload_bytes"]
    if len(data) > limit:
        raise MessageInputError(f"Файл слишком большой: максимум {limit // 1024} КБ.")
    if not data.strip():
        raise MessageInputError("Файл пустой.")
    if b"\x00" in data:
        raise MessageInputError("Файл похож на двоичный. Загрузите обычный текстовый файл .txt.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MessageInputError(
            "Не удалось прочитать файл: он должен быть в кодировке UTF-8. "
            "Сохраните текст как «UTF-8» и загрузите снова."
        ) from exc


def validate_text(text: str | None, catalog: RuleCatalog | None = None) -> str:
    catalog = catalog or load_catalog()
    limit = catalog.thresholds["max_message_chars"]
    value = text or ""
    if not value.strip():
        raise MessageInputError("Введите текст сообщения или загрузите файл .txt.")
    if len(value) > limit:
        raise MessageInputError(
            f"Текст слишком длинный: {len(value)} символов. Максимум — {limit}."
        )
    return value


# ---------------------------------------------------------------------------
# Phrase matching
# ---------------------------------------------------------------------------

def normalize_for_matching(text: str) -> str:
    """Lower-case and replace ё with е. Keeps string length so match offsets stay valid."""
    return text.lower().replace("ё", "е")


def _compile(pattern: str) -> re.Pattern[str]:
    """Spaces in curated patterns match any run of whitespace, commas or dashes between words."""
    body = pattern.replace(" ", r"[\s,—–]+")
    return re.compile(rf"(?<!\w)(?:{body})(?!\w)", re.IGNORECASE)


@lru_cache(maxsize=None)
def _compiled_groups(rule: RuleDefinition) -> tuple[tuple[re.Pattern[str], ...], ...]:
    if rule.all_of:
        return tuple(tuple(_compile(p) for p in group) for group in rule.all_of)
    return (tuple(_compile(p) for p in rule.patterns),)


def _clean_fragment(fragment: str) -> str:
    return re.sub(r"\s+", " ", fragment).strip()


def _find_fragments(patterns: tuple[re.Pattern[str], ...], original: str, normalized: str) -> list[str]:
    spans: list[tuple[int, int]] = []
    for pattern in patterns:
        for match in pattern.finditer(normalized):
            start, end = match.span()
            if any(start < e and s < end for s, e in spans):
                continue
            spans.append((start, end))
    spans.sort()
    fragments = [_clean_fragment(original[s:e]) for s, e in spans]
    unique: dict[str, str] = {}
    for fragment in fragments:
        unique.setdefault(fragment.lower(), fragment)
    return list(unique.values())


def _format_evidence(fragments: list[str]) -> str:
    shown = fragments[:MAX_EVIDENCE_FRAGMENTS]
    text = "; ".join(f"«{f}»" for f in shown)
    if len(fragments) > len(shown):
        text += f" и ещё {len(fragments) - len(shown)}"
    return text


def match_message_rules(text: str, catalog: RuleCatalog | None = None) -> list[Finding]:
    """Apply phrase rules; each rule produces at most one finding listing its distinct fragments."""
    catalog = catalog or load_catalog()
    text_without_urls = URL_PATTERN.sub(lambda m: " " * len(m.group(0)), text)
    normalized = normalize_for_matching(text_without_urls)
    findings: list[Finding] = []
    for rule in catalog.message_rules.values():
        groups = _compiled_groups(rule)
        group_fragments = [_find_fragments(group, text_without_urls, normalized) for group in groups]
        if not all(group_fragments):
            continue
        fragments = [f for group in group_fragments for f in group]
        findings.append(catalog.make_finding(rule.rule_id, _format_evidence(fragments)))
    return findings


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

def _strip_trailing(url: str) -> str:
    while url:
        last = url[-1]
        if last in TRAILING_PUNCTUATION:
            url = url[:-1]
        elif last in BRACKET_PAIRS and url.count(last) > url.count(BRACKET_PAIRS[last]):
            url = url[:-1]
        else:
            break
    return url


def extract_urls(text: str, limit: int | None = None) -> ExtractedUrls:
    """Find unique http(s) URLs in order of appearance, trimming trailing punctuation."""
    if limit is None:
        limit = load_catalog().thresholds["max_urls_per_message"]
    unique: list[str] = []
    for match in URL_PATTERN.finditer(text):
        url = _strip_trailing(match.group(0))
        if re.fullmatch(r"https?://", url, re.IGNORECASE):
            continue
        if url not in unique:
            unique.append(url)
    return ExtractedUrls(tuple(unique[:limit]), max(0, len(unique) - limit), len(unique))


def _display_url(raw: str) -> str:
    try:
        return parse_url(raw).sanitized
    except UrlInputError:
        return "[некорректный адрес скрыт]" if "@" in raw else raw


def _mask_digits(text: str) -> str:
    return CODE_LIKE_DIGITS.sub(lambda m: "•" * len(m.group(0)), text)


def redact_text(text: str) -> str:
    """Hide URL secrets and, outside URLs, sequences of 4+ digits (possible codes or card numbers)."""
    parts: list[str] = []
    position = 0
    for match in URL_PATTERN.finditer(text):
        full = match.group(0)
        url = _strip_trailing(full)
        parts.append(_mask_digits(text[position:match.start()]))
        parts.append(_display_url(url))
        parts.append(_mask_digits(full[len(url):]))
        position = match.end()
    parts.append(_mask_digits(text[position:]))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyze_message(text: str | None, ctx: UrlContext | None = None) -> MessageAnalysis:
    """Analyze message text and each extracted URL separately. Raises MessageInputError."""
    ctx = ctx or default_context()
    catalog = ctx.catalog
    value = validate_text(text, catalog)
    findings = match_message_rules(value, catalog)
    extracted = extract_urls(value, catalog.thresholds["max_urls_per_message"])
    url_results = []
    for raw in extracted.urls:
        try:
            analysis = analyze_url(raw, ctx)
            url_results.append(MessageUrlResult(raw, analysis, None, analysis.parsed.sanitized))
        except UrlInputError as exc:
            url_results.append(MessageUrlResult(raw, None, str(exc), _display_url(raw)))
    return MessageAnalysis(
        char_count=len(value),
        sanitized_text=redact_text(value),
        findings=tuple(findings),
        score=compute_score(findings),
        recommendations=tuple(recommendations_for(findings, catalog)),
        url_results=tuple(url_results),
        omitted_urls=extracted.omitted,
        analyzed_at=datetime.now().astimezone(),
        engine_version=catalog.engine_version,
    )


def strongest_score(analysis: MessageAnalysis) -> int:
    """Highest of the text score and individual URL scores (used only by the experiment's decision rule)."""
    scores = [analysis.score.total]
    scores += [r.analysis.score.total for r in analysis.url_results if r.analysis is not None]
    return max(scores)
