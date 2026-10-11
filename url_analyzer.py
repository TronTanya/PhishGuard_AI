"""URL parsing and rule-based URL indicators for PhishGuard AI.

Analysis is purely local: submitted URLs are never opened, resolved or downloaded.
"""

from __future__ import annotations

import codecs
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Callable
from urllib.parse import SplitResult, unquote, unquote_plus, urlsplit

import tldextract

from scoring import Finding, RuleCatalog, ScoreResult, compute_score, load_catalog, load_json, recommendations_for

SUPPORTED_SCHEMES = ("http", "https")
RESERVED_TLDS = ("test", "example", "invalid", "localhost")
REDACTED = "***"
URL_EXAMPLE = "https://example.com/login"

SENSITIVE_KEYS_EXACT = frozenset(
    {"code", "key", "pin", "sid", "sig", "signature", "card", "cardnumber", "pan", "cvc", "hash"}
)
SENSITIVE_KEY_PARTS = ("token", "pass", "secret", "pwd", "otp", "cvv", "apikey", "api_key", "session", "auth")

CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "к": "k",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ү": "y",
    "0": "o", "1": "l", "3": "e", "5": "s",
}
MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"))


class UrlInputError(ValueError):
    """Raised for inputs that cannot be analyzed; the message is user-facing Russian text."""


@dataclass(frozen=True)
class ParsedUrl:
    original: str
    sanitized: str
    scheme: str
    hostname: str
    hostname_unicode: str
    is_ip: bool
    port: int | None
    has_credentials: bool
    username: str
    has_password: bool
    registrable_domain: str
    registrable_domain_unicode: str
    subdomain: str
    domain_label: str
    suffix: str
    path: str
    path_decoded: str
    query: str
    fragment: str
    host_percent_encoded: bool
    redacted_keys: tuple[str, ...]

    @property
    def is_idn(self) -> bool:
        return any(label.startswith("xn--") for label in self.hostname.split("."))

    @property
    def subdomain_levels(self) -> int:
        return len(self.subdomain.split(".")) if self.subdomain else 0


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    official_domains: tuple[str, ...]


@dataclass(frozen=True)
class UrlAnalysis:
    parsed: ParsedUrl
    findings: tuple[Finding, ...]
    score: ScoreResult
    recommendations: tuple[str, ...]
    analyzed_at: datetime
    engine_version: str


@dataclass(frozen=True)
class UrlContext:
    catalog: RuleCatalog
    brands: tuple[Brand, ...]
    shorteners: frozenset[str]


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def load_brands() -> tuple[Brand, ...]:
    data = load_json("brand_domains.json")
    return tuple(
        Brand(
            name=item["name"],
            keywords=tuple(k.lower() for k in item["keywords"]),
            official_domains=tuple(d.lower() for d in item["official_domains"]),
        )
        for item in data["brands"]
    )


@lru_cache(maxsize=1)
def load_shorteners() -> frozenset[str]:
    return frozenset(d.lower() for d in load_json("shorteners.json")["domains"])


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # Empty suffix_list_urls and no cache: only the bundled public-suffix snapshot is used.
    return tldextract.TLDExtract(
        cache_dir=None,
        suffix_list_urls=(),
        fallback_to_snapshot=True,
        extra_suffixes=RESERVED_TLDS,
    )


def default_context() -> UrlContext:
    return UrlContext(load_catalog(), load_brands(), load_shorteners())


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _check_scheme(text: str) -> None:
    lower = text.lower()
    if lower.startswith(("http://", "https://")):
        return
    if re.match(r"^https?:", lower):
        raise UrlInputError(
            f"После «http:» или «https:» должны идти две косые черты. Пример: {URL_EXAMPLE}"
        )
    other = re.match(r"^([a-z][a-z0-9+.\-]*)://", lower) or re.match(
        r"^(javascript|data|vbscript|file|mailto|ftp|tel|blob|about):", lower
    )
    if other:
        raise UrlInputError(
            f"Схема «{other.group(1)}» не поддерживается. Проверяются только адреса http:// и https://."
        )
    raise UrlInputError(
        f"Укажите протокол явно: адрес должен начинаться с http:// или https://. Пример: {URL_EXAMPLE}"
    )


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Recognize standard IP literals and numeric IPv4 forms that browsers accept (e.g. 3232235777, 0x7f.1)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(re.fullmatch(r"0x[0-9a-f]*|\d+", p) for p in parts):
        return None
    try:
        numbers = [int(p, 16) if p.startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p) for p in parts]
    except ValueError:
        return None
    *head, last = numbers
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (4 - len(head)) + last
    return ipaddress.IPv4Address(value)


def _label_to_ascii(label: str) -> str:
    if label.isascii():
        return label
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError:
        try:
            return "xn--" + label.encode("punycode").decode("ascii")
        except UnicodeError as exc:
            raise UrlInputError(f"Не удалось преобразовать метку имени хоста «{label}».") from exc


def _label_to_unicode(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    error = UrlInputError(f"Некорректная Punycode-запись в имени хоста: «{label}».")
    try:
        decoded = codecs.decode(label[4:].encode("ascii"), "punycode")
    except (UnicodeError, ValueError) as exc:
        raise error from exc
    if not decoded or decoded.isascii() or any(unicodedata.category(ch)[0] in "CZ" for ch in decoded):
        raise error
    return decoded


def _is_sensitive_key(key: str) -> bool:
    norm = unquote_plus(key).strip().lower().replace("-", "_")
    return norm in SENSITIVE_KEYS_EXACT or any(part in norm for part in SENSITIVE_KEY_PARTS)


def redact_pairs(value: str) -> tuple[str, list[str]]:
    """Replace values of sensitive key=value pairs (query or fragment) with ***."""
    redacted: list[str] = []
    parts = []
    for part in value.split("&"):
        key, eq, val = part.partition("=")
        if eq and val and _is_sensitive_key(key):
            parts.append(f"{key}={REDACTED}")
            redacted.append(unquote_plus(key))
        else:
            parts.append(part)
    return "&".join(parts), redacted


def _build_sanitized(text: str, split: SplitResult, query: str, fragment: str) -> str:
    scheme_typed = text.split("://", 1)[0]
    userinfo, at, hostport = split.netloc.rpartition("@")
    netloc = hostport
    if at:
        user, colon, _password = userinfo.partition(":")
        netloc = f"{user}:{REDACTED}@{hostport}" if colon else f"{user}@{hostport}"
    result = f"{scheme_typed}://{netloc}{split.path}"
    if split.query or "?" in text.split("#", 1)[0]:
        result += f"?{query}"
    if split.fragment or "#" in text:
        result += f"#{fragment}"
    return result


def parse_url(raw: str | None) -> ParsedUrl:
    """Validate and parse an HTTP(S) URL without any network access."""
    catalog = load_catalog()
    max_length = catalog.thresholds["max_url_length"]
    text = (raw or "").strip()
    if not text:
        raise UrlInputError(f"Введите адрес ссылки для проверки. Пример: {URL_EXAMPLE}")
    if len(text) > max_length:
        raise UrlInputError(
            f"Адрес слишком длинный: {len(text)} символов. Максимум — {max_length}."
        )
    if any(ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf") for ch in text):
        raise UrlInputError(
            "Адрес не должен содержать пробелы, переводы строк или невидимые управляющие символы."
        )
    if "\\" in text:
        raise UrlInputError(
            "Адрес содержит обратную косую черту «\\», которую браузеры трактуют по-разному. "
            "Замените её на «/» и повторите проверку."
        )
    _check_scheme(text)

    try:
        split = urlsplit(text)
        port = split.port
    except ValueError as exc:
        if "port" in str(exc).lower():
            raise UrlInputError("Некорректный порт: допустимы целые числа от 1 до 65535.") from exc
        raise UrlInputError("Адрес имеет некорректный формат и не может быть разобран.") from exc
    if port == 0:
        raise UrlInputError("Некорректный порт: допустимы целые числа от 1 до 65535.")

    if not split.netloc:
        raise UrlInputError(f"В адресе не указано имя хоста. Пример: {URL_EXAMPLE}")
    userinfo, at, _ = split.netloc.rpartition("@")
    has_credentials = bool(at)
    username, colon, password = userinfo.partition(":")

    host = split.hostname or ""
    host_percent_encoded = "%" in host
    if host_percent_encoded:
        host = unquote(host).lower()
        if any(ch.isspace() or ch in "/@?#:\\" for ch in host):
            raise UrlInputError("Имя хоста содержит недопустимые закодированные символы.")
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise UrlInputError(f"В адресе не указано имя хоста. Пример: {URL_EXAMPLE}")

    ip = _parse_ip(host)
    if ip is not None:
        hostname = hostname_unicode = str(ip)
        registrable = registrable_unicode = subdomain = domain_label = suffix = ""
    else:
        labels = host.split(".")
        if any(not label for label in labels):
            raise UrlInputError("Имя хоста содержит пустую часть (например, две точки подряд).")
        ascii_labels = [_label_to_ascii(label) for label in labels]
        for label in ascii_labels:
            if len(label) > 63 or not re.fullmatch(r"[a-z0-9_\-]+", label):
                raise UrlInputError(f"Имя хоста содержит недопустимую часть: «{label[:70]}».")
        hostname = ".".join(ascii_labels)
        if len(hostname) > 253:
            raise UrlInputError("Имя хоста длиннее 253 символов.")
        hostname_unicode = ".".join(_label_to_unicode(label) for label in ascii_labels)
        extracted = _extractor()(hostname)
        subdomain = ".".join(_label_to_unicode(l) for l in extracted.subdomain.split(".")) if extracted.subdomain else ""
        domain_label = extracted.domain
        suffix = extracted.suffix
        if extracted.domain and extracted.suffix:
            registrable = f"{extracted.domain}.{extracted.suffix}"
            registrable_unicode = ".".join(_label_to_unicode(l) for l in registrable.split("."))
        else:
            registrable = registrable_unicode = ""

    query, redacted_query = redact_pairs(split.query)
    fragment, redacted_fragment = redact_pairs(split.fragment) if "=" in split.fragment else (split.fragment, [])

    return ParsedUrl(
        original=text,
        sanitized=_build_sanitized(text, split, query, fragment),
        scheme=split.scheme.lower(),
        hostname=hostname,
        hostname_unicode=hostname_unicode,
        is_ip=ip is not None,
        port=port,
        has_credentials=has_credentials,
        username=unquote(username),
        has_password=bool(colon),
        registrable_domain=registrable,
        registrable_domain_unicode=registrable_unicode,
        subdomain=subdomain,
        domain_label=domain_label,
        suffix=suffix,
        path=split.path,
        path_decoded=unquote(split.path, errors="replace"),
        query=query,
        fragment=fragment,
        host_percent_encoded=host_percent_encoded,
        redacted_keys=tuple(dict.fromkeys(redacted_query + redacted_fragment)),
    )


# ---------------------------------------------------------------------------
# Helpers for brand and script checks
# ---------------------------------------------------------------------------

def skeleton(text: str) -> str:
    """Map a small, documented set of look-alike characters to Latin for brand comparison."""
    result = "".join(CONFUSABLES.get(ch, ch) for ch in text.lower())
    for source, target in MULTI_CHAR_CONFUSABLES:
        result = result.replace(source, target)
    return result


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (insertions, deletions, substitutions, adjacent transpositions)."""
    rows = len(a) + 1
    cols = len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    if name.startswith("LATIN"):
        return "latin"
    if name.startswith("CYRILLIC"):
        return "cyrillic"
    return None


def mixed_script_labels(hostname_unicode: str) -> list[tuple[str, list[str]]]:
    """Return labels mixing Latin and Cyrillic letters, with the Cyrillic characters found."""
    result = []
    for label in hostname_unicode.split("."):
        scripts = {_script_of(ch) for ch in label} - {None}
        if {"latin", "cyrillic"} <= scripts:
            cyrillic = [f"«{ch}» (U+{ord(ch):04X})" for ch in dict.fromkeys(label) if _script_of(ch) == "cyrillic"]
            result.append((label, cyrillic))
    return result


def _is_official(registrable: str, brand: Brand) -> bool:
    return registrable in brand.official_domains


def _official_text(brand: Brand) -> str:
    return ", ".join(brand.official_domains)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def rule_credentials(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if not p.has_credentials:
        return None
    user = p.username or "(пусто)"
    password_note = " и пароль (скрыт)" if p.has_password else ""
    evidence = f"До символа @ указано имя «{user}»{password_note}. Фактический хост: {p.hostname_unicode}"
    return ctx.catalog.make_finding("URL_CREDENTIALS", evidence)


def rule_ip_host(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if not p.is_ip:
        return None
    return ctx.catalog.make_finding("URL_IP_HOST", f"Хост: {p.hostname}")


def rule_http(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if p.scheme != "http":
        return None
    return ctx.catalog.make_finding("URL_HTTP", "Схема: http://")


def rule_many_subdomains(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    limit = ctx.catalog.thresholds["max_subdomain_levels"]
    if p.is_ip or p.subdomain_levels <= limit:
        return None
    evidence = f"Поддомен «{p.subdomain}»: уровней — {p.subdomain_levels} (порог: больше {limit})"
    return ctx.catalog.make_finding("URL_MANY_SUBDOMAINS", evidence)


def rule_long_url(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    limit = ctx.catalog.thresholds["long_url_length"]
    if len(p.original) <= limit:
        return None
    return ctx.catalog.make_finding("URL_LONG", f"Длина адреса: {len(p.original)} символов (порог: {limit})")


def rule_idn(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if p.is_ip or not p.is_idn:
        return None
    evidence = f"Punycode: {p.hostname}; декодированное имя: {p.hostname_unicode}"
    return ctx.catalog.make_finding("URL_IDN", evidence)


def rule_mixed_script(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if p.is_ip:
        return None
    labels = mixed_script_labels(p.hostname_unicode)
    if not labels:
        return None
    evidence = "; ".join(f"метка «{label}», кириллические символы: {', '.join(chars)}" for label, chars in labels)
    return ctx.catalog.make_finding("URL_MIXED_SCRIPT", evidence)


def rule_percent_host(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if not p.host_percent_encoded:
        return None
    return ctx.catalog.make_finding("URL_PERCENT_ENCODED_HOST", f"Декодированный хост: {p.hostname_unicode}")


def rule_shortener(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if p.is_ip:
        return None
    candidates = {p.hostname, p.registrable_domain}
    matched = next((d for d in sorted(ctx.shorteners) if d in candidates or p.hostname.endswith("." + d)), None)
    if matched is None:
        return None
    return ctx.catalog.make_finding("URL_SHORTENER", f"Домен {matched} есть в локальном списке сокращателей")


def rule_brand_subdomain(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if p.is_ip or not p.subdomain:
        return None
    tokens = set(re.split(r"[.\-_]", skeleton(p.subdomain)))
    hits = []
    for brand in ctx.brands:
        if _is_official(p.registrable_domain, brand):
            continue
        keyword = next((k for k in brand.keywords if k in tokens), None)
        if keyword:
            hits.append(
                f"поддомен «{p.subdomain}» содержит «{keyword}» ({brand.name}), "
                f"регистрируемый домен: {p.registrable_domain_unicode or p.hostname_unicode}; "
                f"официальный домен: {_official_text(brand)}"
            )
    return ctx.catalog.make_finding("URL_BRAND_IN_SUBDOMAIN", "; ".join(hits)) if hits else None


def _near_match(label: str, keyword: str, ctx: UrlContext) -> str | None:
    """Return a Russian description of how `label` imitates `keyword`, or None."""
    t = ctx.catalog.thresholds
    if label == keyword:
        return "совпадает название, но домен не официальный"
    normalized = skeleton(label)
    compact = normalized.replace("-", "")
    if normalized == keyword or compact == keyword:
        return f"после замены похожих символов и удаления дефисов получается «{keyword}»"
    min_len = t["brand_min_length_for_near_match"]
    if len(keyword) < min_len or len(compact) < min_len:
        return None
    allowed = t["brand_max_edit_distance_long"] if len(keyword) >= t["brand_long_name_length"] else t["brand_max_edit_distance_short"]
    distance = edit_distance(compact, keyword)
    if 0 < distance <= allowed:
        return f"отличается от «{keyword}» на {distance} симв."
    return None


def _domain_label_unicode(p: ParsedUrl) -> str:
    return _label_to_unicode(p.domain_label) if p.domain_label else ""


def rule_brand_near_match(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if p.is_ip or not p.registrable_domain:
        return None
    label = _domain_label_unicode(p).lower()
    hits = []
    for brand in ctx.brands:
        if _is_official(p.registrable_domain, brand):
            continue
        for keyword in brand.keywords:
            how = _near_match(label, keyword, ctx)
            if how:
                hits.append(
                    f"домен {p.registrable_domain_unicode}: {how} ({brand.name}); "
                    f"официальный домен: {_official_text(brand)}"
                )
                break
    return ctx.catalog.make_finding("URL_BRAND_NEAR_MATCH", "; ".join(hits)) if hits else None


def rule_brand_token(p: ParsedUrl, ctx: UrlContext) -> Finding | None:
    if p.is_ip or not p.registrable_domain:
        return None
    label = _domain_label_unicode(p).lower()
    tokens = skeleton(label).split("-")
    if len(tokens) < 2:
        return None
    hits = []
    for brand in ctx.brands:
        if _is_official(p.registrable_domain, brand):
            continue
        if any(_near_match(label, k, ctx) for k in brand.keywords):
            continue
        keyword = next((k for k in brand.keywords if k in tokens), None)
        if keyword:
            hits.append(
                f"домен {p.registrable_domain_unicode} содержит слово «{keyword}» ({brand.name}); "
                f"официальный домен: {_official_text(brand)}"
            )
    return ctx.catalog.make_finding("URL_BRAND_TOKEN_IN_DOMAIN", "; ".join(hits)) if hits else None


URL_RULES: tuple[Callable[[ParsedUrl, UrlContext], Finding | None], ...] = (
    rule_credentials,
    rule_ip_host,
    rule_http,
    rule_many_subdomains,
    rule_long_url,
    rule_idn,
    rule_mixed_script,
    rule_percent_host,
    rule_shortener,
    rule_brand_subdomain,
    rule_brand_near_match,
    rule_brand_token,
)


def run_url_rules(parsed: ParsedUrl, ctx: UrlContext | None = None) -> list[Finding]:
    ctx = ctx or default_context()
    findings = []
    for rule in URL_RULES:
        finding = rule(parsed, ctx)
        if finding is not None:
            findings.append(finding)
    return findings


def analyze_url(raw: str | None, ctx: UrlContext | None = None) -> UrlAnalysis:
    """Parse and analyze a URL. Raises UrlInputError for invalid input."""
    ctx = ctx or default_context()
    parsed = parse_url(raw)
    findings = run_url_rules(parsed, ctx)
    return UrlAnalysis(
        parsed=parsed,
        findings=tuple(findings),
        score=compute_score(findings),
        recommendations=tuple(recommendations_for(findings, ctx.catalog)),
        analyzed_at=datetime.now().astimezone(),
        engine_version=ctx.catalog.engine_version,
    )
