"""Standalone HTML report export for PhishGuard AI.

All user-provided content is HTML-escaped; submitted URLs are rendered as plain,
non-clickable text. Reports are generated in memory and never stored automatically.
"""

from __future__ import annotations

from datetime import datetime
from html import escape

from message_analyzer import MessageAnalysis
from scoring import NO_FINDINGS_NOTE, SCORE_DISCLAIMER, Finding, ScoreResult
from url_analyzer import ParsedUrl, UrlAnalysis

LIMITATIONS: tuple[str, ...] = (
    "Анализ основан на прозрачных правилах, а не на обученной модели машинного обучения.",
    "Содержимое веб-страниц не загружается и не проверяется; ссылки не открываются.",
    "Живые базы угроз и репутационные сервисы не запрашиваются.",
    "Возможны ложные срабатывания (например, на учебные предупреждения) и пропуски фишинга.",
    "Списки брендов и сокращателей ссылок иллюстративны, ограничены и требуют обновления.",
    "Проверка похожих символов ограничена латиницей и кириллицей.",
    "Индекс подозрительных признаков — не вероятность фишинга и не гарантия безопасности.",
)

LEVEL_COLORS = {"none": "#667085", "low": "#B7791F", "medium": "#B7791F", "high": "#C43D3D"}

_STYLE = """
body{margin:0;background:#F7F8FA;color:#202733;font:14px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:24px 0 8px}h3{font-size:15px;margin:16px 0 6px}
.muted{color:#667085}
.box{background:#FFFFFF;border:1px solid #E4E7EC;border-radius:6px;padding:12px 16px;margin:8px 0}
.mono{font-family:Consolas,"SFMono-Regular",Menlo,monospace;word-break:break-all}
table{width:100%;border-collapse:collapse;background:#FFFFFF;border:1px solid #E4E7EC}
th,td{border-bottom:1px solid #E4E7EC;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#F7F8FA;font-weight:600}
.level{font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;margin:0}
"""


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _format_date(moment: datetime) -> str:
    return moment.strftime("%d.%m.%Y %H:%M:%S %Z").strip()


def report_filename(kind: str, moment: datetime | None = None) -> str:
    moment = moment or datetime.now()
    return f"phishguard-{kind}-{moment.strftime('%Y%m%d-%H%M%S')}.html"


def _domain_rows(p: ParsedUrl) -> list[tuple[str, str]]:
    host = p.hostname if p.hostname == p.hostname_unicode else f"{p.hostname_unicode} ({p.hostname})"
    rows = [
        ("Схема", p.scheme),
        ("Фактический хост", host),
        ("Тип хоста", "IP-адрес" if p.is_ip else "Доменное имя"),
        ("Регистрируемый домен", p.registrable_domain_unicode or "не определён"),
        ("Поддомен", p.subdomain or "нет"),
        ("Путь", p.path_decoded or "/"),
    ]
    if p.port is not None:
        rows.append(("Порт", str(p.port)))
    if p.has_credentials:
        rows.append(("Учётные данные в адресе", "есть (пароль скрыт)" if p.has_password else "есть (имя пользователя)"))
    if p.redacted_keys:
        rows.append(("Скрытые параметры", ", ".join(p.redacted_keys)))
    return rows


def _domain_table(p: ParsedUrl) -> str:
    body = "".join(
        f"<tr><th>{_e(k)}</th><td class=\"mono\">{_e(v)}</td></tr>" for k, v in _domain_rows(p)
    )
    return f"<table>{body}</table>"


def _findings_table(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return f"<div class=\"box\">{_e(NO_FINDINGS_NOTE)}</div>"
    rows = "".join(
        "<tr>"
        f"<td>{_e(f.title)}<br><span class=\"muted\">{_e(f.rule_id)} · {_e(f.severity_label)}</span></td>"
        f"<td class=\"mono\">{_e(f.evidence)}</td>"
        f"<td>{_e(f.explanation)}</td>"
        f"<td>{_e(f.action)}</td>"
        f"<td>+{f.score}</td>"
        "</tr>"
        for f in findings
    )
    head = "<tr><th>Признак</th><th>Доказательство</th><th>Объяснение</th><th>Что сделать</th><th>Баллы</th></tr>"
    return f"<table>{head}{rows}</table>"


def _score_block(score: ScoreResult) -> str:
    color = LEVEL_COLORS[score.band.level]
    if score.contributions:
        parts = " + ".join(f"{c.points} ({_e(c.rule_id)})" for c in score.contributions)
        calc = f"{parts} = {score.raw_total}"
        if score.was_clamped:
            calc += f", ограничено до {score.total}"
    else:
        calc = "Правила не сработали: 0"
    return (
        "<div class=\"box\">"
        f"<div>Индекс подозрительных признаков: <b>{score.total}</b> из 100 — "
        f"<span class=\"level\" style=\"color:{color}\">{_e(score.band.label)}</span></div>"
        f"<div class=\"muted\">Расчёт: {calc}</div>"
        f"<div class=\"muted\">{_e(SCORE_DISCLAIMER)}</div>"
        "</div>"
    )


def _list(items: tuple[str, ...] | list[str]) -> str:
    return "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in items) + "</ul>"


def _document(title: str, analyzed_at: datetime, input_type: str, engine_version: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        f"<title>{_e(title)}</title><style>{_STYLE}</style></head><body><main>"
        "<h1>PhishGuard AI — отчёт об анализе</h1>"
        "<div class=\"muted\">Анализ признаков фишинга в ссылках и сообщениях</div>"
        "<div class=\"box\">"
        f"<div>Дата анализа: {_e(_format_date(analyzed_at))}</div>"
        f"<div>Тип ввода: {_e(input_type)}</div>"
        f"<div>Версия движка правил: {_e(engine_version)}</div>"
        "</div>"
        f"{body}"
        "<h2>Ограничения</h2>"
        f"{_list(LIMITATIONS)}"
        "</main></body></html>"
    )


def _url_section(analysis: UrlAnalysis, heading_level: str = "h2") -> str:
    p = analysis.parsed
    recs = analysis.recommendations
    return (
        f"<{heading_level}>Проверенный адрес (секреты скрыты)</{heading_level}>"
        f"<div class=\"box mono\">{_e(p.sanitized)}</div>"
        f"<{heading_level}>Сведения о домене</{heading_level}>{_domain_table(p)}"
        f"<{heading_level}>Индекс и расчёт</{heading_level}>{_score_block(analysis.score)}"
        f"<{heading_level}>Сработавшие правила</{heading_level}>{_findings_table(analysis.findings)}"
        + (f"<{heading_level}>Рекомендации</{heading_level}>{_list(recs)}" if recs else "")
    )


def build_url_report(analysis: UrlAnalysis) -> str:
    return _document(
        "Отчёт PhishGuard AI: ссылка",
        analysis.analyzed_at,
        "Ссылка (URL)",
        analysis.engine_version,
        _url_section(analysis),
    )


def build_message_report(analysis: MessageAnalysis) -> str:
    parts = [
        "<h2>Текст сообщения (ссылки очищены, последовательности цифр скрыты)</h2>",
        f"<div class=\"box\"><pre>{_e(analysis.sanitized_text)}</pre></div>",
        "<h2>Индекс текста и расчёт</h2>",
        _score_block(analysis.score),
        "<h2>Сработавшие правила текста</h2>",
        _findings_table(analysis.findings),
    ]
    if analysis.recommendations:
        parts += ["<h2>Рекомендации по тексту</h2>", _list(analysis.recommendations)]
    parts.append("<h2>Ссылки из сообщения</h2>")
    if not analysis.url_results:
        parts.append("<div class=\"box\">Ссылки http:// или https:// в тексте не найдены.</div>")
    parts.append(
        "<div class=\"muted\">Каждая ссылка оценивается отдельно; индексы разных ссылок не суммируются.</div>"
    )
    for number, result in enumerate(analysis.url_results, start=1):
        parts.append(f"<h3>Ссылка {number}</h3>")
        if result.analysis is None:
            parts.append(
                f"<div class=\"box\"><div class=\"mono\">{_e(result.display)}</div>"
                f"<div>Не проанализирована: {_e(result.error)}</div></div>"
            )
        else:
            parts.append(_url_section(result.analysis, heading_level="h3"))
    if analysis.omitted_urls:
        parts.append(
            f"<div class=\"box\">Ещё {analysis.omitted_urls} уникальн. ссылок не проанализировано: "
            "действует ограничение на количество ссылок в одном сообщении.</div>"
        )
    return _document(
        "Отчёт PhishGuard AI: сообщение",
        analysis.analyzed_at,
        "Текст сообщения",
        analysis.engine_version,
        "".join(parts),
    )
