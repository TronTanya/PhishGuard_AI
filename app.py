"""PhishGuard AI — Streamlit interface.

All analysis logic lives in url_analyzer, message_analyzer, scoring and reporting.
Inputs and results are kept only in the in-memory Streamlit session.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

import streamlit as st

from message_analyzer import MessageAnalysis, MessageInputError, analyze_message, decode_upload, validate_text
from reporting import LIMITATIONS, build_message_report, build_url_report, report_filename
from scoring import NO_FINDINGS_NOTE, SCORE_DISCLAIMER, SEVERITY_LABELS, Finding, ScoreResult, load_catalog
from url_analyzer import ParsedUrl, UrlAnalysis, UrlInputError, analyze_url, load_brands, load_shorteners

RESULTS_SUMMARY = Path(__file__).resolve().parent / "experiments" / "results" / "evaluation_summary.json"

URL_EXAMPLES: dict[str, str] = {
    "Учётные данные в адресе": "https://account.example.com@verify.example.net/login",
    "Бренд в поддомене чужого домена": "https://sberbank.account-verify.example.net/login",
    "Сокращённая ссылка (вымышленный код)": "https://bit.ly/3xYzAbc",
    "Обычная ссылка": "https://www.example.org/news/2026/conference",
}

MESSAGE_EXAMPLES: dict[str, str] = {
    "Нейтральное сообщение": (
        "Добрый день! Консультация по курсовой работе переносится на четверг, 15:00, аудитория 214. "
        "Материалы лежат в учебном портале: https://portal.example.org/course/informatics."
    ),
    "Срочное сообщение с запросом кода": (
        "Служба безопасности банка: зафиксирована подозрительная операция. Срочно сообщите код из СМС, "
        "иначе ваша карта будет заблокирована в течение 30 минут. "
        "Подтвердите личность по ссылке https://secure-bank.example.net/verify?session=8f2a91c4 и введите пароль."
    ),
}

LEVEL_CLASS = {"none": "pg-level-none", "low": "pg-level-warn", "medium": "pg-level-warn", "high": "pg-level-high"}

CSS = """
<style>
[data-testid="stMainBlockContainer"] { max-width: 1100px; padding-top: 2rem; }
.pg-sub { color: #667085; margin: 0 0 0.25rem 0; font-size: 1.05rem; }
.pg-desc { color: #667085; margin: 0; font-size: 0.95rem; }
.pg-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin: 4px 0 8px; }
.pg-cell { background: #FFFFFF; border: 1px solid #E4E7EC; border-radius: 6px; padding: 10px 12px; }
.pg-cell-label { color: #667085; font-size: 0.8rem; margin-bottom: 2px; }
.pg-cell-value { color: #202733; font-size: 0.98rem; font-weight: 600; overflow-wrap: anywhere; }
.pg-mono { font-family: "SFMono-Regular", Consolas, Menlo, monospace; overflow-wrap: anywhere; }
.pg-level { display: inline-block; border: 1px solid; border-radius: 4px; padding: 1px 6px; font-size: 0.82rem; font-weight: 600; background: #FFFFFF; }
.pg-level-none { color: #667085; border-color: #E4E7EC; }
.pg-level-warn { color: #B7791F; border-color: #B7791F; }
.pg-level-high { color: #C43D3D; border-color: #C43D3D; }
.pg-table { width: 100%; border-collapse: collapse; background: #FFFFFF; border: 1px solid #E4E7EC; font-size: 0.9rem; }
.pg-table th, .pg-table td { border-bottom: 1px solid #E4E7EC; padding: 7px 9px; text-align: left; vertical-align: top; color: #202733; }
.pg-table th { background: #F7F8FA; font-weight: 600; color: #344054; }
.pg-table td.pg-muted, .pg-muted { color: #667085; }
.pg-host { font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-weight: 700; background: #EEF2FF; border: 1px solid #C7D3FE; border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }
.pg-note { background: #FFFFFF; border: 1px solid #E4E7EC; border-left: 3px solid #315EFB; border-radius: 6px; padding: 10px 12px; color: #202733; font-size: 0.92rem; }
.pg-calc { font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 0.88rem; color: #202733; }
@media (max-width: 760px) { .pg-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
"""


def e(value: object) -> str:
    return escape(str(value), quote=True)


def html(markup: str) -> None:
    st.html(markup)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def level_badge(score: ScoreResult) -> str:
    return f'<span class="pg-level {LEVEL_CLASS[score.band.level]}">{e(score.band.label)}</span>'


def summary_grid(cells: list[tuple[str, str]]) -> None:
    body = "".join(
        f'<div class="pg-cell"><div class="pg-cell-label">{e(label)}</div><div class="pg-cell-value">{value}</div></div>'
        for label, value in cells
    )
    html(f'<div class="pg-grid">{body}</div>')


def score_cell(score: ScoreResult) -> str:
    return f"{score.total} из 100<br>{level_badge(score)}"


def parsed_table(p: ParsedUrl) -> None:
    host = f'<span class="pg-host">{e(p.hostname_unicode)}</span>'
    if p.hostname != p.hostname_unicode:
        host += f' <span class="pg-mono pg-muted">({e(p.hostname)})</span>'
    rows: list[tuple[str, str]] = [
        ("Фактический хост", host),
        ("Схема", f'<span class="pg-mono">{e(p.scheme)}</span>'),
        ("Тип хоста", "IP-адрес" if p.is_ip else "Доменное имя"),
        ("Регистрируемый домен", f'<span class="pg-mono">{e(p.registrable_domain_unicode)}</span>' if p.registrable_domain else '<span class="pg-muted">не определён</span>'),
        ("Поддомен", f'<span class="pg-mono">{e(p.subdomain)}</span>' if p.subdomain else '<span class="pg-muted">нет</span>'),
        ("Путь", f'<span class="pg-mono">{e(p.path_decoded or "/")}</span>'),
    ]
    if p.port is not None:
        rows.append(("Порт", f'<span class="pg-mono">{p.port}</span>'))
    if p.has_credentials:
        rows.append(("Часть до @", f'<span class="pg-mono">{e(p.username or "(пусто)")}</span>' + (" — пароль скрыт" if p.has_password else "")))
    if p.redacted_keys:
        rows.append(("Скрытые значения параметров", f'<span class="pg-mono">{e(", ".join(p.redacted_keys))}</span>'))
    body = "".join(f"<tr><th style='width:220px'>{e(k)}</th><td>{v}</td></tr>" for k, v in rows)
    html(f'<table class="pg-table">{body}</table>')


def findings_table(findings: tuple[Finding, ...]) -> None:
    if not findings:
        html(f'<div class="pg-note">{e(NO_FINDINGS_NOTE)}</div>')
        return
    head = (
        "<tr><th style='width:18%'>Признак</th><th style='width:24%'>Доказательство</th>"
        "<th>Объяснение</th><th style='width:20%'>Что сделать</th><th style='width:60px'>Баллы</th></tr>"
    )
    rows = "".join(
        "<tr>"
        f"<td><b>{e(f.title)}</b><br><span class='pg-muted'>{e(f.severity_label)} · {e(f.category)}</span></td>"
        f"<td class='{'pg-mono' if f.rule_id.startswith('URL_') else ''}'>{e(f.evidence)}</td>"
        f"<td>{e(f.explanation)}</td>"
        f"<td>{e(f.action)}</td>"
        f"<td>+{f.score}</td>"
        "</tr>"
        for f in findings
    )
    html(f'<table class="pg-table">{head}{rows}</table>')


def score_breakdown(score: ScoreResult) -> None:
    if score.contributions:
        lines = [f"+{c.points:>2}  {c.rule_id} ({SEVERITY_LABELS[c.severity].lower()})" for c in score.contributions]
        total_line = f"= {score.raw_total}"
        if score.was_clamped:
            total_line += f" → ограничено до {score.total}"
        lines.append(total_line)
    else:
        lines = ["Правила не сработали: 0"]
    body = "<br>".join(e(line).replace("  ", "&nbsp;&nbsp;") for line in lines)
    html(
        f'<div class="pg-note"><div class="pg-calc">{body}</div>'
        f'<div class="pg-muted" style="margin-top:6px">Веса: сильный признак — 25, умеренный — 10, слабый — 5. '
        f"Каждое правило учитывается один раз. {e(SCORE_DISCLAIMER)}</div></div>"
    )


def recommendations_block(recommendations: tuple[str, ...]) -> None:
    if not recommendations:
        return
    st.markdown("**Рекомендации по найденным признакам**")
    items = "".join(f"<li>{e(r)}</li>" for r in recommendations)
    html(f'<ul style="margin:0 0 0 1.1rem;padding:0">{items}</ul>')


def url_details(analysis: UrlAnalysis) -> None:
    st.markdown("**Проверенный адрес** (некликабельный, секреты скрыты)")
    st.code(analysis.parsed.sanitized, language=None, wrap_lines=True)
    st.markdown("**Разбор адреса**")
    parsed_table(analysis.parsed)
    st.markdown("**Диагностика**")
    findings_table(analysis.findings)
    st.markdown("**Расчёт индекса подозрительных признаков**")
    score_breakdown(analysis.score)
    recommendations_block(analysis.recommendations)


# ---------------------------------------------------------------------------
# State callbacks
# ---------------------------------------------------------------------------

def run_url_check() -> None:
    st.session_state.url_result = None
    st.session_state.url_error = None
    try:
        st.session_state.url_result = analyze_url(st.session_state.get("url_input", ""))
    except UrlInputError as exc:
        st.session_state.url_error = str(exc)


def load_url_example(value: str) -> None:
    st.session_state.url_input = value
    run_url_check()


def run_message_check() -> None:
    st.session_state.msg_result = None
    st.session_state.msg_error = None
    try:
        st.session_state.msg_result = analyze_message(st.session_state.get("msg_input", ""))
    except MessageInputError as exc:
        st.session_state.msg_error = str(exc)


def load_message_example(value: str) -> None:
    st.session_state.msg_input = value
    st.session_state.msg_file_note = None
    run_message_check()


def load_uploaded_file() -> None:
    uploaded = st.session_state.get("msg_file")
    st.session_state.msg_file_note = None
    st.session_state.msg_error = None
    if uploaded is None:
        return
    try:
        text = validate_text(decode_upload(uploaded.getvalue()))
    except MessageInputError as exc:
        st.session_state.msg_error = str(exc)
        return
    st.session_state.msg_input = text
    st.session_state.msg_result = None
    st.session_state.msg_file_note = f"Текст из файла «{uploaded.name}» загружен в поле ниже ({len(text)} символов)."


def init_state() -> None:
    defaults = {
        "url_input": "",
        "url_result": None,
        "url_error": None,
        "msg_input": "",
        "msg_result": None,
        "msg_error": None,
        "msg_file_note": None,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

def url_tab() -> None:
    st.caption("Демонстрационные примеры (вымышленные адреса, ссылки не открываются)")
    columns = st.columns(len(URL_EXAMPLES))
    for column, (label, value) in zip(columns, URL_EXAMPLES.items()):
        column.button(label, key=f"url_ex_{label}", on_click=load_url_example, args=(value,), width="stretch")

    with st.form("url_form", border=False):
        st.text_input(
            "Адрес ссылки",
            key="url_input",
            placeholder="https://example.com/login",
            help="Только http:// и https://, до 4096 символов. Адрес не открывается и не сохраняется.",
        )
        st.form_submit_button("Проверить", type="primary", on_click=run_url_check)

    if st.session_state.url_error:
        st.error(st.session_state.url_error)
    analysis: UrlAnalysis | None = st.session_state.url_result
    if analysis is None:
        return

    st.divider()
    p = analysis.parsed
    summary_grid([
        ("Тип ввода", "Ссылка (URL)"),
        ("Индекс подозрительных признаков", score_cell(analysis.score)),
        ("Сработало правил", str(analysis.score.rule_count)),
        ("Фактический хост", f'<span class="pg-mono">{e(p.hostname_unicode)}</span>'),
    ])
    st.caption(SCORE_DISCLAIMER)
    url_details(analysis)
    st.download_button(
        "Скачать отчёт (HTML)",
        data=build_url_report(analysis).encode("utf-8"),
        file_name=report_filename("url", analysis.analyzed_at),
        mime="text/html",
        key="url_download",
    )


def message_tab() -> None:
    st.caption("Демонстрационные примеры (вымышленные сообщения, ссылки не открываются)")
    columns = st.columns(4)
    for column, (label, value) in zip(columns, MESSAGE_EXAMPLES.items()):
        column.button(label, key=f"msg_ex_{label}", on_click=load_message_example, args=(value,), width="stretch")

    st.file_uploader(
        "Загрузить текст из файла .txt (UTF-8, до 1 МБ)",
        type=["txt"],
        key="msg_file",
        on_change=load_uploaded_file,
    )
    if st.session_state.msg_file_note:
        st.caption(st.session_state.msg_file_note)

    with st.form("msg_form", border=False):
        st.text_area(
            "Текст сообщения",
            key="msg_input",
            height=180,
            placeholder="Вставьте текст письма, SMS или сообщения из мессенджера",
            help="До 20 000 символов. Текст не сохраняется; ссылки из него не открываются.",
        )
        st.form_submit_button("Проверить", type="primary", on_click=run_message_check)

    if st.session_state.msg_error:
        st.error(st.session_state.msg_error)
    analysis: MessageAnalysis | None = st.session_state.msg_result
    if analysis is None:
        return

    st.divider()
    found = len(analysis.url_results) + analysis.omitted_urls
    summary_grid([
        ("Тип ввода", "Текст сообщения"),
        ("Индекс текста", score_cell(analysis.score)),
        ("Сработало правил текста", str(analysis.score.rule_count)),
        ("Ссылки", f"найдено {found}, проверено {len(analysis.url_results)}"),
    ])
    st.caption(SCORE_DISCLAIMER + " Индексы текста и каждой ссылки показаны отдельно и не суммируются.")

    st.markdown("**Диагностика текста**")
    findings_table(analysis.findings)
    st.markdown("**Расчёт индекса текста**")
    score_breakdown(analysis.score)
    recommendations_block(analysis.recommendations)

    st.markdown("**Ссылки из сообщения**")
    if not analysis.url_results:
        st.caption("Ссылки http:// или https:// в тексте не найдены.")
    for number, result in enumerate(analysis.url_results, start=1):
        if result.analysis is None:
            with st.expander(f"Ссылка {number}: не проанализирована", expanded=True):
                st.code(result.display, language=None, wrap_lines=True)
                st.warning(result.error)
            continue
        score = result.analysis.score
        title = f"Ссылка {number}: хост `{result.analysis.parsed.hostname_unicode}` — индекс {score.total}, {score.band.label.lower()}"
        with st.expander(title, expanded=score.total > 0):
            summary_grid([
                ("Тип ввода", "Ссылка из сообщения"),
                ("Индекс ссылки", score_cell(score)),
                ("Сработало правил", str(score.rule_count)),
                ("Фактический хост", f'<span class="pg-mono">{e(result.analysis.parsed.hostname_unicode)}</span>'),
            ])
            url_details(result.analysis)
    if analysis.omitted_urls:
        limit = load_catalog().thresholds["max_urls_per_message"]
        st.warning(
            f"В сообщении ещё {analysis.omitted_urls} уникальн. ссылок, которые не проанализированы: "
            f"проверяется не более {limit} ссылок за раз."
        )

    st.download_button(
        "Скачать отчёт (HTML)",
        data=build_message_report(analysis).encode("utf-8"),
        file_name=report_filename("message", analysis.analyzed_at),
        mime="text/html",
        key="msg_download",
    )


def rules_table() -> None:
    catalog = load_catalog()
    rows = "".join(
        f"<tr><td class='pg-mono'>{e(r.rule_id)}</td><td>{e(r.title)}</td><td>{e(r.category)}</td>"
        f"<td>{e(SEVERITY_LABELS[r.severity])}</td><td>{r.weight}</td></tr>"
        for r in [*catalog.url_rules.values(), *catalog.message_rules.values()]
    )
    head = "<tr><th>ID правила</th><th>Признак</th><th>Категория</th><th>Степень</th><th>Баллы</th></tr>"
    html(f'<table class="pg-table">{head}{rows}</table>')


def about_tab() -> None:
    catalog = load_catalog()
    t = catalog.thresholds
    st.markdown(
        "### Назначение\n"
        "PhishGuard AI — учебный инструмент, который находит в ссылках и сообщениях признаки, типичные для фишинга, "
        "и объясняет каждый из них простым языком. Инструмент помогает научиться замечать такие признаки "
        "самостоятельно, а не выносит окончательный вердикт.\n\n"
        "**Для кого:** студенты и преподаватели — для занятий по информационной безопасности и цифровой грамотности.\n\n"
        "**Гипотеза исследования:** «Объяснимый анализ ссылок и сообщений может помочь пользователям замечать признаки фишинга».\n\n"
        "### Как устроен анализ\n"
        "Инструмент использует **прозрачные правила, а не обученную модель искусственного интеллекта**. "
        "Каждое правило имеет постоянный идентификатор, категорию, степень, доказательство, объяснение, "
        "рекомендацию и вклад в индекс. Слово «AI» в названии отражает тематику проекта; "
        "модель машинного обучения в приложение не встроена."
    )
    rules_table()
    st.markdown(
        "#### Индекс подозрительных признаков\n"
        "Сумма весов сработавших правил: сильный признак — 25 баллов, умеренный — 10, слабый — 5. "
        "Каждое правило учитывается один раз для ссылки или текста, результат ограничен диапазоном 0–100.\n\n"
        "| Индекс | Значение |\n|---|---|\n"
        "| 0 | Признаки по текущим правилам не обнаружены |\n"
        "| 1–24 | Есть признаки для проверки |\n"
        "| 25–49 | Требуется внимательная проверка |\n"
        "| 50–100 | Обнаружено несколько существенных признаков |\n\n"
        f"{SCORE_DISCLAIMER}\n\n"
        "#### Настраиваемые пороги (файл `content/rules.json`)\n"
        f"- Чрезмерно длинный адрес: более {t['long_url_length']} символов.\n"
        f"- Много поддоменов: более {t['max_subdomain_levels']} уровней поддомена.\n"
        f"- Похожий на бренд домен: расстояние редактирования до {t['brand_max_edit_distance_short']} "
        f"(до {t['brand_max_edit_distance_long']} для названий от {t['brand_long_name_length']} символов); "
        f"сравниваются только метки от {t['brand_min_length_for_near_match']} символов.\n"
        f"- Сообщение: до {t['max_message_chars']} символов, файл до 1 МБ, не более {t['max_urls_per_message']} уникальных ссылок.\n\n"
        f"Список брендов ({len(load_brands())} шт.) и сокращателей ссылок ({len(load_shorteners())} шт.) — "
        "иллюстративный, ограниченный и требует регулярного обновления. Это не полный список разрешённых доменов.\n\n"
        "Проверка смешения алфавитов ограничена латиницей и кириллицей; это не полная защита от подмены символов Unicode.\n\n"
        "### Технологии\n"
        "Python 3.11+, Streamlit, стандартная библиотека Python (разбор URL, регулярные выражения, Unicode), "
        "tldextract со встроенной копией списка публичных суффиксов (без сетевых запросов), pytest.\n\n"
        "### Практическая польза\n"
        "- Наглядно показывает, где в адресе находится настоящий хост и почему знакомое название может обманывать.\n"
        "- Объясняет приёмы социальной инженерии в тексте: срочность, угрозы, запрос кодов и платежей.\n"
        "- Работает локально и офлайн: ничего не отправляется во внешние сервисы.\n"
        "- Формирует HTML-отчёт для обсуждения на занятии.\n\n"
        "### Методика исследования\n"
        "Подготовлен небольшой размеченный вручную учебный набор: примеры для разработки правил хранятся отдельно "
        "от оценочного подмножества. Скрипт `experiments/evaluate.py` применяет детектор, считает пример "
        f"подозрительным при индексе не ниже {t['evaluation_threshold']} (для сообщений — по наибольшему из индексов "
        "текста и ссылок), строит матрицу ошибок и вычисляет точность (precision), полноту (recall) и F1. "
        "В набор намеренно включены безопасные учебные тексты с терминами безопасности, чтобы показать ложные срабатывания."
    )
    if RESULTS_SUMMARY.exists():
        try:
            summary = json.loads(RESULTS_SUMMARY.read_text(encoding="utf-8"))
            ev = summary["subsets"]["evaluation"]
            m = ev["metrics"]
            cm = ev["confusion_matrix"]

            def fmt(value: float | None) -> str:
                return "не определена" if value is None else f"{value:.2f}"

            st.markdown(
                f"**Результат последнего запуска** (оценочное подмножество, {ev['count']} примеров, порог {summary['threshold']}): "
                f"TP = {cm['tp']}, FP = {cm['fp']}, TN = {cm['tn']}, FN = {cm['fn']}; "
                f"precision = {fmt(m['precision'])}, recall = {fmt(m['recall'])}, F1 = {fmt(m['f1'])}."
            )
        except (OSError, KeyError, ValueError):
            st.caption("Файл с результатами эксперимента повреждён; запустите experiments/evaluate.py заново.")
    else:
        st.caption("Результаты эксперимента появятся здесь после запуска: python experiments/evaluate.py")
    st.markdown(
        "**Оценка выполнена на небольшом учебном наборе примеров и не отражает точность на реальном интернет-трафике.** "
        "Оценочное подмножество не является репрезентативной выборкой реального фишинга. "
        "Образовательная эффективность инструмента требует отдельного исследования с участием пользователей; "
        "такое исследование не проводилось.\n\n"
        "### Ограничения"
    )
    st.markdown("\n".join(f"- {item}" for item in LIMITATIONS))
    st.caption(f"Версия движка правил: {catalog.engine_version}")


def main() -> None:
    st.set_page_config(page_title="PhishGuard AI", layout="wide")
    html(CSS)
    init_state()
    st.title("PhishGuard AI", anchor=False)
    html(
        '<p class="pg-sub">Анализ признаков фишинга в ссылках и сообщениях</p>'
        '<p class="pg-desc">Проверьте адрес или текст сообщения и получите объяснение подозрительных признаков.</p>'
    )
    url, message, about = st.tabs(["Проверка ссылки", "Проверка сообщения", "О проекте"])
    with url:
        url_tab()
    with message:
        message_tab()
    with about:
        about_tab()


main()
