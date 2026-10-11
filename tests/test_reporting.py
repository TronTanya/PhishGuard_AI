import re
import sys
from pathlib import Path

from message_analyzer import analyze_message
from reporting import build_message_report, build_url_report
from url_analyzer import analyze_url

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "experiments"))
import evaluate  # noqa: E402


def test_url_report_escapes_and_redacts():
    url = 'https://a"><svg>:pw123@evil.example.net/<script>alert(1)</script>?token=SECRET&q=<marquee>'
    report = build_url_report(analyze_url(url))
    assert "<script>" not in report and "<svg>" not in report and "<marquee>" not in report
    assert "&lt;script&gt;" in report
    assert "&lt;svg&gt;" in report
    assert "&lt;marquee&gt;" in report
    assert "pw123" not in report
    assert "SECRET" not in report


def test_reports_have_no_clickable_links():
    url_report = build_url_report(analyze_url("https://account.example.com@verify.example.net/login"))
    msg_report = build_message_report(analyze_message("Срочно: https://bit.ly/abc и https://example.com/a"))
    for report in (url_report, msg_report):
        assert not re.search(r"<a[\s>]", report, re.IGNORECASE)
        assert "href=" not in report.lower()


def test_url_report_contents():
    report = build_url_report(analyze_url("http://account.example.com@192.0.2.5/login"))
    for expected in [
        "Дата анализа", "Ссылка (URL)", "Версия движка правил", "URL_CREDENTIALS",
        "Регистрируемый домен", "Расчёт: 25 (URL_CREDENTIALS) + 10 (URL_IP_HOST) + 5 (URL_HTTP) = 40",
        "Рекомендации", "Ограничения", "не вероятность фишинга",
    ]:
        assert expected in report


def test_message_report_escapes_text_and_hides_codes():
    report = build_message_report(analyze_message("<img src=x onerror=alert(1)> Сообщите код 482913 срочно"))
    assert "<img" not in report
    assert "&lt;img" in report
    assert "482913" not in report
    assert "MSG_CREDENTIAL_REQUEST" in report


def test_message_report_mentions_omitted_urls():
    text = " ".join(f"https://s{i}.example.com/" for i in range(12))
    report = build_message_report(analyze_message(text))
    assert "Ещё 2" in report


# --- Evaluation metrics (experiments/evaluate.py) ---------------------------------

def test_undefined_metrics_are_none():
    metrics = evaluate.compute_metrics({"tp": 0, "fp": 0, "tn": 5, "fn": 0})
    assert metrics == {"precision": None, "recall": None, "f1": None}
    reasons = evaluate.undefined_reasons({"tp": 0, "fp": 0, "tn": 5, "fn": 0}, metrics)
    assert len(reasons) == 3


def test_zero_precision_and_recall_gives_zero_f1():
    metrics = evaluate.compute_metrics({"tp": 0, "fp": 3, "tn": 1, "fn": 2})
    assert metrics == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_metrics_values():
    metrics = evaluate.compute_metrics({"tp": 8, "fp": 2, "tn": 7, "fn": 3})
    assert metrics["precision"] == 0.8
    assert round(metrics["recall"], 4) == round(8 / 11, 4)
    assert round(metrics["f1"], 4) == round(2 * 0.8 * (8 / 11) / (0.8 + 8 / 11), 4)


def test_evaluation_writes_outputs(tmp_path, no_network):
    assert evaluate.main(["--output-dir", str(tmp_path)]) == 0
    assert (tmp_path / "evaluation_results.csv").exists()
    assert (tmp_path / "evaluation_summary.json").exists()


def test_dataset_has_required_composition():
    from scoring import load_json

    examples = load_json("evaluation_examples.json")["examples"]
    assert sum(e["label"] == "suspicious" for e in examples) >= 15
    assert sum(e["label"] == "benign" for e in examples) >= 15
    assert {e["subset"] for e in examples} == {"development", "evaluation"}
    assert len({e["id"] for e in examples}) == len(examples)
