import pytest

from scoring import SCORE_BANDS, band_for, compute_score, load_catalog, recommendations_for
from url_analyzer import analyze_url


def test_weights_match_severity():
    catalog = load_catalog()
    expected = {"strong": 25, "moderate": 10, "weak": 5}
    assert catalog.severity_weights == expected
    for rule in [*catalog.url_rules.values(), *catalog.message_rules.values()]:
        assert rule.weight == expected[rule.severity]


def test_rule_ids_unique_and_complete():
    catalog = load_catalog()
    all_ids = [*catalog.url_rules, *catalog.message_rules]
    assert len(all_ids) == len(set(all_ids))
    for rule in catalog.url_rules.values():
        assert rule.title and rule.explanation and rule.action and rule.category


def test_contributions_sum_to_total():
    analysis = analyze_url("http://account.example.com@192.0.2.5/login")
    contributions = {c.rule_id: c.points for c in analysis.score.contributions}
    assert contributions == {"URL_CREDENTIALS": 25, "URL_IP_HOST": 10, "URL_HTTP": 5}
    assert analysis.score.total == 40


def test_each_rule_counted_once():
    catalog = load_catalog()
    findings = [catalog.make_finding("URL_HTTP", "a"), catalog.make_finding("URL_HTTP", "b")]
    assert compute_score(findings).total == 5


def test_score_clamped_to_100():
    catalog = load_catalog()
    strong = [r for r in catalog.url_rules.values() if r.severity == "strong"]
    strong += [r for r in catalog.message_rules.values() if r.severity == "strong"]
    findings = [catalog.make_finding(r.rule_id, "x") for r in strong]
    score = compute_score(findings)
    assert score.raw_total > 100
    assert score.total == 100
    assert score.was_clamped


def test_empty_score_is_zero():
    score = compute_score([])
    assert score.total == 0
    assert score.band.label == "Признаки по текущим правилам не обнаружены"


@pytest.mark.parametrize(
    "value, level",
    [(0, "none"), (1, "low"), (24, "low"), (25, "medium"), (49, "medium"), (50, "high"), (100, "high")],
)
def test_bands(value, level):
    assert band_for(value).level == level


def test_bands_cover_range_without_gaps():
    covered = [v for band in SCORE_BANDS for v in range(band.min_score, band.max_score + 1)]
    assert covered == list(range(0, 101))


def test_out_of_range_band_rejected():
    with pytest.raises(ValueError):
        band_for(101)


def test_recommendations_unique_and_linked():
    catalog = load_catalog()
    findings = [
        catalog.make_finding("URL_CREDENTIALS", "x"),
        catalog.make_finding("URL_IP_HOST", "y"),
        catalog.make_finding("MSG_CREDENTIAL_REQUEST", "z"),
    ]
    recs = recommendations_for(findings)
    assert recs == [catalog.recommendations["inspect_domain"], catalog.recommendations["no_codes"]]
    assert recommendations_for([]) == []
