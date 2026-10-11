import pytest

import url_analyzer
from url_analyzer import UrlInputError, analyze_url, edit_distance, parse_url, skeleton


def rule_ids(url: str) -> set[str]:
    return {f.rule_id for f in analyze_url(url).findings}


# --- Input validation -------------------------------------------------------

@pytest.mark.parametrize("value", ["", "   ", None])
def test_empty_input_rejected(value):
    with pytest.raises(UrlInputError, match="Введите адрес"):
        parse_url(value)


def test_missing_scheme_shows_example():
    with pytest.raises(UrlInputError, match="https://example.com/login"):
        parse_url("example.com/login")


@pytest.mark.parametrize("value", ["ftp://example.com/file", "javascript:alert(1)", "file:///etc/passwd", "data:text/html,hi"])
def test_unsupported_schemes_rejected(value):
    with pytest.raises(UrlInputError, match="не поддерживается"):
        parse_url(value)


@pytest.mark.parametrize("value", ["https://example.com:99999/", "https://example.com:abc/", "https://example.com:0/"])
def test_invalid_ports_rejected(value):
    with pytest.raises(UrlInputError, match="порт"):
        parse_url(value)


@pytest.mark.parametrize("value", ["https://", "https:///path", "http://user@/"])
def test_missing_hostname_rejected(value):
    with pytest.raises(UrlInputError, match="имя хоста"):
        parse_url(value)


@pytest.mark.parametrize(
    "value",
    ["https://exa mple.com", "https:example.com", "https://a..b.com/", "https://[::1/", "https://exa!mple.com/", "https://a.com\\@b.com"],
)
def test_malformed_urls_rejected(value):
    with pytest.raises(UrlInputError):
        parse_url(value)


def test_length_limit():
    with pytest.raises(UrlInputError, match="слишком длинный"):
        parse_url("https://example.com/" + "a" * 5000)


def test_valid_port_kept():
    assert parse_url("https://example.com:8443/x").port == 8443


# --- Hostname extraction ----------------------------------------------------

def test_actual_hostname_after_credentials():
    p = parse_url("https://trusted.example@other.example/login")
    assert p.hostname == "other.example"
    assert p.has_credentials
    assert p.username == "trusted.example"
    assert "URL_CREDENTIALS" in rule_ids("https://trusted.example@other.example/login")


def test_last_at_sign_determines_host():
    p = parse_url("https://a@b.example@evil.example.net/")
    assert p.hostname == "evil.example.net"


def test_components_and_registrable_domain():
    p = parse_url("https://login.secure.example.co.uk/path/to?q=1#frag")
    assert p.scheme == "https"
    assert p.registrable_domain == "example.co.uk"
    assert p.subdomain == "login.secure"
    assert p.path == "/path/to"
    assert p.fragment == "frag"


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://192.0.2.10/login", "192.0.2.10"),
        ("http://[2001:db8::1]/", "2001:db8::1"),
        ("http://3232235777/", "192.168.1.1"),
        ("http://0x7f.0.0.1/", "127.0.0.1"),
    ],
)
def test_ip_hosts(url, expected):
    p = parse_url(url)
    assert p.is_ip and p.hostname == expected
    assert "URL_IP_HOST" in rule_ids(url)


def test_numeric_like_domain_is_not_ip():
    assert not parse_url("https://123.example.com/").is_ip


# --- IDN, punycode, mixed scripts --------------------------------------------

def test_idn_decoding_from_punycode():
    p = parse_url("https://xn--c1aapkosapc.xn--p1ai/")
    assert p.hostname_unicode == "госуслуги.рф"
    assert p.registrable_domain_unicode == "госуслуги.рф"
    assert rule_ids("https://xn--c1aapkosapc.xn--p1ai/") == {"URL_IDN"}


def test_unicode_host_converted_to_punycode():
    p = parse_url("https://госуслуги.рф/")
    assert p.hostname == "xn--c1aapkosapc.xn--p1ai"


def test_invalid_punycode_rejected():
    with pytest.raises(UrlInputError, match="Punycode"):
        parse_url("https://xn--a.example/")


def test_mixed_latin_cyrillic_detected():
    ids = rule_ids("https://xn--pypal-4ve.test/")  # "pаypal" with Cyrillic а
    assert "URL_MIXED_SCRIPT" in ids
    finding = next(f for f in analyze_url("https://xn--pypal-4ve.test/").findings if f.rule_id == "URL_MIXED_SCRIPT")
    assert "U+0430" in finding.evidence


def test_single_script_labels_not_mixed():
    assert "URL_MIXED_SCRIPT" not in rule_ids("https://госуслуги.рф/")
    assert "URL_MIXED_SCRIPT" not in rule_ids("https://example.com/")
    # Separate labels in different scripts are not a mixed label.
    assert "URL_MIXED_SCRIPT" not in rule_ids("https://shop.пример.рф/")


def test_percent_encoded_host_decoded_and_flagged():
    p = parse_url("https://exa%6Dple.com/")
    assert p.hostname == "example.com"
    assert "URL_PERCENT_ENCODED_HOST" in rule_ids("https://exa%6Dple.com/")


def test_percent_encoded_path_decoded_for_display():
    p = parse_url("https://ru.wikipedia.org/wiki/%D0%A4%D0%B8%D1%88%D0%B8%D0%BD%D0%B3")
    assert p.path_decoded == "/wiki/Фишинг"


# --- Other structural rules ---------------------------------------------------

def test_http_flagged_https_not():
    assert "URL_HTTP" in rule_ids("http://example.com/")
    assert "URL_HTTP" not in rule_ids("https://example.com/")


def test_subdomain_threshold():
    assert "URL_MANY_SUBDOMAINS" not in rule_ids("https://a.b.example.com/")
    assert "URL_MANY_SUBDOMAINS" in rule_ids("https://a.b.c.example.com/")


def test_long_url_threshold():
    base = "https://example.com/"
    assert "URL_LONG" not in rule_ids(base + "a" * (100 - len(base)))
    assert "URL_LONG" in rule_ids(base + "a" * (101 - len(base)))


# --- Shorteners ----------------------------------------------------------------

@pytest.mark.parametrize("url", ["https://bit.ly/abc", "https://www.bit.ly/abc", "https://clck.ru/xyz"])
def test_known_shorteners(url):
    assert "URL_SHORTENER" in rule_ids(url)


@pytest.mark.parametrize("url", ["https://notbit.ly/abc", "https://bit.ly.example.com/", "https://t.me/channel"])
def test_shortener_matching_is_exact(url):
    assert "URL_SHORTENER" not in rule_ids(url)


# --- Brand rules ----------------------------------------------------------------

def test_brand_in_subdomain_of_other_domain():
    finding = next(
        f for f in analyze_url("https://paypal.com.secure-login.example/").findings if f.rule_id == "URL_BRAND_IN_SUBDOMAIN"
    )
    assert "paypal.com" in finding.evidence  # official domain is shown


@pytest.mark.parametrize("url", ["https://www.paypal.com/", "https://online.sberbank.ru/", "https://mail.google.com/"])
def test_official_domains_not_flagged(url):
    assert not rule_ids(url) & {"URL_BRAND_IN_SUBDOMAIN", "URL_BRAND_NEAR_MATCH", "URL_BRAND_TOKEN_IN_DOMAIN"}


@pytest.mark.parametrize("url", ["https://g00gle.test/", "https://microsfot.test/", "https://gosuslugl.test/", "https://paypal.example/"])
def test_near_match_domains(url):
    assert "URL_BRAND_NEAR_MATCH" in rule_ids(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://cloud.example.com/",      # substring of icloud
        "https://apply.example.org/",      # one edit from apple, but too short for distance check
        "https://bank.example/",           # substring of tbank
        "https://googleblog.example/",     # contains google but is not a token or near match
        "https://mysberbankstore.example/",  # brand only as a substring
        "https://disappleased.example/",
    ],
)
def test_brand_rules_do_not_flag_substrings(url):
    assert not rule_ids(url) & {"URL_BRAND_IN_SUBDOMAIN", "URL_BRAND_NEAR_MATCH", "URL_BRAND_TOKEN_IN_DOMAIN"}


def test_brand_token_in_domain():
    assert "URL_BRAND_TOKEN_IN_DOMAIN" in rule_ids("https://tinkoff-bonus.test/")


def test_edit_distance_and_skeleton():
    assert edit_distance("microsoft", "microsfot") == 1
    assert edit_distance("paypal", "paypal") == 0
    assert skeleton("g00gle") == "google"
    assert skeleton("раураl") == "paypal"


# --- Redaction ----------------------------------------------------------------

def test_password_and_sensitive_query_redacted():
    p = parse_url("https://user:hunter2@example.net/cb?access_token=SECRET1&page=2&code=777#id_token=SECRET2")
    assert "hunter2" not in p.sanitized
    assert "SECRET1" not in p.sanitized and "SECRET2" not in p.sanitized
    assert "777" not in p.sanitized
    assert "page=2" in p.sanitized
    assert "user:***@example.net" in p.sanitized
    finding_text = " ".join(f.evidence for f in analyze_url(p.original).findings)
    assert "hunter2" not in finding_text


# --- Offline guarantee ------------------------------------------------------------

def test_no_network_requests(no_network):
    url_analyzer._extractor.cache_clear()
    for url in ["https://paypal.com.evil.example/", "https://госуслуги.рф/", "http://192.0.2.1/", "https://bit.ly/x"]:
        analyze_url(url)
