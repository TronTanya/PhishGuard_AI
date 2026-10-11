import pytest

from message_analyzer import (
    MessageInputError,
    analyze_message,
    decode_upload,
    extract_urls,
    match_message_rules,
    redact_text,
)


def ids(text: str) -> set[str]:
    return {f.rule_id for f in match_message_rules(text)}


# --- Input handling -----------------------------------------------------------

@pytest.mark.parametrize("value", ["", "   \n\t", None])
def test_empty_message_rejected(value):
    with pytest.raises(MessageInputError):
        analyze_message(value)


def test_text_length_limit():
    with pytest.raises(MessageInputError, match="слишком длинный"):
        analyze_message("а" * 20001)


def test_upload_decoding():
    assert decode_upload("Привет".encode("utf-8")) == "Привет"
    assert decode_upload("\ufeffПривет".encode("utf-8")) == "Привет"


def test_upload_invalid_encoding():
    with pytest.raises(MessageInputError, match="UTF-8"):
        decode_upload("Привет".encode("cp1251"))


def test_upload_size_and_binary():
    with pytest.raises(MessageInputError, match="большой"):
        decode_upload(b"a" * (1024 * 1024 + 1))
    with pytest.raises(MessageInputError):
        decode_upload(b"abc\x00def")
    with pytest.raises(MessageInputError):
        decode_upload(b"   ")


# --- Phrase rules ----------------------------------------------------------------

def test_categories_detected_ru():
    assert "MSG_URGENCY" in ids("Срочно ответьте")
    assert "MSG_ACCOUNT_THREAT" in ids("Ваш аккаунт будет заблокирован")
    assert "MSG_CREDENTIAL_REQUEST" in ids("Сообщите код из СМС")
    assert "MSG_PAYMENT_REQUEST" in ids("Укажите номер карты и CVV")
    assert "MSG_PRIZE" in ids("Вы выиграли приз")
    assert "MSG_LINK_LOGIN" in ids("Перейдите по ссылке и введите пароль")


def test_categories_detected_en():
    assert "MSG_URGENCY" in ids("Act now!")
    assert "MSG_ACCOUNT_THREAT" in ids("Your account has been suspended")
    assert "MSG_CREDENTIAL_REQUEST" in ids("Please send me the verification code")
    assert "MSG_PRIZE" in ids("Congratulations, you've won")
    assert "MSG_LINK_LOGIN" in ids("Click the link and sign in")


def test_word_boundaries():
    # "срочно" inside a longer word must not match; "act now" inside "contact nowhere" must not match.
    assert "MSG_URGENCY" not in ids("Бессрочного договора нет")
    assert "MSG_URGENCY" not in ids("Please contact nowhere")
    assert "MSG_CREDENTIAL_REQUEST" not in ids("Recode the pin")


def test_yo_normalization_and_punctuation_gaps():
    assert "MSG_ACCOUNT_THREAT" in ids("Аккаунт будет удалён")
    assert "MSG_CREDENTIAL_REQUEST" in ids("Назовите, пожалуйста, код")


def test_link_login_requires_both_parts():
    assert "MSG_LINK_LOGIN" not in ids("Перейдите по ссылке, чтобы посмотреть расписание")
    assert "MSG_LINK_LOGIN" not in ids("Введите пароль в приложении")


def test_repeated_phrase_counted_once():
    analysis = analyze_message("Срочно! Срочно! СРОЧНО! Немедленно!")
    urgency = [f for f in analysis.findings if f.rule_id == "MSG_URGENCY"]
    assert len(urgency) == 1
    assert analysis.score.total == 5
    assert urgency[0].evidence.lower().count("срочно") == 1  # duplicate fragments collapsed


def test_educational_warning_triggers_documented_limitation():
    assert "MSG_CREDENTIAL_REQUEST" in ids("Никогда никому не сообщайте код из СМС")


def test_phrases_inside_urls_ignored():
    assert "MSG_URGENCY" not in ids("Материалы: https://example.com/srochno-urgent")


# --- URL extraction -------------------------------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("Ссылка: https://example.com/a.", "https://example.com/a"),
        ("Смотри https://example.com/a, потом", "https://example.com/a"),
        ("(см. https://example.com/a)", "https://example.com/a"),
        ("https://en.wikipedia.org/wiki/Foo_(bar))", "https://en.wikipedia.org/wiki/Foo_(bar)"),
        ("«https://example.com/x»", "https://example.com/x"),
        ("Go to https://example.com/x?!", "https://example.com/x"),
    ],
)
def test_url_extraction_trailing_punctuation(text, expected):
    assert extract_urls(text).urls == (expected,)


def test_no_duplicate_url_analysis():
    text = "https://bit.ly/a и снова https://bit.ly/a. И ещё раз https://bit.ly/a!"
    analysis = analyze_message(text)
    assert len(analysis.url_results) == 1


def test_url_limit_and_omitted_count():
    text = " ".join(f"https://site{i}.example.com/" for i in range(13))
    analysis = analyze_message(text)
    assert len(analysis.url_results) == 10
    assert analysis.omitted_urls == 3


def test_invalid_url_in_message_reported_not_crashing():
    analysis = analyze_message("Порт неверный: https://example.com:99999/")
    assert analysis.url_results[0].analysis is None
    assert "порт" in analysis.url_results[0].error


def test_text_and_url_scores_separate():
    analysis = analyze_message("Срочно перейдите: https://account.example.com@verify.example.net/login")
    assert analysis.score.total == 5
    assert analysis.url_results[0].analysis.score.total == 25


# --- Redaction --------------------------------------------------------------------

def test_redact_text_hides_codes_and_url_secrets():
    text = "Код 123456, карта 4111 1111 1111 1111, ссылка https://u:pw@example.com/?token=abc. Аудитория 305."
    redacted = redact_text(text)
    assert "123456" not in redacted
    assert "4111" not in redacted
    assert "pw@" not in redacted and "token=abc" not in redacted
    assert "305" in redacted


def test_no_network_requests(no_network):
    analyze_message("Срочно! https://paypal.com.evil.example/login и https://bit.ly/x")
