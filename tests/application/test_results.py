"""
Tests for Application Results.
"""

from cqrs_ddd_auth.application.results import AuthResult, TokenPair


def test_auth_result_factories():
    tokens = TokenPair("at", "rt")

    # Success
    res = AuthResult.success(tokens, "u1", "alice")
    assert res.is_success
    assert res.user_id == "u1"
    assert res.tokens == tokens

    # Failed
    res = AuthResult.failed("bad", "CODE")
    assert res.is_failed
    assert res.error_message == "bad"
    assert res.error_code == "CODE"

    # OTP Required
    res = AuthResult.otp_required(["totp"], "sess1")
    assert res.requires_otp
    assert res.session_id == "sess1"
    assert "totp" in res.available_otp_methods


def test_token_pair_defaults():
    tp = TokenPair("a", "b")
    assert tp.token_type == "Bearer"
    assert tp.expires_in == 3600
