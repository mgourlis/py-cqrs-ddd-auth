"""
Tests for Domain Value Objects.
"""

from cqrs_ddd_auth.domain.value_objects import UserClaims, TOTPSecret


def test_user_claims_creation():
    claims = UserClaims(
        sub="123",
        username="testuser",
        email="test@example.com",
        groups=("group1",),
        attributes={"attr1": "value1"},
    )
    assert claims.sub == "123"
    assert claims.username == "testuser"
    assert claims.email == "test@example.com"
    assert claims.groups == ("group1",)
    assert claims.attributes == {"attr1": "value1"}


def test_user_claims_comparison():
    c1 = UserClaims(sub="1", username="u", email="e", groups=(), attributes={})
    c2 = UserClaims(sub="1", username="u", email="e", groups=(), attributes={})
    c3 = UserClaims(sub="2", username="u", email="e", groups=(), attributes={})

    assert c1 == c2
    assert c1 != c3
    # UserClaims contains dict (attributes), so it is not hashable by default
    # assert hash(c1) == hash(c2)


def test_totp_secret_generation():
    secret = TOTPSecret.generate()
    assert secret.secret is not None
    assert len(secret.secret) > 0


def test_totp_secret_provisioning_uri():
    secret = TOTPSecret(secret="JBSWY3DPEHPK3PXP")
    uri = secret.get_provisioning_uri("user", "issuer")
    assert "otpauth://totp/issuer:user" in uri
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=issuer" in uri
