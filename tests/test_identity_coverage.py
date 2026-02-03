from cqrs_ddd_auth.identity import (
    AuthenticatedIdentity,
    AnonymousIdentity,
    SystemIdentity,
)


def test_authenticated_identity_coverage():
    user = AuthenticatedIdentity(
        user_id="u1",
        username="user",
        groups=["u_group"],
        permissions=["p1"],
        tenant_id="t1",
    )

    assert user.user_id == "u1"
    assert user.username == "user"
    assert "u_group" in user.groups
    assert "p1" in user.permissions
    assert user.tenant_id == "t1"
    assert user.is_authenticated is True
    assert user.is_system is False


def test_static_identities():
    anon = AnonymousIdentity()
    assert anon.user_id == "anonymous"
    assert anon.is_authenticated is False

    sys = SystemIdentity()
    assert sys.user_id == "system"
    assert sys.is_authenticated is True
    assert sys.is_system is True


def test_identity_context_management():
    from cqrs_ddd_auth.identity import (
        get_identity,
        set_identity,
        clear_context,
        AuthenticatedIdentity,
    )

    # Default is Anonymous
    assert get_identity().user_id == "anonymous"

    user = AuthenticatedIdentity(user_id="u1", username="u")
    set_identity(user)
    assert get_identity().user_id == "u1"

    clear_context()
    assert get_identity().user_id == "anonymous"
