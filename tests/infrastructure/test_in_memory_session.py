"""
Tests for InMemory Session Adapter.
"""

import pytest
from datetime import datetime, timezone, timedelta

from cqrs_ddd_auth.infrastructure.adapters.session import InMemorySessionAdapter
from cqrs_ddd_auth.domain.aggregates import AuthSessionStatus


@pytest.mark.asyncio
async def test_create_and_get():
    repo = InMemorySessionAdapter()

    mod = await repo.create("1.2.3.4", "UA", 300)
    session = mod.session
    assert session
    assert session.id

    fetched = await repo.get(session.id)
    assert fetched
    assert fetched.id == session.id


@pytest.mark.asyncio
async def test_save_and_update():
    repo = InMemorySessionAdapter()
    mod = await repo.create("1.1.1.1", "UA", 300)
    session = mod.session

    session.subject_id = "user1"
    session.status = AuthSessionStatus.AUTHENTICATED

    await repo.save(session)

    fetched = await repo.get(session.id)
    assert fetched.subject_id == "user1"
    assert fetched.status == AuthSessionStatus.AUTHENTICATED


@pytest.mark.asyncio
async def test_delete():
    repo = InMemorySessionAdapter()
    mod = await repo.create("1.1.1.1", "UA", 300)
    session = mod.session

    await repo.delete(session.id)
    assert await repo.get(session.id) is None


@pytest.mark.asyncio
async def test_role_revocation():
    repo = InMemorySessionAdapter()
    m1 = await repo.create("1.1.1.1", "UA", 300)
    s1 = m1.session
    s1.subject_id = "u1"
    s1.status = AuthSessionStatus.AUTHENTICATED
    await repo.save(s1)

    m2 = await repo.create("2.2.2.2", "UA", 300)
    s2 = m2.session
    s2.subject_id = "u1"
    s2.status = AuthSessionStatus.AUTHENTICATED
    await repo.save(s2)

    count = await repo.revoke_all_for_user("u1")
    assert count == 2

    fetched = await repo.get(s1.id)
    assert fetched.status == AuthSessionStatus.REVOKED


@pytest.mark.asyncio
async def test_cleanup_expired():
    repo = InMemorySessionAdapter()
    m1 = await repo.create("1.1.1.1", "UA", -300)
    s1 = m1.session

    # Force expiration
    s1._expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    await repo.save(s1)

    m2 = await repo.create("1.1.1.1", "UA", 300)
    s2 = m2.session

    count = await repo.cleanup_expired()
    assert count == 1
    assert await repo.get(s1.id) is None
    assert await repo.get(s2.id) is not None


@pytest.mark.asyncio
async def test_revoke_redundant():
    repo = InMemorySessionAdapter()

    # Old session
    m1 = await repo.create("1.1.1.1", "UA", 300)
    s1 = m1.session
    s1.subject_id = "u1"
    s1.status = AuthSessionStatus.AUTHENTICATED
    s1._created_at = datetime.now(timezone.utc) - timedelta(hours=2)
    await repo.save(s1)

    # New session (same IP)
    m2 = await repo.create("1.1.1.1", "UA", 300)
    s2 = m2.session
    s2.subject_id = "u1"
    s2.status = AuthSessionStatus.AUTHENTICATED
    s2._created_at = datetime.now(timezone.utc)
    await repo.save(s2)

    # Other IP
    m3 = await repo.create("2.2.2.2", "UA", 300)
    s3 = m3.session
    s3.subject_id = "u1"
    s3.status = AuthSessionStatus.AUTHENTICATED
    await repo.save(s3)

    count = await repo.revoke_redundant_for_user("u1", "1.1.1.1")
    assert count == 1

    f1 = await repo.get(s1.id)
    assert f1.status == AuthSessionStatus.REVOKED
    f2 = await repo.get(s2.id)
    assert f2.status == AuthSessionStatus.AUTHENTICATED
