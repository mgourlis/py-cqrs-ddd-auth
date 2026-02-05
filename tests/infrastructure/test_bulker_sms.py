"""
Tests for Bulker SMS Adapters.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from cqrs_ddd_auth.contrib.fastapi.sms import BulkerSMSSender as FastAPIBulkerSender
from cqrs_ddd_auth.contrib.django.sms import BulkerSMSSender as DjangoBulkerSender
from cqrs_ddd_auth.infrastructure.ports.communication import SMSMessage


@pytest.mark.asyncio
async def test_fastapi_bulker_send_success():
    auth_key = "test_key"
    sender = FastAPIBulkerSender(auth_key=auth_key)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "OK;12345;0.05"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        msg = SMSMessage(to="+306912345678", body="Hello Bulker", from_number="SENDER")
        await sender.send(msg)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        data = kwargs["data"]
        assert data["auth_key"] == "test_key"
        assert data["to"] == "306912345678"
        assert data["text"] == "Hello Bulker"


@pytest.mark.asyncio
async def test_fastapi_bulker_send_error():
    sender = FastAPIBulkerSender(auth_key="test_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "ERROR;101;Invalid auth key"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response

        msg = SMSMessage(to="+306912345678", body="Fail", from_number="SENDER")
        with pytest.raises(Exception, match="Bulker API returned error"):
            await sender.send(msg)


@pytest.mark.asyncio
async def test_django_bulker_send_success():
    # Patch settings to avoid ImproperlyConfigured
    with patch("cqrs_ddd_auth.contrib.django.sms.settings", new=MagicMock()):
        sender = DjangoBulkerSender(auth_key="django_key", default_from_sms="DJANGO")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK;67890;0.05"

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            msg = SMSMessage(to="+306900000000", body="Django Test")
            await sender.send(msg)

            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            data = kwargs["data"]
            assert data["auth_key"] == "django_key"
            assert data["from"] == "DJANGO"
            assert data["text"] == "Django Test"


@pytest.mark.asyncio
async def test_bulker_missing_auth_key():
    msg = SMSMessage(to="+306912345678", body="No key")

    # Patch settings to None to simulate missing config
    with patch("cqrs_ddd_auth.contrib.django.sms.settings", None):
        django_sender = DjangoBulkerSender(auth_key=None)
        with pytest.raises(ValueError, match="Bulker AUTH_KEY is not configured"):
            await django_sender.send(msg)


@pytest.mark.asyncio
async def test_bulker_missing_originator():
    sender = FastAPIBulkerSender(auth_key="key")
    msg = SMSMessage(to="+306912345678", body="No from")  # from_number is None

    with pytest.raises(ValueError, match=r"Sender number \(from_number\) is required"):
        await sender.send(msg)
