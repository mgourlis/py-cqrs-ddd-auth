import pytest
from unittest.mock import Mock, AsyncMock
from cqrs_ddd_auth.refresh.middleware import (
    BaseTokenRefreshMiddleware,
    TokenExtractionResult,
    TokenRefreshResult,
)


@pytest.fixture
def mock_adapter():
    return Mock()


@pytest.fixture
def middleware(mock_adapter):
    return BaseTokenRefreshMiddleware(adapter=mock_adapter)


class TestBaseTokenRefreshMiddleware:
    def test_extract_from_headers_bearer(self, middleware):
        headers = {"Authorization": "Bearer access123"}
        access, refresh = middleware.extract_from_headers(headers)
        assert access == "access123"
        assert refresh is None

    def test_extract_from_headers_custom_scheme(self, mock_adapter):
        mw = BaseTokenRefreshMiddleware(adapter=mock_adapter, header_scheme="Token")
        headers = {"Authorization": "Token access123"}
        access, refresh = mw.extract_from_headers(headers)
        assert access == "access123"

    def test_extract_from_headers_missing(self, middleware):
        headers = {}
        access, refresh = middleware.extract_from_headers(headers)
        assert access is None
        assert refresh is None

    def test_extract_from_cookies_present(self, middleware):
        cookies = {"access_token": "acc", "refresh_token": "ref"}
        access, refresh = middleware.extract_from_cookies(cookies)
        assert access == "acc"
        assert refresh == "ref"

    def test_extract_from_cookies_partial(self, middleware):
        cookies = {"access_token": "acc"}
        access, refresh = middleware.extract_from_cookies(cookies)
        assert access == "acc"
        assert refresh is None

    def test_token_extraction_result_has_tokens(self):
        t1 = TokenExtractionResult(access_token="a")
        assert t1.has_tokens
        t2 = TokenExtractionResult(refresh_token="r")
        assert t2.has_tokens
        t3 = TokenExtractionResult()
        assert not t3.has_tokens

    @pytest.mark.asyncio
    async def test_process_refresh_logic_no_tokens(self, middleware, mock_adapter):
        extraction = TokenExtractionResult()
        result = await middleware.process_refresh_logic(extraction)
        assert not result.was_refreshed
        # Adapter should not be called
        mock_adapter.process_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_refresh_logic_with_tokens(self, middleware, mock_adapter):
        extraction = TokenExtractionResult(access_token="a", refresh_token="r")
        expected_result = TokenRefreshResult(new_access_token="token")
        mock_adapter.process_request = AsyncMock(return_value=expected_result)

        result = await middleware.process_refresh_logic(extraction)

        assert result.was_refreshed
        mock_adapter.process_request.assert_called_with(
            access_token="a", refresh_token="r"
        )
