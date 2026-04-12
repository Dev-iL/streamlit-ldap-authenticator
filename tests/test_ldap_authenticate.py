"""Tests for streamlit_ldap_authenticator.ldap_authenticate.LdapAuthenticate."""

import pytest
from unittest.mock import MagicMock

from ldap3.core.exceptions import LDAPException

from streamlit_ldap_authenticator.ldap_authenticate import LdapAuthenticate


@pytest.fixture
def ldap_auth(ldap_config):
    return LdapAuthenticate(ldap_config)


@pytest.fixture
def mock_conn():
    """A mock ldap3 Connection that simulates a successful bind."""
    conn = MagicMock()
    conn.bound = True
    conn.result = {"result": 0}
    return conn


# ---------------------------------------------------------------------------
# AC-1.6 — LdapAuthenticate.login() tests
# ---------------------------------------------------------------------------


class TestLdapLogin:
    def test_successful_bind_returns_user_info(self, ldap_auth, mock_conn, mocker):
        """Successful LDAP bind + get_info returns the user dict."""
        user = {"cn": "alice", "mail": "alice@example.com"}
        mock_conn.result = {"result": 0}
        mocker.patch(
            "streamlit_ldap_authenticator.ldap_authenticate.Connection",
            return_value=mock_conn,
        )
        mocker.patch(
            "streamlit_ldap_authenticator.ldap_authenticate.Server",
        )

        get_info = MagicMock(return_value=user)

        result = ldap_auth.login("alice", "correct_password", get_info)

        assert result == user
        get_info.assert_called_once()

    def test_wrong_credentials_returns_error_string(self, ldap_auth, mock_conn, mocker):
        """LDAP bind result != 0 → 'Wrong username or password' string."""
        mock_conn.result = {"result": 49}  # LDAP_INVALID_CREDENTIALS
        mock_conn.bound = False
        mocker.patch(
            "streamlit_ldap_authenticator.ldap_authenticate.Connection",
            return_value=mock_conn,
        )
        mocker.patch(
            "streamlit_ldap_authenticator.ldap_authenticate.Server",
        )

        result = ldap_auth.login("alice", "wrong_password", MagicMock())

        assert result == "Wrong username or password"

    def test_exception_during_bind_returns_sanitized_string(
        self, ldap_auth, mock_conn, mocker
    ):
        """Exception during bind returns a string with server path replaced.

        The server path (``ldap://test-server:389``) must be stripped from the
        returned message to avoid exposing internal topology.
        """
        server_path = ldap_auth.config.server_path  # "ldap://test-server:389"
        mock_conn.bind.side_effect = LDAPException(
            f"Connection refused to {server_path}"
        )
        mocker.patch(
            "streamlit_ldap_authenticator.ldap_authenticate.Connection",
            return_value=mock_conn,
        )
        mocker.patch(
            "streamlit_ldap_authenticator.ldap_authenticate.Server",
        )

        result = ldap_auth.login("alice", "pass", MagicMock())

        assert isinstance(result, str)
        assert server_path not in result
        assert "server" in result
