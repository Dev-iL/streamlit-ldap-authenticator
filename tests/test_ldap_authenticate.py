"""Tests for streamlit_ldap_authenticator.ldap_authenticate.LdapAuthenticate."""

import ldap
import pytest
from unittest.mock import MagicMock

from streamlit_ldap_authenticator.ldap_authenticate import LdapAuthenticate


@pytest.fixture
def ldap_auth(ldap_config):
    return LdapAuthenticate(ldap_config)


@pytest.fixture
def mock_conn():
    """A mock python-ldap LDAPObject that simulates a successful bind."""
    conn = MagicMock()
    return conn


# ---------------------------------------------------------------------------
# AC-1.6 — LdapAuthenticate.login() tests
# ---------------------------------------------------------------------------


class TestLdapLogin:
    def test_successful_bind_returns_user_info(self, ldap_auth, mock_conn, mocker):
        """Successful LDAP bind + get_info returns the user dict."""
        user = {"cn": "alice", "mail": "alice@example.com"}
        mocker.patch("ldap.initialize", return_value=mock_conn)

        get_info = MagicMock(return_value=user)

        result = ldap_auth.login("alice", "correct_password", get_info)

        assert result == user
        get_info.assert_called_once()
        mock_conn.unbind_s.assert_called_once()

    def test_wrong_credentials_returns_error_string(self, ldap_auth, mock_conn, mocker):
        """INVALID_CREDENTIALS exception → 'Wrong username or password' string."""
        # pyrefly: ignore [missing-attribute]
        mock_conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS(
            {"desc": "Invalid credentials"}
        )
        mocker.patch("ldap.initialize", return_value=mock_conn)

        result = ldap_auth.login("alice", "wrong_password", MagicMock())

        assert result == "Wrong username or password"
        mock_conn.unbind_s.assert_not_called()

    def test_exception_during_bind_returns_sanitized_string(
        self, ldap_auth, mock_conn, mocker
    ):
        """LDAPError during bind returns a string with server path replaced.

        The server path (``ldap://test-server:389``) must be stripped from the
        returned message to avoid exposing internal topology.
        """
        server_path = ldap_auth.config.server_path  # "ldap://test-server:389"
        # pyrefly: ignore [missing-attribute]
        mock_conn.simple_bind_s.side_effect = ldap.SERVER_DOWN(
            {"desc": f"Cannot contact LDAP server at {server_path}"}
        )
        mocker.patch("ldap.initialize", return_value=mock_conn)

        result = ldap_auth.login("alice", "pass", MagicMock())

        assert isinstance(result, str)
        assert server_path not in result
        assert "server" in result
