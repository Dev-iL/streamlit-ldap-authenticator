"""Tests for direct LDAP authentication and OIDC identity lookup."""

from unittest.mock import MagicMock

import ldap
import pytest

from streamlit_ldap_authenticator.ldap_authenticate import LdapAuthenticate


def ldap_error(name, details):
    return getattr(ldap, name)(details)


@pytest.fixture
def ldap_auth(ldap_config):
    return LdapAuthenticate(ldap_config)


@pytest.fixture
def connections(mocker):
    class ConnectionFactory(list):
        def __init__(self):
            super().__init__()
            self.pool = [MagicMock(), MagicMock()]

        def initialize(self, _server_path):
            connection = self.pool[len(self)]
            self.append(connection)
            return connection

        def __getitem__(self, index):
            return self.pool[index]

    factory = ConnectionFactory()
    mocker.patch("ldap.initialize", side_effect=factory.initialize)
    return factory


def test_direct_login_preserves_successful_bind(ldap_auth, mocker):
    connection = MagicMock()
    mocker.patch("ldap.initialize", return_value=connection)
    user = {"cn": "alice", "mail": "alice@example.com"}

    result = ldap_auth.login("alice", "correct_password", MagicMock(return_value=user))

    assert result == user
    connection.simple_bind_s.assert_called_once_with("alice", "correct_password")
    connection.unbind_s.assert_called_once_with()


def test_direct_login_invalid_credentials_returns_safe_string(ldap_auth, mocker):
    connection = MagicMock()
    connection.simple_bind_s.side_effect = ldap_error(
        "INVALID_CREDENTIALS", {"desc": "Invalid"}
    )
    mocker.patch("ldap.initialize", return_value=connection)

    result = ldap_auth.login("alice", "wrong_password", MagicMock())

    assert result == "Wrong username or password"
    connection.unbind_s.assert_not_called()


def test_direct_login_ldap_error_does_not_expose_server(ldap_auth, mocker):
    connection = MagicMock()
    connection.simple_bind_s.side_effect = ldap_error(
        "SERVER_DOWN", {"desc": f"Cannot contact {ldap_auth.config.server_path}"}
    )
    mocker.patch("ldap.initialize", return_value=connection)

    result = ldap_auth.login("alice", "password", MagicMock())

    assert isinstance(result, str)
    assert ldap_auth.config.server_path not in result


def test_direct_login_setup_failure_is_safe_and_unbinds(ldap_auth, mocker):
    connection = MagicMock()
    connection.set_option.side_effect = ldap_error(
        "SERVER_DOWN", {"desc": ldap_auth.config.server_path}
    )
    mocker.patch("ldap.initialize", return_value=connection)

    result = ldap_auth.login("alice", "password", MagicMock())

    assert isinstance(result, str)
    assert ldap_auth.config.server_path not in result
    connection.unbind_s.assert_called_once_with()


def test_lookup_uses_anonymous_bind_first(ldap_auth, connections, monkeypatch):
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_USERNAME", raising=False)
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_PASSWORD", raising=False)
    user = {"cn": "alice"}
    get_info = MagicMock(return_value=user)

    result = ldap_auth.lookup("alice@example.com", get_info)

    assert result == user
    connections[0].simple_bind_s.assert_called_once_with("", "")
    get_info.assert_called_once_with(connections[0], "alice@example.com")
    connections[0].unbind_s.assert_called_once_with()


def test_lookup_falls_back_after_anonymous_bind_error(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "svc@example.com")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "secret-password")
    connections[0].simple_bind_s.side_effect = ldap_error(
        "SERVER_DOWN", {"desc": "down"}
    )
    get_info = MagicMock(return_value={"cn": "alice"})

    result = ldap_auth.lookup("alice", get_info)

    assert result == {"cn": "alice"}
    connections[0].simple_bind_s.assert_called_once_with("", "")
    connections[1].simple_bind_s.assert_called_once_with(
        "svc@example.com", "secret-password"
    )
    connections[0].unbind_s.assert_called_once_with()
    connections[1].unbind_s.assert_called_once_with()


def test_lookup_falls_back_after_anonymous_no_record(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "svc")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "secret-password")
    get_info = MagicMock(side_effect=[None, {"cn": "alice"}])

    result = ldap_auth.lookup("alice", get_info)

    assert result == {"cn": "alice"}
    assert [call.args for call in get_info.call_args_list] == [
        (connections[0], "alice"),
        (connections[1], "alice"),
    ]
    connections[0].unbind_s.assert_called_once_with()
    connections[1].unbind_s.assert_called_once_with()


@pytest.mark.parametrize(
    ("username", "password"),
    [(None, None), ("", None), (None, ""), ("svc", "")],
)
def test_lookup_rejects_incomplete_service_environment(
    ldap_auth, connections, monkeypatch, username, password
):
    if username is None:
        monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_USERNAME", raising=False)
    else:
        monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", username)
    if password is None:
        monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", password)
    connections[0].simple_bind_s.side_effect = ldap_error(
        "SERVER_DOWN", {"desc": "down"}
    )

    result = ldap_auth.lookup("alice", MagicMock())

    assert isinstance(result, str)
    assert "LDAP" in result
    assert "down" not in result
    assert ldap_auth.config.server_path not in result
    assert len(connections) == 1


def test_lookup_rejects_both_empty_service_environment(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "")

    result = ldap_auth.lookup("alice", MagicMock(return_value=None))

    assert isinstance(result, str)
    assert len(connections) == 1


def test_lookup_without_service_account_reports_no_record(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_USERNAME", raising=False)
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_PASSWORD", raising=False)

    result = ldap_auth.lookup("alice", MagicMock(return_value=None))

    assert result == "User not found"
    assert len(connections) == 1


def test_lookup_service_account_no_record_is_safe(ldap_auth, connections, monkeypatch):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "svc")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "secret-password")

    result = ldap_auth.lookup("alice", MagicMock(return_value=None))

    assert result == "User not found"
    assert len(connections) == 2
    assert all(connection.unbind_s.call_count == 1 for connection in connections)


def test_lookup_search_ldap_error_retries_with_service_account(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "svc")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "secret-password")
    get_info = MagicMock(
        side_effect=[
            ldap_error("SERVER_DOWN", {"desc": "search failed"}),
            {"cn": "alice"},
        ]
    )

    assert ldap_auth.lookup("alice", get_info) == {"cn": "alice"}
    assert len(connections) == 2
    assert all(connection.unbind_s.call_count == 1 for connection in connections)


def test_lookup_all_bind_failures_are_generic(ldap_auth, connections, monkeypatch):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "svc")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "secret-password")
    failure = ldap_error("SERVER_DOWN", {"desc": f"bad {ldap_auth.config.server_path}"})
    connections[0].simple_bind_s.side_effect = failure
    connections[1].simple_bind_s.side_effect = ldap_error(
        "SERVER_DOWN", {"desc": "also bad"}
    )
    get_info = MagicMock()

    result = ldap_auth.lookup("alice", get_info)

    assert isinstance(result, str)
    assert ldap_auth.config.server_path not in result
    get_info.assert_not_called()
    assert all(connection.unbind_s.call_count == 1 for connection in connections)


def test_lookup_unexpected_get_info_exception_does_not_retry(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "svc")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "secret-password")
    get_info = MagicMock(side_effect=RuntimeError("secret internal detail"))

    result = ldap_auth.lookup("alice", get_info)

    assert isinstance(result, str)
    assert "secret internal detail" not in result
    assert len(connections) == 1
    connections[0].unbind_s.assert_called_once_with()


def test_lookup_authorization_denial_does_not_retry(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_USERNAME", "svc")
    monkeypatch.setenv("LDAP_SERVICE_ACCOUNT_PASSWORD", "secret-password")
    additional_check = MagicMock(return_value=False)

    result = ldap_auth.lookup(
        "alice",
        MagicMock(return_value={"cn": "alice"}),
        additional_check,
    )

    assert isinstance(result, str)
    additional_check.assert_called_once_with(connections[0], {"cn": "alice"})
    assert len(connections) == 1


def test_lookup_unexpected_authorization_exception_is_safe(ldap_auth, connections):
    additional_check = MagicMock(side_effect=RuntimeError("private detail"))

    result = ldap_auth.lookup(
        "alice",
        MagicMock(return_value={"cn": "alice"}),
        additional_check,
    )

    assert isinstance(result, str)
    assert "private detail" not in result
    connections[0].unbind_s.assert_called_once_with()


def test_lookup_initialize_failure_is_safe(ldap_auth, mocker, monkeypatch):
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_USERNAME", raising=False)
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_PASSWORD", raising=False)
    mocker.patch(
        "ldap.initialize",
        side_effect=ldap_error("SERVER_DOWN", {"desc": ldap_auth.config.server_path}),
    )

    result = ldap_auth.lookup("alice", MagicMock())

    assert result == "LDAP lookup configuration is incomplete"
    assert ldap_auth.config.server_path not in result


def test_lookup_setup_failure_unbinds_partial_connection(
    ldap_auth, connections, monkeypatch
):
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_USERNAME", raising=False)
    monkeypatch.delenv("LDAP_SERVICE_ACCOUNT_PASSWORD", raising=False)
    connections[0].set_option.side_effect = ldap_error(
        "SERVER_DOWN", {"desc": ldap_auth.config.server_path}
    )

    result = ldap_auth.lookup("alice", MagicMock())

    assert isinstance(result, str)
    connections[0].unbind_s.assert_called_once_with()
