"""Tests for the native Streamlit OIDC authentication flow."""

from unittest.mock import MagicMock

import pytest
import streamlit as st

from streamlit_ldap_authenticator.authenticate import Authenticate
from streamlit_ldap_authenticator.ldap_authenticate import LdapAuthenticate

ALLOWED_CLAIMS = {
    "sub": "00u123",
    "email": "alice@example.com",
    "name": "Alice",
    "groups": ["admins"],
}


class FakeUser(dict):
    def __init__(self, *, is_logged_in: bool, **claims):
        super().__init__(claims)
        self.is_logged_in = is_logged_in

    def to_dict(self):
        return dict(self)


def set_user(mocker, *, is_logged_in=True, **claims):
    user = FakeUser(is_logged_in=is_logged_in, **claims)
    mocker.patch.object(st, "user", user)
    return user


def test_unauthenticated_user_gets_login_button(mocker):
    set_user(mocker, is_logged_in=False)
    button = mocker.patch.object(st, "button", return_value=False)
    login = mocker.patch.object(st, "login")

    assert Authenticate().login() is None

    button.assert_called_once()
    assert button.call_args.args == ("Log in",)
    button.call_args.kwargs["on_click"]()
    login.assert_called_once_with()


def test_named_provider_is_forwarded(mocker):
    set_user(mocker, is_logged_in=False)
    button = mocker.patch.object(st, "button", return_value=False)
    login = mocker.patch.object(st, "login")

    Authenticate().login(provider="okta")

    button.call_args.kwargs["on_click"](*button.call_args.kwargs["args"])
    login.assert_called_once_with("okta")


def test_claim_allowlist_removes_tokens(mocker):
    set_user(
        mocker,
        sub="00u123",
        email="alice@example.com",
        tokens={"access_token": "secret"},
        nonce="nonce",
        is_logged_in=True,
        unrelated="drop me",
    )
    state = {}
    mocker.patch.object(st, "session_state", state)

    result = Authenticate().login()

    assert result == {"sub": "00u123", "email": "alice@example.com"}
    assert state == {}


def test_no_ldap_additional_check_receives_claims_and_none(mocker):
    set_user(mocker, **ALLOWED_CLAIMS)
    additional_check = MagicMock(return_value=True)
    callback = MagicMock(return_value=None)

    result = Authenticate().login(
        additional_check=additional_check,
        callback=callback,
    )

    assert result == ALLOWED_CLAIMS
    additional_check.assert_called_once_with(None, ALLOWED_CLAIMS)
    callback.assert_called_once_with(ALLOWED_CLAIMS)


def test_get_info_without_ldap_is_denied(mocker):
    set_user(mocker, **ALLOWED_CLAIMS)
    get_info = MagicMock()
    callback = MagicMock()
    error = mocker.patch.object(st, "error")

    assert Authenticate().login(get_info=get_info, callback=callback) is None

    get_info.assert_not_called()
    callback.assert_not_called()
    error.assert_called_once()


def test_get_info_without_ldap_is_denied_before_rendering_login(mocker):
    set_user(mocker, is_logged_in=False)
    button = mocker.patch.object(st, "button")
    error = mocker.patch.object(st, "error")

    assert Authenticate().login(get_info=lambda *_args: {}) is None

    button.assert_not_called()
    error.assert_called_once()


def test_missing_identifier_does_not_open_ldap(mocker, ldap_config):
    set_user(
        mocker,
        email=" ",
        preferred_username=123,
        login=None,
        upn="",
    )
    auth = Authenticate(ldap_config)
    lookup = mocker.patch.object(auth.ldap_auth, "lookup")
    error = mocker.patch.object(st, "error")

    assert auth.login() is None

    lookup.assert_not_called()
    error.assert_called_once()


@pytest.mark.parametrize(
    ("claims", "expected_identifier"),
    [
        ({"email": " Alice@example.com "}, "Alice@example.com"),
        ({"email": "", "preferred_username": " DOMAIN\\alice "}, "DOMAIN\\alice"),
        ({"email": 42, "preferred_username": "", "login": " raw-user "}, "raw-user"),
        (
            {"email": "", "preferred_username": "", "login": "", "upn": "upn-user"},
            "upn-user",
        ),
    ],
)
def test_identifier_claim_precedence_and_normalization(
    mocker, ldap_config, claims, expected_identifier
):
    set_user(mocker, **claims)
    auth = Authenticate(ldap_config)
    lookup = mocker.patch.object(auth.ldap_auth, "lookup", return_value={"cn": "Alice"})

    result = auth.login()
    assert result is not None
    assert result["cn"] == "Alice"

    assert lookup.call_args.args[0] == expected_identifier


@pytest.mark.parametrize("identifier", [None, 0, [], " ", ""])
def test_invalid_identifier_values_are_skipped(mocker, ldap_config, identifier):
    set_user(mocker, email=identifier, preferred_username=None, login="", upn=None)
    auth = Authenticate(ldap_config)
    lookup = mocker.patch.object(auth.ldap_auth, "lookup")
    error = mocker.patch.object(st, "error")

    assert auth.login() is None

    lookup.assert_not_called()
    error.assert_called_once()


@pytest.mark.parametrize(
    ("value", "method", "mapped"),
    [
        (" Alice@example.com ", "get_info_by_user_principal_name", "Alice@example.com"),
        (" DOMAIN\\alice ", "get_info_by_sam_account_name", "alice"),
        (" DOMAIN\\team\\alice ", "get_info_by_sam_account_name", "team\\alice"),
        (" DOMAIN\\team\\ ", "get_info_by_sam_account_name", "DOMAIN\\team\\"),
        (" alice ", "get_info_by_sam_account_name", "alice"),
    ],
)
def test_default_get_info_maps_identifiers(mocker, ldap_config, value, method, mapped):
    auth = Authenticate(ldap_config)
    connection = object()
    directory_method = mocker.patch.object(
        auth.ldap_auth, method, return_value={"cn": "Alice"}
    )

    assert auth.get_info(connection, value) == {"cn": "Alice"}

    directory_method.assert_called_once_with(connection, mapped)


def test_ldap_claims_merge_with_oidc_precedence_and_callback(mocker, ldap_config):
    set_user(mocker, email="alice@example.com", name="OIDC Alice", sub="00u123")
    auth = Authenticate(ldap_config)
    raw_ldap = {
        "email": "ldap@example.com",
        "name": "LDAP Alice",
        "department": "IT",
        "tokens": {"secret": "drop"},
    }
    lookup = mocker.patch.object(auth.ldap_auth, "lookup", return_value=raw_ldap)
    additional_check = MagicMock(return_value=True)
    callback = MagicMock(return_value=None)

    result = auth.login(
        additional_check=additional_check,
        callback=callback,
    )

    expected = {
        "email": "alice@example.com",
        "name": "OIDC Alice",
        "sub": "00u123",
        "department": "IT",
    }
    assert result == expected
    assert lookup.call_args.args[2] is additional_check
    callback.assert_called_once_with(expected)


@pytest.mark.parametrize("callback_result", ["cancel", False, 1, object()])
def test_invalid_login_callback_returns_deny(mocker, callback_result):
    set_user(mocker, **ALLOWED_CLAIMS)
    callback = MagicMock(return_value=callback_result)
    error = mocker.patch.object(st, "error")

    assert Authenticate().login(callback=callback) is None

    callback.assert_called_once_with(ALLOWED_CLAIMS)
    error.assert_called_once()


def test_login_callback_exception_denies_without_session_state(mocker):
    set_user(mocker, **ALLOWED_CLAIMS)
    state = {}
    mocker.patch.object(st, "session_state", state)
    error = mocker.patch.object(st, "error")

    def fail(_user):
        raise RuntimeError("do not expose this")

    assert Authenticate().login(callback=fail) is None

    assert state == {}
    assert "do not expose this" not in str(error.call_args)


@pytest.mark.parametrize("check_result", [False, "allow"])
def test_additional_check_must_return_true(mocker, check_result):
    set_user(mocker, **ALLOWED_CLAIMS)
    additional_check = MagicMock(return_value=check_result)
    callback = MagicMock()
    error = mocker.patch.object(st, "error")

    assert (
        Authenticate().login(additional_check=additional_check, callback=callback)
        is None
    )

    additional_check.assert_called_once_with(None, ALLOWED_CLAIMS)
    callback.assert_not_called()
    error.assert_called_once()


def test_logout_success_uses_sanitized_oidc_claims(mocker):
    set_user(
        mocker,
        **ALLOWED_CLAIMS,
        tokens={"access_token": "secret"},
        nonce="nonce",
    )
    button = mocker.patch.object(st, "button", return_value=True)
    logout = mocker.patch.object(st, "logout")
    callback = MagicMock(return_value=None)

    Authenticate().create_logout_form(callback=callback, label="Sign out")

    assert button.call_args.args == ("Sign out",)
    callback.assert_called_once_with(ALLOWED_CLAIMS)
    logout.assert_called_once_with()


@pytest.mark.parametrize("callback_result", ["cancel", False, 1, object()])
def test_logout_callback_invalid_result_does_not_logout(mocker, callback_result):
    set_user(mocker, **ALLOWED_CLAIMS)
    mocker.patch.object(st, "button", return_value=True)
    logout = mocker.patch.object(st, "logout")
    error = mocker.patch.object(st, "error")

    Authenticate().create_logout_form(callback=lambda _user: callback_result)

    logout.assert_not_called()
    error.assert_called_once()


def test_logout_callback_exception_does_not_logout(mocker):
    set_user(mocker, **ALLOWED_CLAIMS)
    mocker.patch.object(st, "button", return_value=True)
    logout = mocker.patch.object(st, "logout")
    error = mocker.patch.object(st, "error")

    def fail(_user):
        raise RuntimeError("do not expose this")

    Authenticate().create_logout_form(callback=fail)

    logout.assert_not_called()
    error.assert_called_once()
    assert "do not expose this" not in str(error.call_args)


def test_logout_is_not_rendered_for_logged_out_user(mocker):
    set_user(mocker, is_logged_in=False)
    button = mocker.patch.object(st, "button")

    assert Authenticate().create_logout_form() is None

    button.assert_not_called()


def test_ldap_auth_only_exists_when_configured(ldap_config):
    assert Authenticate().ldap_auth is None
    assert isinstance(Authenticate(ldap_config).ldap_auth, LdapAuthenticate)
