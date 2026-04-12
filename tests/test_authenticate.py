"""Tests for streamlit_ldap_authenticator.authenticate.Authenticate."""

import jwt
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, PropertyMock

import streamlit as st
from streamlit_rsa_auth_ui import SigninEvent, SignoutEvent

from streamlit_ldap_authenticator.authenticate import Authenticate
from streamlit_ldap_authenticator.configs import CookieConfig, LoginConfig


# ---------------------------------------------------------------------------
# Helpers for accessing private (name-mangled) static methods
# ---------------------------------------------------------------------------


def _encode(cookie_config: CookieConfig, user: dict) -> str:
    return Authenticate._Authenticate__token_encode(cookie_config, user)  # type: ignore[attr-defined]


def _decode(cookie_config: CookieConfig, token) -> dict | None:
    return Authenticate._Authenticate__token_decode(cookie_config, token)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# AC-1.2 — Token encode/decode tests
# ---------------------------------------------------------------------------


class TestTokenEncodeDecode:
    def test_roundtrip_returns_original_user(self, cookie_config):
        """Valid token encodes and decodes back to the original user dict."""
        user = {"cn": "alice", "mail": "alice@test.com"}
        token = _encode(cookie_config, user)
        assert isinstance(token, str)
        result = _decode(cookie_config, token)
        assert result == user

    def test_expired_token_returns_none(self, cookie_config):
        """A token whose exp claim is in the past returns None."""
        past = datetime.now(tz=UTC) - timedelta(days=1)
        token = jwt.encode(
            {"user": {"cn": "alice"}, "exp": past},
            cookie_config.key,
            algorithm="HS256",
        )
        assert _decode(cookie_config, token) is None

    def test_invalid_signature_returns_none(self, cookie_config):
        """A token signed with a different key returns None."""
        token = jwt.encode(
            {
                "user": {"cn": "alice"},
                "exp_date": (datetime.now(tz=UTC) + timedelta(days=1)).timestamp(),
            },
            "wrong-secret-key-completely-different",
            algorithm="HS256",
        )
        assert _decode(cookie_config, token) is None

    def test_none_token_returns_none(self, cookie_config):
        """Passing None as token returns None without raising."""
        assert _decode(cookie_config, None) is None

    def test_old_format_token_returns_none(self, cookie_config):
        """Old-format token (exp_date at epoch — expired) returns None.

        This characterises that once D4 migrates to the standard ``exp`` claim,
        tokens using the legacy ``exp_date`` field will be rejected and return
        None (not raise an uncaught exception).
        """
        old_format_token = jwt.encode(
            {"user": {"cn": "alice"}, "exp_date": 0.0},  # Unix epoch — expired
            cookie_config.key,
            algorithm="HS256",
        )
        assert _decode(cookie_config, old_format_token) is None


# ---------------------------------------------------------------------------
# AC-1.3 — login() tests
# ---------------------------------------------------------------------------


class TestLogin:
    def test_session_state_cache_hit_returns_user(self, auth_instance, session_state):
        """User found in session state → returned immediately, no LDAP call."""
        user = {"cn": "alice", "mail": "alice@test.com"}
        session_state["login_user"] = user

        result = auth_instance.login()

        assert result == user

    def test_cookie_cache_hit_returns_user(
        self, auth_instance, cookie_config, session_state, mocker
    ):
        """Valid cookie → user returned without showing the login form."""
        user = {"cn": "bob", "mail": "bob@test.com"}
        token = _encode(cookie_config, user)
        mocker.patch.object(
            type(st.context),
            "cookies",
            new_callable=PropertyMock,
            return_value={cookie_config.name: token},
        )

        result = auth_instance.login()

        assert result == user
        assert session_state.get("login_user") == user

    def test_ldap_success_returns_user_and_triggers_rerun(
        self, auth_instance, session_state, mocker
    ):
        """Successful LDAP bind → returns user dict and schedules a rerun."""
        user = {"cn": "carol", "mail": "carol@test.com"}

        # Pre-populate auth_result so the del in __create_login_form succeeds
        session_state["login_result"] = "pending"

        # Mock the UI form to emit a sign-in event
        signin_event = SigninEvent()
        signin_event.username = "carol"
        signin_event.password = "s3cr3t"
        signin_event.remember = False
        auth_instance.ui.signinForm.return_value = MagicMock()
        mocker.patch(
            "streamlit_ldap_authenticator.authenticate.getEvent",
            return_value=signin_event,
        )
        mocker.patch("streamlit_ldap_authenticator.authenticate.st.spinner")
        mocker.patch("streamlit_ldap_authenticator.authenticate.st.error")
        rerun_spy = mocker.spy(st, "rerun")

        # LDAP auth succeeds
        auth_instance.ldap_auth.login = MagicMock(return_value=user)

        result = auth_instance.login()

        assert result == user
        rerun_spy.assert_called_once()

    def test_ldap_wrong_credentials_returns_none(
        self, auth_instance, session_state, mocker
    ):
        """LDAP returns error string → login() returns None."""
        session_state["login_result"] = "pending"

        signin_event = SigninEvent()
        signin_event.username = "dave"
        signin_event.password = "wrong"
        signin_event.remember = False
        auth_instance.ui.signinForm.return_value = MagicMock()
        mocker.patch(
            "streamlit_ldap_authenticator.authenticate.getEvent",
            return_value=signin_event,
        )
        mocker.patch("streamlit_ldap_authenticator.authenticate.st.spinner")
        mocker.patch("streamlit_ldap_authenticator.authenticate.st.error")

        auth_instance.ldap_auth.login = MagicMock(
            return_value="Wrong username or password"
        )

        result = auth_instance.login()

        assert result is None


# ---------------------------------------------------------------------------
# AC-1.4 — create_logout_form() tests
# ---------------------------------------------------------------------------


class TestLogoutForm:
    def _setup_signout(self, auth_instance, session_state, mock_cookie_manager, mocker):
        """Common setup: user is logged in, UI emits a SignoutEvent."""
        session_state["login_user"] = {"cn": "alice"}
        mocker.patch.object(
            type(st.context),
            "cookies",
            new_callable=PropertyMock,
            return_value={"test_cookie": "some_token"},
        )

        signout_event = SignoutEvent()
        auth_instance.ui.signoutForm.return_value = signout_event
        mocker.patch(
            "streamlit_ldap_authenticator.authenticate.getEvent",
            return_value=signout_event,
        )
        mocker.patch("streamlit_ldap_authenticator.authenticate.st.spinner")

    def test_logout_success_clears_user_and_cookie_and_reruns(
        self, auth_instance, session_state, mock_cookie_manager, mocker
    ):
        """Happy path: user is cleared, cookie is removed, rerun is triggered."""
        self._setup_signout(auth_instance, session_state, mock_cookie_manager, mocker)
        rerun_spy = mocker.spy(st, "rerun")

        auth_instance.create_logout_form()

        assert session_state.get("login_user") is None
        mock_cookie_manager.remove.assert_called_once()
        rerun_spy.assert_called_once()

    def test_logout_cancel_callback_stops_logout(
        self, auth_instance, session_state, mock_cookie_manager, mocker
    ):
        """Callback returning 'cancel' halts logout; user remains logged in."""
        self._setup_signout(auth_instance, session_state, mock_cookie_manager, mocker)
        rerun_spy = mocker.spy(st, "rerun")

        auth_instance.create_logout_form(callback=lambda event: "cancel")

        assert session_state.get("login_user") == {"cn": "alice"}
        mock_cookie_manager.remove.assert_not_called()
        rerun_spy.assert_not_called()


# ---------------------------------------------------------------------------
# AC-1.7 — __get_cookie() same-run characterisation
# ---------------------------------------------------------------------------


class TestGetCookieSameRun:
    def test_cookie_not_visible_same_run_returns_none(
        self, auth_instance, mock_cookie_manager
    ):
        """Characterisation: cookie just set in the same run is not yet visible.

        ``cookie_manager.get()`` returns None when the cookie was set on this
        run (browser hasn't sent it back yet).  This baseline is preserved when
        D5 switches the read path to ``st.context.cookies``, which has the same
        next-run-only semantics.
        """
        mock_cookie_manager.get.return_value = None  # simulates same-run invisibility

        result = auth_instance._Authenticate__get_cookie()  # type: ignore[attr-defined]

        assert result is None


# ---------------------------------------------------------------------------
# AC-5.7 — use_dialog=True auth and fragment logout observable results
# ---------------------------------------------------------------------------


class TestDialogAndFragment:
    def test_dialog_auth_result_in_session_state_returns_user(
        self, auth_instance, session_state
    ):
        """use_dialog=True: after dialog stores result in session state, subsequent
        login() call picks it up and returns the authenticated user (R-6 scenario).
        """
        user = {"cn": "frank", "mail": "frank@test.com"}
        # Simulate what the dialog stores after successful auth
        session_state[auth_instance.session_configs.auth_result] = user

        result = auth_instance.login(config=LoginConfig(use_dialog=True))

        assert result == user
        # auth_result key is cleaned up and user is stored in the user key
        assert auth_instance.session_configs.auth_result not in session_state
        assert session_state.get(auth_instance.session_configs.user) == user

    def test_fragment_logout_cancel_is_observable(
        self, auth_instance, session_state, mock_cookie_manager, mocker
    ):
        """@st.fragment-wrapped create_logout_form: a cancel callback prevents logout
        and the caller can observe the user is still logged in.
        """
        session_state["login_user"] = {"cn": "grace"}
        mock_cookie_manager.getAll.return_value = {"test_cookie": "some_token"}

        signout_event = SignoutEvent()
        auth_instance.ui.signoutForm.return_value = signout_event
        mocker.patch(
            "streamlit_ldap_authenticator.authenticate.getEvent",
            return_value=signout_event,
        )
        mocker.patch("streamlit_ldap_authenticator.authenticate.st.spinner")

        auth_instance.create_logout_form(callback=lambda event: "cancel")

        # User remains logged in (cancel was honoured)
        assert session_state.get("login_user") == {"cn": "grace"}
        mock_cookie_manager.remove.assert_not_called()
