"""Shared fixtures for streamlit-ldap-authenticator tests."""

import pytest
import streamlit as st
from unittest.mock import MagicMock

from streamlit_ldap_authenticator.authenticate import Authenticate
from streamlit_ldap_authenticator.configs import CookieConfig, LdapConfig


@pytest.fixture
def cookie_config():
    return CookieConfig(
        key="test-secret-key-32chars-padded!!",
        name="test_cookie",
        expiry_days=1.0,
        delay_sec=0.0,
    )


@pytest.fixture
def ldap_config():
    return LdapConfig(
        server_path="ldap://test-server:389",
        domain="TEST",
        search_base="dc=test,dc=com",
        attributes=["cn", "mail"],
    )


@pytest.fixture
def session_state():
    """A plain dict standing in for st.session_state."""
    return {}


@pytest.fixture
def mock_cookie_manager():
    cm = MagicMock()
    cm.get.return_value = None
    cm.getAll.return_value = {}
    return cm


@pytest.fixture
def auth_instance(ldap_config, cookie_config, session_state, mock_cookie_manager, mocker):
    """Authenticate instance with all external dependencies mocked."""
    mocker.patch(
        "streamlit_ldap_authenticator.authenticate.CookieController",
        return_value=mock_cookie_manager,
    )
    mocker.patch("streamlit_ldap_authenticator.authenticate.authUI")
    # Patch both the module-level 'ss' alias and st.session_state so they
    # both refer to the same plain dict throughout each test.
    mocker.patch("streamlit_ldap_authenticator.authenticate.ss", new=session_state)
    mocker.patch.object(st, "session_state", session_state)
    mocker.patch("time.sleep")

    return Authenticate(ldap_config, cookie_configs=cookie_config)
