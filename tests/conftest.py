"""Shared fixtures for streamlit-ldap-authenticator tests."""

import pytest

from streamlit_ldap_authenticator.configs import LdapConfig


@pytest.fixture
def ldap_config():
    return LdapConfig(
        server_path="ldap://test-server:389",
        domain="TEST",
        search_base="dc=test,dc=com",
        attributes=["cn", "mail"],
    )
