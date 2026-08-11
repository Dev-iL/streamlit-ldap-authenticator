"""Regression tests: package behaviour when python-ldap is absent.

Previously, ldap_authenticate.py had ``import ldap`` at the module level, which
caused a ModuleNotFoundError to propagate on any environment where python-ldap
was not available (e.g. Python 3.14 on Linux before a compatible wheel exists).

After the fix:
  - The package must be importable without python-ldap.
  - Instantiating LdapAuthenticate (or Authenticate) must raise ImportError with
    a clear, actionable message rather than a raw ModuleNotFoundError buried
    inside login().
"""

import sys
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest


@contextmanager
def _ldap_blocked():
    """Context manager that hides python-ldap for the duration of the block.

    Evicts all ``ldap.*`` and ``streamlit_ldap_authenticator.*`` entries from
    ``sys.modules``, injects ``None`` sentinels for the ldap packages (which
    makes Python raise ImportError on any ``import ldap`` attempt), then
    restores everything on exit.
    """
    saved: dict = {}
    to_evict = [
        k
        for k in sys.modules
        if k == "ldap" or k.startswith(("ldap.", "streamlit_ldap_authenticator"))
    ]
    for k in to_evict:
        saved[k] = sys.modules.pop(k)

    sys.modules["ldap"] = None  # type: ignore[assignment]
    sys.modules["ldap.filter"] = None  # type: ignore[assignment]
    sys.modules["ldap.ldapobject"] = None  # type: ignore[assignment]

    try:
        yield
    finally:
        for k in list(sys.modules):
            if k == "ldap" or k.startswith(("ldap.", "streamlit_ldap_authenticator")):
                del sys.modules[k]
        sys.modules.update(saved)


def test_package_importable_without_python_ldap():
    """Importing streamlit_ldap_authenticator must not raise when python-ldap is missing."""
    with _ldap_blocked():
        import streamlit_ldap_authenticator  # noqa: F401  — must not raise


def test_ldap_authenticate_raises_import_error_without_python_ldap():
    """LdapAuthenticate.__init__ must raise ImportError (not ModuleNotFoundError
    buried in login()) when python-ldap is unavailable."""
    with _ldap_blocked():
        from streamlit_ldap_authenticator.configs import LdapConfig
        from streamlit_ldap_authenticator.ldap_authenticate import LdapAuthenticate

        config = LdapConfig(
            server_path="ldap://test-server:389",
            domain="TEST",
            search_base="dc=test,dc=com",
            attributes=["cn"],
        )
        with pytest.raises(ImportError, match="python-ldap"):
            LdapAuthenticate(config)


def test_oidc_only_constructor_and_get_info_are_available_without_ldap():
    with _ldap_blocked():
        import streamlit as st

        from streamlit_ldap_authenticator import Authenticate

        user = SimpleNamespace(is_logged_in=True, to_dict=lambda: {"sub": "00u123"})
        with patch.object(st, "user", user), patch.object(st, "error") as error:
            auth = Authenticate()
            assert auth.ldap_auth is None
            assert auth.login(get_info=lambda *_args: {}) is None
            error.assert_called_once()


def test_public_exports_match_oidc_surface():
    import streamlit_ldap_authenticator as package

    assert set(package.__all__) == {
        "Authenticate",
        "LdapConfig",
        "UserInfos",
        "Connection",
        "LdapAuthenticate",
        "RegexDomain",
        "RegexEmail",
    }
    for removed in (
        "CookieConfig",
        "EncryptorConfig",
        "LoginConfig",
        "LogoutConfig",
        "SessionStateConfig",
    ):
        assert not hasattr(package, removed)
