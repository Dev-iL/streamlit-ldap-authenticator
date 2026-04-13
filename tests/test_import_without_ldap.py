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
        if k == "ldap"
        or k.startswith("ldap.")
        or k.startswith("streamlit_ldap_authenticator")
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
            if (
                k == "ldap"
                or k.startswith("ldap.")
                or k.startswith("streamlit_ldap_authenticator")
            ):
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
        from streamlit_ldap_authenticator.ldap_authenticate import LdapAuthenticate
        from streamlit_ldap_authenticator.configs import LdapConfig

        config = LdapConfig(
            server_path="ldap://test-server:389",
            domain="TEST",
            search_base="dc=test,dc=com",
            attributes=["cn"],
        )
        with pytest.raises(ImportError, match="python-ldap"):
            LdapAuthenticate(config)
