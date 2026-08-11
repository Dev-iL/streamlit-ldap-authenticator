"""Streamlit OIDC authentication with optional LDAP enrichment."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Literal

import streamlit as st

from streamlit_ldap_authenticator.configs import AttrDict, LdapConfig, UserInfos
from streamlit_ldap_authenticator.ldap_authenticate import Connection, LdapAuthenticate

logger = logging.getLogger("streamlit_ldap_authenticator")

RegexDomain = re.compile(r"^(.*)\\(.*)$")
RegexEmail = re.compile(r"^[\w\-.]+@([\w\-]+\.)+[\w\-]{2,4}$")

_OIDC_CLAIMS = frozenset(
    {
        "sub",
        "iss",
        "aud",
        "email",
        "email_verified",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "upn",
        "login",
        "groups",
        "roles",
        "oid",
        "tid",
        "ver",
    }
)
_RESERVED_CLAIMS = {"is_logged_in", "tokens", "nonce"}


class Authenticate:
    """Authenticate through Streamlit's native OIDC session."""

    ldap_auth: LdapAuthenticate | None

    def __init__(self, ldap_configs: LdapConfig | AttrDict | None = None) -> None:
        self.ldap_auth = (
            None if ldap_configs is None else LdapAuthenticate(ldap_configs)
        )

    @staticmethod
    def __claims() -> UserInfos:
        user = st.user
        values = user.to_dict() if hasattr(user, "to_dict") else dict(user)
        return {key: value for key, value in values.items() if key in _OIDC_CLAIMS}

    @staticmethod
    def __show_error(message: str) -> None:
        st.error(message)

    @staticmethod
    def __run_additional_check(
        additional_check: Callable[[Connection | None, UserInfos], Literal[True] | str]
        | None,
        connection: Connection | None,
        user: UserInfos,
    ) -> bool:
        if additional_check is None:
            return True
        try:
            result = additional_check(connection, user)
        except Exception as exc:  # noqa: BLE001 - isolate application checks
            logger.error(
                "Unexpected authentication check error: %s", type(exc).__name__
            )
            Authenticate.__show_error("Authentication check failed")
            return False
        if result is True:
            return True
        Authenticate.__show_error(
            result if isinstance(result, str) else "Authentication check failed"
        )
        return False

    @staticmethod
    def __run_login_callback(
        callback: Callable[[UserInfos], str | None] | None,
        user: UserInfos,
    ) -> UserInfos | None:
        if callback is None:
            return user
        try:
            result = callback(user)
        except Exception as exc:  # noqa: BLE001 - isolate application callbacks
            logger.error(
                "Unexpected authentication callback error: %s", type(exc).__name__
            )
            Authenticate.__show_error("Authentication callback failed")
            return None
        if result is None:
            return user
        Authenticate.__show_error(
            result if isinstance(result, str) else "Authentication callback failed"
        )
        return None

    @staticmethod
    def __identifier(claims: UserInfos) -> str | None:
        for name in ("email", "preferred_username", "login", "upn"):
            value = claims.get(name)
            if isinstance(value, str) and (value := value.strip()):
                return value
        return None

    def login(
        self,
        additional_check: Callable[[Connection | None, UserInfos], Literal[True] | str]
        | None = None,
        get_info: Callable[[Connection, str], UserInfos | None] | None = None,
        callback: Callable[[UserInfos], str | None] | None = None,
        *,
        provider: str | None = None,
    ) -> UserInfos | None:
        if self.ldap_auth is None and get_info is not None:
            self.__show_error("LDAP configuration is required for get_info")
            return None
        if not getattr(st.user, "is_logged_in", False):
            if provider is None:
                st.button("Log in", on_click=st.login)
            else:
                st.button("Log in", on_click=st.login, args=(provider,))
            return None

        claims = self.__claims()
        if self.ldap_auth is None:
            if not self.__run_additional_check(additional_check, None, claims):
                return None
            return self.__run_login_callback(callback, claims)

        identifier = self.__identifier(claims)
        if identifier is None:
            self.__show_error("No usable identity claim was provided")
            return None

        result = self.ldap_auth.lookup(
            identifier,
            get_info or self.get_info,
            additional_check,
        )
        if not isinstance(result, dict):
            self.__show_error(
                result if isinstance(result, str) else "LDAP lookup failed"
            )
            return None
        merged = {
            key: value for key, value in result.items() if key not in _RESERVED_CLAIMS
        }
        merged.update(claims)
        return self.__run_login_callback(callback, merged)

    def create_logout_form(
        self,
        callback: Callable[[UserInfos], Literal["cancel"] | None] | None = None,
        *,
        label: str = "Log out",
    ) -> None:
        if not getattr(st.user, "is_logged_in", False):
            return
        claims = self.__claims()
        if not st.button(label):
            return
        if callback is not None:
            try:
                result = callback(claims)
            except Exception as exc:  # noqa: BLE001 - isolate application callbacks
                logger.error("Unexpected logout callback error: %s", type(exc).__name__)
                self.__show_error("Logout callback failed")
                return
            if result is not None:
                self.__show_error(
                    "Logout cancelled"
                    if result == "cancel"
                    else "Logout callback failed"
                )
                return
        st.logout()

    def get_info(self, conn: Connection, identifier: str) -> UserInfos | None:
        if self.ldap_auth is None:
            return None
        identifier = identifier.strip()
        email = RegexEmail.fullmatch(identifier)
        if email is not None:
            return self.ldap_auth.get_info_by_user_principal_name(conn, identifier)
        domain = RegexDomain.fullmatch(identifier)
        if domain is not None and all(domain.groups()):
            prefix, _, name = identifier.partition("\\")
            if prefix and name:
                return self.ldap_auth.get_info_by_sam_account_name(conn, name)
        return self.ldap_auth.get_info_by_sam_account_name(conn, identifier)
