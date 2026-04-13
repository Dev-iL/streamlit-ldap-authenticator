# Author    : Nathan Chen
# Date      : 04-Apr-2024

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from ldap.ldapobject import LDAPObject as Connection

try:
    from ldap.ldapobject import LDAPObject as Connection

    _LDAP_AVAILABLE = True
except ImportError:
    Connection = Any  # type: ignore[assignment,misc]
    _LDAP_AVAILABLE = False

from streamlit_ldap_authenticator.configs import (
    AttrDict,
    LdapConfig,
    UserInfos,
    UserInfoValue,
)
from streamlit_ldap_authenticator.exceptions import ActiveDirectoryAttributeError

logger = logging.getLogger("streamlit_ldap_authenticator")


class LdapAuthenticate:
    """Authentication using active directory.

    ## Properties
    config: LdapConfig
        Config for authentication using active directory
    """

    config: LdapConfig

    def __init__(self, config: LdapConfig | AttrDict) -> None:
        """Create an instance of `LdapAuthenticate` object.

        ## Arguments
        config: LdapConfig | dict | streamlit.runtime.secrets.AttrDict
            Config for authentication using active directory
        """
        if not _LDAP_AVAILABLE:
            raise ImportError(
                "python-ldap is required for LDAP authentication but is not installed.\n"
                "Install it with: pip install python-ldap\n"
                "Note: python-ldap is a C extension and requires system LDAP libraries "
                "(e.g. libldap-dev on Debian/Ubuntu). Pre-built wheels for your "
                "platform/Python version may not be available."
            )
        self.config = LdapConfig.get_instance(config)

    def __make_uri(self) -> str:
        """Build the LDAP URI from server_path and use_ssl."""
        uri = self.config.server_path
        if "://" not in uri:
            scheme = "ldaps" if self.config.use_ssl else "ldap"
            return f"{scheme}://{uri}"
        return uri

    def login(
        self,
        username: str,
        password: str,
        get_info: Callable[[Connection], UserInfos | None],
        additional_check: Callable[[Connection | None, UserInfos], Literal[True] | str]
        | None = None,
    ) -> UserInfos | str:
        """Login to active directory.

        ## Arguments
        username: str
            username to log in to active directory
        password: str
            password to log in to active directory
        get_info: (connection: Connection) -> UserInfos | None
            Function to retrieve user information from active directory
        additional_check: ((connection: Connection | None, user: UserInfos) -> (True | str)) | None
            * Function to perform additional authentication check.
            * Function must return `True` if additional authentication is successful, otherwise must return error message
            * Passing `None` will ignore additional authentication check.

        ## Returns:
        UserInfos | str
            User information if authentication is successful.
            otherwise, authentication fail message
        """
        import ldap

        conn = ldap.initialize(self.__make_uri())
        # pyrefly: ignore [missing-attribute]
        conn.protocol_version = ldap.VERSION3
        # pyrefly: ignore [missing-attribute]
        conn.set_option(ldap.OPT_REFERRALS, 0)
        bound = False
        try:
            conn.simple_bind_s(username, password)
            bound = True
            user = get_info(conn)
            if user is None:
                return f"No information found in active directory for '{username}'"
            if additional_check is None:
                return user
            result = additional_check(conn, user)
            if result is True:
                return user
            return result
        # pyrefly: ignore [missing-attribute]
        except ldap.INVALID_CREDENTIALS:
            return "Wrong username or password"
        # pyrefly: ignore [missing-attribute]
        except ldap.LDAPError as e:
            return str(e).replace(self.config.server_path, "server")
        except Exception as e:
            logger.error("Unexpected LDAP error: %s", type(e).__name__)
            return "An unexpected error occurred during authentication"
        finally:
            if bound:
                try:
                    conn.unbind_s()
                # pyrefly: ignore [missing-attribute]
                except ldap.LDAPError:
                    pass

    def get_infos(
        self,
        conn: Connection,
        filters: str | dict[str, str],
    ) -> list[UserInfos]:
        """Get list of entries information from active directory.

        ## Arguments
        conn: Connection
            Active directory connection
        filters: str | Dict[str, str]
            * str: filter string
            * Dict[str, str]: Filter key value pairs

        ## Returns
        list[UserInfos]
            List of user information
        """
        import ldap

        results = conn.search_s(
            self.config.search_base,
            # pyrefly: ignore [missing-attribute]
            ldap.SCOPE_SUBTREE,
            self.__to_filter_str(filters),
            self.config.attributes,
        )
        return self.__to_infos(results)

    def get_info(
        self,
        conn: Connection,
        filters: str | dict[str, str],
    ) -> UserInfos | None:
        """Get entry information from active directory.

        ## Arguments
        conn: Connection
            Active directory connection
        filters: str | Dict[str, str]
            * str: filter string
            * Dict[str, str]: Filter key value pairs

        ## Returns
        UserInfos | None
            User information if available. otherwise, `None`
        """
        infos = self.get_infos(conn, filters)
        if len(infos) < 1:
            return None
        return infos[0]

    def get_info_by_sam_account_name(
        self,
        conn: Connection,
        name: str,
    ) -> UserInfos | None:
        """Get information from active directory.

        ## Arguments
        conn: Connection
            Active directory connection
        name: str
            Active directory SaAccountName

        ## Returns
        UserInfos | None
            User information if available. otherwise, `None`
        """
        return self.get_info(conn, {"sAMAccountName": name})

    def get_info_by_user_principal_name(
        self,
        conn: Connection,
        name: str,
    ) -> UserInfos | None:
        """Get information from active directory.

        ## Arguments
        conn: Connection
            Active directory connection
        name: str
            Active directory UserPrincipalName

        ## Returns
        UserInfos | None
            User information if available. otherwise, `None`
        """
        return self.get_info(conn, {"userPrincipalName": name})

    def get_info_by_distinguished_name(
        self,
        conn: Connection,
        name: str,
    ) -> UserInfos | None:
        """Get information from active directory.

        ## Arguments
        conn: Connection
            Active directory connection
        name: str
            Active directory DistinguishedName

        ## Returns
        UserInfos | None
            User information if available. otherwise, `None`
        """
        return self.get_info(conn, {"distinguishedName": name})

    @staticmethod
    def __to_value(attribute) -> UserInfoValue:
        """Convert the attribute value.

        ## Arguments
        attribute: any
            Active directory attribute

        ## Returns
            * List[str]: when there is more than one item in attribute value
            * str: when there is only single item in attribute value
            * None: when there is no item in attribute value
        """
        if type(attribute) is not list:
            msg = f"'{attribute}' is not `List` type"
            raise ActiveDirectoryAttributeError(msg)
        if not attribute:
            return None
        decoded = [
            v.decode("utf-8") if isinstance(v, bytes) else str(v) for v in attribute
        ]
        return decoded[0] if len(decoded) == 1 else decoded

    def __to_info(self, entry) -> UserInfos | None:
        if not isinstance(entry, tuple) or len(entry) != 2:
            return None
        _, attrs = entry
        if not isinstance(
            attrs, dict
        ):  # referral entries have a non-dict second element
            return None
        return {k: self.__to_value(v) for k, v in attrs.items()}

    def __to_infos(self, entries) -> list[UserInfos]:
        """Convert entries to user information list."""
        if type(entries) is not list:
            msg = "Expect 'entries' to be list type"
            raise TypeError(msg)
        infos = [self.__to_info(e) for e in entries]
        return [i for i in infos if i is not None]

    @staticmethod
    def __to_filter_str(filters: str | dict[str, str]) -> str:
        if type(filters) is str:
            return filters
        if type(filters) is dict:
            import ldap.filter

            parts = [
                f"({k}={ldap.filter.escape_filter_chars(v)})"
                for k, v in filters.items()
            ]
            return f"(&{''.join(parts)})"
        msg = "Expect 'filters' argument to be either str or Dict[str, str] type"
        raise TypeError(msg)
