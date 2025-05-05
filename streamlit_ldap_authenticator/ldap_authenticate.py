# Author    : Nathan Chen
# Date      : 04-Apr-2024


from collections.abc import Callable
from typing import Literal

from ldap3 import Connection, Server
from ldap3.abstract.entry import Entry

from .configs import AttrDict, LdapConfig, UserInfos, UserInfoValue
from .exceptions import ActiveDirectoryAttributeError


class LdapAuthenticate:
    """Authentication using active directory

    ## Properties
    config: LdapConfig
        Config for authentication using active directory
    """

    config: LdapConfig

    def __init__(self, config: LdapConfig | AttrDict) -> None:
        """Create an instance of `LdapAuthenticate` object

        ## Arguments
        config: LdapConfig | dict | streamlit.runtime.secrets.AttrDict
            Config for authentication using active directory
        """
        self.config = LdapConfig.get_instance(config)

    def login(
        self,
        username: str,
        password: str,
        get_info: Callable[[Connection], UserInfos | None],
        additional_check: Callable[[Connection | None, UserInfos], Literal[True] | str] | None = None,
    ) -> UserInfos | str | Literal[True]:
        """Login to active directory

        ## Arguments
        userName: str
            username to log in to active directory
        password: str
            password to log in to active directory
        getInfo: (connection: Connection) -> UserInfos | None
            Function to retrieve user information from active directory
        additionalCheck: ((connection: Connection | None, user: UserInfos) -> (True | str)) | None
            * Function to perform additional authentication check.
            * Function must return `True` if additional authentication is successful, otherwise must return error message
            * Passing `None` will ignore additional authentication check.

        ## Returns:
        UserInfos | str
            User information if authentication is successful.
            otherwise, authentication fail message
        """
        server = Server(
            self.config.server_path,
            use_ssl=self.config.use_ssl,
            get_info="ALL",
        )
        conn = Connection(
            server,
            username,
            password,
            auto_bind=False,
            auto_referrals=False,
            raise_exceptions=False,
        )
        try:
            conn.bind()
            conn.password = None
            if conn.result["result"] != 0:
                return "Wrong username or password"
            user = get_info(conn)
            if user is None:
                return f"No information found in active directory for '{username}'"
            if additional_check is None:
                return user

            result = additional_check(conn, user)
            if result:
                return user
            return result
        except Exception as e:
            return str(e).replace(self.config.server_path, "server")
        finally:
            if conn.bound:
                conn.unbind()

    def get_infos(
        self,
        conn: Connection,
        filters: str | dict[str, str],
    ) -> list[UserInfos]:
        """Get list of entries information from active directory

        ## Arguments
        conn: Connection
            Active directory connection
        filters: str | Dict[str, str]
            * sr: filter string
            * Dict[str, str]: Filter key value pairs

        ## Returns
        UserInfos | None
            User information if available. otherwise, `None`
        """
        conn.search(
            search_base=self.config.search_base,
            search_filter=self.__to_filter_str(filters),
            search_scope="SUBTREE",
            attributes=self.config.attributes,
        )
        return self.__to_infos(conn.entries)

    def get_info(
        self,
        conn: Connection,
        filters: str | dict[str, str],
    ) -> UserInfos | None:
        """Get entry information from active directory

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
        """Get information from active directory

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
        """Get information from active directory

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
        """Get information from active directory

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
        """Convert the attribute value

        ## Arguments
        attribute: any
            Active directory attribute

        ## Returns
            * List[str]: when there is more than one item in attribute value
            * str: when there is only single item in attribute value
            * None: when there is no item in attribute value
        """
        if type(attribute) is not list:
            raise ActiveDirectoryAttributeError(f"'{attribute}' is not `List` type")
        length = len(attribute)
        if length < 1:
            return None
        if length == 1:
            return str(attribute[0])
        return attribute

    def __to_info(self, entry) -> UserInfos | None:
        if type(entry) is not Entry:
            return None
        info = {
            str(k): self.__to_value(v) for k, v in entry.entry_attributes_as_dict.items()
        }
        return info

    def __to_infos(self, entries) -> list[UserInfos]:
        """Convert entries to user information list"""
        if type(entries) is not list:
            raise TypeError("Expect 'entries' to be list type")
        infos = [self.__to_info(e) for e in entries]
        infos = [i for i in infos if i is not None]
        return infos

    @staticmethod
    def __to_filter_str(filters: str | dict[str, str]) -> str:
        if type(filters) is str:
            return filters
        if type(filters) is dict:
            search_filters = [f"({k}={v})" for k, v in filters.items()]
            return f"(&{''.join(search_filters)})"
        raise TypeError(
            "Expect 'filters' argument to be either str or Dict[str, str] type",
        )
