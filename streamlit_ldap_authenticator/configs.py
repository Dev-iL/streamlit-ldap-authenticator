# Author    : Nathan Chen
# Date      : 27-Apr-2024


from typing import Any, Optional, TypeVar, Union

from streamlit.runtime.secrets import AttrDict as _AttrDict
from streamlit_rsa_auth_ui import (
    FormType,
    HorizontalAlign,
    Object,
    SigninFormConfig,
    SignoutFormConfig,
)
from streamlit_rsa_auth_ui.configs import (
    ButtonConfig,
    CheckboxConfig,
    IconConfig,
    TextInputConfig,
    TitleConfig,
)


class LoginConfig(SigninFormConfig):
    busy_message: str
    error_icon: str | None

    def __init__(
        self,
        busy_message: str = "Logging in...",
        error_icon: str | None = None,
        form_type: FormType | None = None,
        label_span: int | None = None,
        wrapper_span: int | None = None,
        max_width: int | None = None,
        align: HorizontalAlign | None = None,
        title: TitleConfig | str | Object | None = None,
        cancel: IconConfig | Object | None = None,
        submit: ButtonConfig | str | Object | None = None,
        username: TextInputConfig | str | Object | None = None,
        password: TextInputConfig | str | Object | None = None,
        remember: CheckboxConfig | str | Object | None = None,
        forgot: ButtonConfig | str | Object | None = None,
        args: Object | None = None,
    ) -> None:
        super().__init__(
            form_type,
            label_span,
            wrapper_span,
            max_width,
            align,
            title,
            cancel,
            submit,
            username,
            password,
            remember,
            forgot,
            args,
        )
        self.busy_message = busy_message
        self.error_icon = error_icon

    def toDict(self) -> Object:
        config = super().toDict()
        config["busy_message"] = self.busy_message
        if self.error_icon is not None:
            config["error_icon"] = self.error_icon
        return config


class LogoutConfig(SignoutFormConfig):
    busy_message: str
    sleep_sec: float

    def __init__(
        self,
        busy_message: str = "Logging out...",
        sleep_sec: float = 1.0,
        form_type: FormType | None = None,
        label_span: int | None = None,
        wrapper_span: int | None = None,
        max_width: int | None = None,
        align: HorizontalAlign | None = None,
        title: str | TitleConfig | Object | None = None,
        cancel: IconConfig | Object | None = None,
        submit: str | ButtonConfig | Object | None = None,
        args: Object | None = None,
    ) -> None:
        super().__init__(
            form_type,
            label_span,
            wrapper_span,
            max_width,
            align,
            title,
            cancel,
            submit,
            args,
        )
        self.busy_message = busy_message
        self.sleep_sec = sleep_sec

    def toDict(self) -> Object:
        config = super().toDict()
        config["busy_message"] = self.busy_message
        config["sleep_sec"] = self.sleep_sec
        return config


# Application Config
UserInfoValue = Union[list[str], str, None]
UserInfos = dict[str, Any]
T = TypeVar("T")
AttrDict = Union[_AttrDict, dict]


class Config:
    @classmethod
    def _get_attr_with_default(
        cls,
        dict_: AttrDict,
        key: str,
        type_: type | list[type],
        default_value_if_none: T,
    ):  # type: ignore
        if key in dict_:
            value = dict_[key]
            if type(type_) is list:
                if not any(type(value) is t for t in type_):
                    msg = f"'{value}' is not a valid {key}"
                    raise ValueError(msg)
            elif type(value) is not type_:
                msg = f"'{value}' is not a valid {key}"
                raise ValueError(msg)
        else:
            value = default_value_if_none
        return value

    @classmethod
    def _get_attr(cls, dict_: AttrDict, key: str, _type: type):
        if key not in dict_:
            msg = f"'{key}' is not found"
            raise AttributeError(msg)

        value = dict_[key]
        if type(value) is not _type:
            msg = f"'{key}' is not {_type.__name__}"
            raise AttributeError(msg)
        return value


class LdapConfig(Config):
    """Config for authentication using active directory.

    ## Properties
    server_path: str
        ldap server path. E.g. 'ldap://ldap.example.com:389'
    domain: str
        Your organization domain. E.g. 'Example'
    search_base: str
        Active Directory base search. E.g. 'dc=example,dc=com'
    attributes: List[str]
        Attribute available in your organization active directory. You can reference in [ADExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer)
    use_ssl: bool
        Determine whether to use basic SSL basic authentication. Default value is `True`
    """

    server_path: str
    domain: str
    search_base: str
    attributes: list[str]
    use_ssl: bool

    def __init__(
        self,
        server_path: str,
        domain: str,
        search_base: str,
        attributes: list[str],
        use_ssl: bool = True,
    ) -> None:
        """Create an instance of `LdapConfig` object.

        ## Arguments
        server_path: str
            ldap server path. E.g. 'ldap://ldap.example.com:389'
        domain: str
            Your organization domain. E.g. 'Example'
        search_base: str
            Active Directory base search. E.g. 'dc=example,dc=com'
        attributes: List[str]
            Attribute available in your organization active directory. You can reference in [ADExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer)
        """
        self.server_path = server_path
        self.domain = domain
        self.search_base = search_base
        self.attributes = attributes
        self.use_ssl = use_ssl

    @classmethod
    def from_dict(cls, dict_: AttrDict) -> "LdapConfig":
        server_path = cls._get_attr(dict_, "server_path", str)
        domain = cls._get_attr(dict_, "domain", str)
        search_base = cls._get_attr(dict_, "search_base", str)
        attributes = cls._get_attr(dict_, "attributes", list)
        use_ssl = cls._get_attr_with_default(dict_, "use_ssl", bool, True)
        return LdapConfig(server_path, domain, search_base, attributes, use_ssl)

    @classmethod
    def get_instance(cls, value: Union["LdapConfig", AttrDict]) -> "LdapConfig":
        if type(value) is LdapConfig:
            return value
        if type(value) is dict or type(value) is _AttrDict:
            return cls.from_dict(value)
        msg = "Unexpected 'value' type"
        raise AttributeError(msg)


class SessionStateConfig(Config):
    """Config for streamlit session state key names.

    ## Properties
    user: str
        session state key name to store the user information.

    remember_me: str
        session state key name to keep track remember_me checkbox value.
    """

    __default_user__ = "login_user"
    __default_remember_me__ = "login_remember_me"
    __default_auth_result__ = "login_result"

    user: str
    remember_me: str
    auth_result: str

    def __init__(
        self,
        user: str = __default_user__,
        remember_me: str = __default_remember_me__,
        auth_result: str = __default_auth_result__,
    ) -> None:
        self.user = user
        self.remember_me = remember_me
        self.auth_result = auth_result

    @classmethod
    def from_dict(cls, dict_: AttrDict) -> "SessionStateConfig":
        user = cls._get_attr_with_default(dict_, "user", str, cls.__default_user__)
        remember_me = cls._get_attr_with_default(
            dict_,
            "remember_me",
            str,
            cls.__default_remember_me__,
        )
        auth_result = cls._get_attr_with_default(
            dict_,
            "auth_result",
            str,
            cls.__default_auth_result__,
        )

        return SessionStateConfig(user, remember_me, auth_result)

    @classmethod
    def get_instance(
        cls,
        value: Union["SessionStateConfig", AttrDict, None],
    ) -> "SessionStateConfig":
        if type(value) is SessionStateConfig:
            return value
        if type(value) is dict or type(value) is _AttrDict:
            return cls.from_dict(value)
        return SessionStateConfig()


class CookieConfig(Config):
    """Secrets to encode information to cookie in the client's browser.

    ## Properties
    key: str
        key password to encode and decode information from cookie in the client's browser
    name: str
        name of the cookie to save in the client's browser
    expiry_days: float
        The number of days before the reauthentication cookie automatically expires on the client's browser.
    """

    __default_name__: str = "login_cookie"
    __default_expiry_days__: float = 1.0
    __default_auto_renewal__: bool = True
    __default_delay_sec__: float = 0.1

    key: str
    name: str
    expiry_days: float
    auto_renewal: bool
    delay_sec: float

    def __init__(
        self,
        key: str,
        name: str = __default_name__,
        expiry_days: float = __default_expiry_days__,
        auto_renewal: bool = __default_auto_renewal__,
        delay_sec: float = __default_delay_sec__,
    ) -> None:
        """Create an instance of `CookieConfig` object."""
        self.key = key
        self.name = name
        self.expiry_days = expiry_days
        self.auto_renewal = auto_renewal
        self.delay_sec = delay_sec

    @classmethod
    def from_dict(cls, dict_: AttrDict) -> "CookieConfig":
        key = cls._get_attr(dict_, "key", str)
        name = cls._get_attr_with_default(dict_, "name", str, cls.__default_name__)
        expiry_days = float(
            cls._get_attr_with_default(
                dict_,
                "expiry_days",
                [float, int],
                cls.__default_expiry_days__,
            ),
        )
        auto_renewal = cls._get_attr_with_default(
            dict_,
            "auto_renewal",
            bool,
            cls.__default_auto_renewal__,
        )
        delay_sec = float(
            cls._get_attr_with_default(
                dict_,
                "delay_sec",
                [float, int],
                cls.__default_delay_sec__,
            ),
        )
        return CookieConfig(key, name, expiry_days, auto_renewal, delay_sec)

    @classmethod
    def get_instance(
        cls,
        value: Union["CookieConfig", AttrDict, None],
    ) -> Optional["CookieConfig"]:
        if type(value) is CookieConfig:
            return value
        if type(value) is dict or type(value) is _AttrDict:
            return cls.from_dict(value)
        return None


class EncryptorConfig(Config):
    """Encryption key to encode and decode information between client and server.

    ## Properties
    folderPath: str
        Location of the folder where both private key and public key is located
    keyName: str
        The name of the key
    """

    folder_path: str
    key_name: str

    def __init__(self, folder_path: str, key_name: str) -> None:
        self.folder_path = folder_path
        self.key_name = key_name

    @classmethod
    def from_dict(cls, dict_: AttrDict) -> "EncryptorConfig":
        folder_path = cls._get_attr(dict_, "folder_path", str)
        key_name = cls._get_attr(dict_, "key_name", str)
        return EncryptorConfig(folder_path, key_name)

    @classmethod
    def get_instance(
        cls,
        value: Union["EncryptorConfig", AttrDict, None],
    ) -> Optional["EncryptorConfig"]:
        if type(value) is EncryptorConfig:
            return value
        if type(value) is dict or type(value) is _AttrDict:
            return cls.from_dict(value)
        return None
