"""Configuration and shared types for LDAP enrichment."""

from typing import Any, TypeVar

from streamlit.runtime.secrets import AttrDict as _AttrDict

UserInfoValue = list[str] | str | None
UserInfos = dict[str, Any]
T = TypeVar("T")
AttrDict = _AttrDict | dict


class Config:
    @classmethod
    def _get_attr_with_default(
        cls,
        dict_: AttrDict,
        key: str,
        type_: type | list[type],
        default_value_if_none: T,
    ) -> T:
        if key not in dict_:
            return default_value_if_none
        value = dict_[key]
        valid = (
            any(type(value) is item for item in type_)
            if isinstance(type_, list)
            else type(value) is type_
        )
        if not valid:
            raise ValueError(f"'{value}' is not a valid {key}")
        return value

    @classmethod
    def _get_attr(cls, dict_: AttrDict, key: str, type_: type):
        if key not in dict_:
            raise AttributeError(f"'{key}' is not found")
        value = dict_[key]
        if type(value) is not type_:
            raise AttributeError(f"'{key}' is not {type_.__name__}")
        return value


class LdapConfig(Config):
    """Configuration for Active Directory lookups."""

    def __init__(
        self,
        server_path: str,
        domain: str,
        search_base: str,
        attributes: list[str],
        use_ssl: bool = True,
    ) -> None:
        self.server_path = server_path
        self.domain = domain
        self.search_base = search_base
        self.attributes = attributes
        self.use_ssl = use_ssl

    @classmethod
    def from_dict(cls, dict_: AttrDict) -> "LdapConfig":
        return cls(
            cls._get_attr(dict_, "server_path", str),
            cls._get_attr(dict_, "domain", str),
            cls._get_attr(dict_, "search_base", str),
            cls._get_attr(dict_, "attributes", list),
            cls._get_attr_with_default(dict_, "use_ssl", bool, True),
        )

    @classmethod
    def get_instance(cls, value: "LdapConfig | AttrDict") -> "LdapConfig":
        if isinstance(value, cls):
            return value
        if type(value) is dict or type(value) is _AttrDict:
            return cls.from_dict(value)
        raise AttributeError("Unexpected 'value' type")
