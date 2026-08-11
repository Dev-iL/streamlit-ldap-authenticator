"""Exceptions raised by LDAP data conversion."""


class DeprecationError(Exception):
    """Exception used for deprecated API paths."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class ActiveDirectoryAttributeError(Exception):
    """Raised when an Active Directory attribute has an unexpected shape."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)
