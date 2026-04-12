# Author    : Nathan Chen
# Date      : 27-Apr-2024


import logging
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal

import jwt
import streamlit as st
from streamlit.errors import StreamlitDuplicateElementKey
from streamlit_cookies_controller import CookieController
from streamlit_rsa_auth_ui import (
    Encryptor,
    Object,
    SigninEvent,
    SignoutEvent,
    authUI,
    getEvent,
)

from .configs import (
    AttrDict,
    CookieConfig,
    EncryptorConfig,
    LdapConfig,
    LoginConfig,
    LogoutConfig,
    SessionStateConfig,
    UserInfos,
)
from .exceptions import CookieError
from .ldap_authenticate import Connection, LdapAuthenticate

logger = logging.getLogger("streamlit_ldap_authenticator")


RegexDomain = re.compile(r"^(.*)\\(.*)$")
RegexEmail = re.compile(r"^[\w\-.]+@([\w\-]+\.)+[\w\-]{2,4}$")


class Authenticate:
    """Authentication using active directory.
        Reauthentication method available
        * streamlit session_state: Valid for the current session. if the page is refreshed, session_state will reset thus loose stored data for reauthentication.
        * cookie in the client's browser: Valid until the cookie in the browser is expired.

    ## Properties
    session_configs: SessionStateConfig
        Streamlit session state key names.

    cookie_configs: CookieConfig | None
        Optional configuration to encode user information to cookie in the client's browser.
        Reauthorization using cookie in the client's browser feature will be disabled when `None`.
    """

    session_configs: SessionStateConfig
    cookie_configs: CookieConfig | None

    def __init__(
        self,
        ldap_configs: LdapConfig | AttrDict,
        session_configs: SessionStateConfig | AttrDict | None = None,
        cookie_configs: CookieConfig | AttrDict | None = None,
        encryptor_configs: EncryptorConfig | AttrDict | None = None,
    ) -> None:
        """Create a new instance of `Authenticate`.

        ## Arguments
        ldap_config: LdapConfig | dict | streamlit.runtime.secrets.AttrDict
            Config for Ldap authentication

        session_configs: SessionStateConfig | dict | streamlit.runtime.secrets.AttrDict | None
            Optional streamlit session state key names.

        cookie_configs: CookieConfig | dict | streamlit.runtime.secrets.AttrDict | None
            Optional configuration to encode user information to cookie in the client's browser.
            Reauthorization using cookie in the client's browser feature will be disabled when `None`.
        """
        self.session_configs = SessionStateConfig.get_instance(session_configs)
        self.cookie_configs = CookieConfig.get_instance(cookie_configs)
        self.ldap_auth = LdapAuthenticate(ldap_configs)

        if cookie_configs is not None:
            self.cookie_manager = CookieController()

        encryptor_configs = EncryptorConfig.get_instance(encryptor_configs)
        self.encryptor = (
            Encryptor.load(encryptor_configs.folder_path, encryptor_configs.key_name)
            if encryptor_configs is not None
            else None
        )
        public_key = None if self.encryptor is None else self.encryptor.publicKeyPem
        self.ui = authUI(self.session_configs.auth_result, public_key)

    # streamlit session_state variables
    def __get_user(self) -> UserInfos | None:
        """Get the user information from streamlit session_state
            if reauthorization using streamlit session_state is enabled.

        ## Returns
        UserInfos | None
            User information if it is available. otherwise, `None`
        """
        if self.session_configs.user not in st.session_state:
            return None
        user = st.session_state[self.session_configs.user]
        return user if type(user) is dict else None

    def __set_user(self, user: UserInfos | None) -> None:
        """Assign the user information to session_state of streamlit
            if reauthorization using streamlit session_state is enabled.

        ## Arguments
        user : UserInfos | None
            User information to assign to streamlit session_state
        """
        if self.session_configs.user is None:
            return
        st.session_state[self.session_configs.user] = user

    def __set_remember_me(self, remember_me: bool) -> None:
        st.session_state[self.session_configs.remember_me] = remember_me

    def __get_remember_me(self) -> bool:
        if self.session_configs.remember_me in st.session_state:
            remember_me = st.session_state[self.session_configs.remember_me]
            if type(remember_me) is bool:
                return remember_me

        self.__set_remember_me(True)
        return True

    # For reauthentication using cookie from client's browser
    @staticmethod
    def __token_encode(cookie_configs: CookieConfig, user: UserInfos):
        """Encodes the contents for the reauthentication cookie.

        ## Arguments
        user: UserInfos
            User Information

        ## Returns
        str
            The JWT cookie for passwordless reauthentication.
        """
        exp_date = datetime.now(tz=UTC) + timedelta(days=cookie_configs.expiry_days)
        return jwt.encode(
            {"user": user, "exp_date": exp_date.timestamp()},
            cookie_configs.key,
            algorithm="HS256",
        )

    @staticmethod
    def __token_decode(cookie_configs: CookieConfig, token) -> UserInfos | None:
        """Decodes the contents of the reauthentication cookie.

        ## Arguments:
        token: any
            Encoded cookie token

        ## Returns:
        UserInfos | False
            User information if cookie is correct.
            otherwise, return `None`
        """
        try:
            if token is None:
                msg = "No cookie found"
                raise CookieError(msg)
            if type(token) is not str:
                msg = "Cookie value is expected to be `str`"
                raise CookieError(msg)

            value = jwt.decode(token, cookie_configs.key, algorithms=["HS256"])
            if type(value) is not dict:
                msg = "Decoded cookie is not dict"
                raise CookieError(msg)

            if "exp_date" not in value:
                msg = "exp_date is not found"
                raise CookieError(msg)
            exp_date = value["exp_date"]
            if type(exp_date) is not float:
                msg = "exp_date is not float"
                raise CookieError(msg)
            if exp_date < datetime.now(tz=UTC).timestamp():
                msg = "Cookie expired"
                raise CookieError(msg)

            if "user" not in value:
                msg = "user is not found"
                raise CookieError(msg)
            user = value["user"]
            if type(user) is not dict:
                msg = "user is not dict"
                raise CookieError(msg)

            return user
        except (jwt.InvalidTokenError, CookieError):
            return None
        except Exception as e:
            logger.warning("Unexpected decode error: %s", type(e).__name__)
            return None

    def __get_cookie(self) -> UserInfos | None:
        """Get the decoded user information from cookie in the client's browser.
            if reauthorization using cookie in the client's browser is enabled.

        ## Returns
        UserInfos | None
            user information if it is available and valid, otherwise `None`
        """
        if self.cookie_configs is None:
            return None

        token = self.cookie_manager.get(self.cookie_configs.name)
        return self.__token_decode(self.cookie_configs, token)

    def __set_cookie(self, user: UserInfos | None) -> None:
        """Assign the encoded user information to cookie in the client's browser
            if reauthorization using cookie in the client's browser is enabled.

        ## Arguments
        user: UserInfos
            User information to assign to cookie in the client's browser
        """
        if user is None:
            return
        if self.cookie_configs is None:
            return

        remember_me = self.__get_remember_me()
        if not remember_me:
            return

        token = self.__token_encode(self.cookie_configs, user)
        exp_date = datetime.now() + timedelta(days=self.cookie_configs.expiry_days)
        self.cookie_manager.set(self.cookie_configs.name, token, expires=exp_date)
        time.sleep(self.cookie_configs.delay_sec)

    def __delete_cookie(self) -> None:
        """Delete the cookie in the client's browser
        if reauthorization using cookie in the client's browser is enabled.
        """
        if self.cookie_configs is None:
            return

        cookies = self.cookie_manager.getAll()
        if self.cookie_configs.name in cookies:
            self.cookie_manager.remove(self.cookie_configs.name)
            time.sleep(self.cookie_configs.delay_sec)

    def __get_login_config(self, config: Object | LoginConfig | None = None):
        config = (
            config
            if type(config) is dict
            else config.toDict()
            if isinstance(config, LoginConfig)
            else {}
        )

        if self.cookie_configs is not None and "remember" not in config:
            config["remember"] = {}

        busy_message = config.get("busy_message")
        config.pop("busy_message", "")
        if type(busy_message) is not str:
            busy_message = "Logging in..."

        error_icon = config.get("error_icon", None)
        config.pop("error_icon", "")
        if type(error_icon) is not str:
            error_icon = None

        return config, busy_message, error_icon

    def __create_login_form(
        self,
        additional_check: Callable[[Connection | None, UserInfos], Literal[True] | str]
        | None = None,
        get_login_user_name: Callable[[str], str] | None = None,
        get_info: Callable[[Connection, str], UserInfos | None] | None = None,
        config: Object | LoginConfig | None = None,
        callback: Callable[[UserInfos | str], str | None] | None = None,
    ):
        get_info = get_info if get_info is not None else self.get_info
        get_login_user_name = (
            get_login_user_name
            if get_login_user_name is not None
            else self.get_login_user_name
        )
        default = (
            {"remember": self.__get_remember_me()}
            if self.cookie_configs is not None
            else None
        )
        (config, busy_message, error_icon) = self.__get_login_config(config)

        # Create form
        result = self.ui.signinForm(default, config)
        if result is None:
            return None

        if self.encryptor is not None and type(result) is str:
            result = self.encryptor.decrypt(result)
        event = getEvent(result)
        if type(event) is not SigninEvent:
            return None

        self.__set_remember_me(event.remember)

        with st.spinner(busy_message):
            username = event.username
            login_name = get_login_user_name(username)
            result = self.ldap_auth.login(
                login_name,
                event.password,
                lambda conn: get_info(conn, username),
                additional_check,
            )

            if callback is not None:
                callback_result = callback(result)
                if type(callback_result) is str:
                    result = callback_result

            if type(result) is str:  # If it is error message
                st.error(result, icon=error_icon)
                return None
            if type(result) is dict:
                del st.session_state[self.session_configs.auth_result]
                return result
            st.error(f"Unexpected Return: {result}", icon=error_icon)
            return None

    def __check_reauthentication(
        self,
        user: UserInfos | None,
        additional_check: Callable[[Connection | None, UserInfos], Literal[True] | str]
        | None = None,
    ) -> bool:
        """Check user information during reauthorization.

        ## Arguments
        user : Person | None
            Optional user information to check
        connection: Connection | None
            Optional active directory connection
        additionalCheck: ((connection: Connection | None, user: UserInfos) -> (True | str)) | None
            * Function to perform additional authentication check.
            * Function must return `True` if additional authentication is successful, otherwise must return error message
            * Passing `None` will ignore additional authentication check.

        ## Returns
        bool
            * `True` when user is authorized to use.
            * `None` when user is not UserInfos.
            * `str` error message when authentication fail.
        """
        if type(user) is not dict:
            return False
        if additional_check is None:
            if self.cookie_configs is not None and self.cookie_configs.auto_renewal:
                self.__set_cookie(user)
            return True  # No additional check is required
        result = additional_check(None, user)
        if not result:
            return False

        if self.cookie_configs is not None and self.cookie_configs.auto_renewal:
            self.__set_cookie(user)
        return True

    def login(
        self,
        additional_check: Callable[[Connection | None, UserInfos], Literal[True] | str]
        | None = None,
        get_login_user_name: Callable[[str], str] | None = None,
        get_info: Callable[[Connection, str], UserInfos | None] | None = None,
        config: Object | LoginConfig | None = None,
        callback: Callable[[UserInfos | str], str | None] | None = None,
    ) -> UserInfos | None:
        """Authentication using ldap. Reauthorize if it is valid and create login form if authorization fail.

        ## Arguments
        additionalCheck: ((connection: Connection | None, user: UserInfos) -> (True | str)) | None
            * Function to perform additional authentication check.
            * Function must return `True` if additional authentication is successful, otherwise must return error message
            * Passing `None` will ignore additional authentication check.

        getLoginUserName: ((username: str) -> str) | None
            Optional function to decode the username entered by user to active directory login username

        getInfo: ((connection: Connection, username: str) -> UserInfos | None) | None
            Optional function to retrieve user information from active directory

        config: Object | LoginConfig | None
            Optional config for login form

        callback: ((user: UserInfos | str) -> str | None) | None
            Optional callback function.
            - Return error message as string will halt login process
            - Return `None` will continue login process.


        ## Returns
        UserInfos | None
            User information if authentication is successful.
            otherwise, `None`
        """
        # check user authentication if it is found in streamlit session_state
        user = self.__get_user()
        if self.__check_reauthentication(user, additional_check):
            return user

        # check user authentication if it is found cookie in client's browser
        self.__allow_cookie_refresh()
        user = self.__get_cookie()
        if self.__check_reauthentication(user, additional_check):
            self.__set_user(user)
            return user

        # ask user to log in
        user = self.__create_login_form(
            additional_check,
            get_login_user_name,
            get_info,
            config,
            callback,
        )
        if type(user) is not dict:
            return None
        self.__set_user(user)
        self.__allow_cookie_refresh()
        self.__set_cookie(user)
        try:
            return user
        finally:
            st.rerun()

    def __allow_cookie_refresh(self):
        """Allow cookie refresh to avoid duplicate element key error"""
        try:
            self.cookie_manager.refresh()
        except StreamlitDuplicateElementKey:
            time.sleep(0.1)

    @staticmethod
    def __get_logout_config(config: Object | LogoutConfig | None = None):
        config = (
            config
            if type(config) is dict
            else config.toDict()
            if isinstance(config, LogoutConfig)
            else {}
        )

        # For backward compatibility
        if "title" not in config and "message" in config:
            message = config["message"]
            config.pop("message", "")
            if type(message) is str:
                config["title"] = {"text": message}

        busy_message = config.get("busy_message")
        config.pop("busy_message", "")
        if type(busy_message) is not str:
            busy_message = "Logging out..."

        sleep_sec = config.get("sleep_sec")
        config.pop("sleep_sec", "")
        if type(sleep_sec) is not float:
            sleep_sec = 1.0

        return config, busy_message, sleep_sec

    def create_logout_form(
        self,
        config: Object | LogoutConfig | None = None,
        callback: Callable[[SignoutEvent], Literal["cancel"] | None] | None = None,
    ) -> None:
        """Create logout form
        config: Object | LogoutConfig | None
            Optional config for logout form.

        callback: ((user: UserInfos | str) -> str | None) | None
            Optional callback function.
            - Return `'cancel'` will stop the logout process.
            - Return `None` will continue logout process.
        """
        (config, busy_message, sleep_sec) = self.__get_logout_config(config)

        # Create form
        result = self.ui.signoutForm(configs=config)
        if result is None:
            return

        if self.encryptor is not None and type(result) is str:
            result = self.encryptor.decrypt(result)
        event = getEvent(result)
        if type(event) is not SignoutEvent:
            return

        with st.spinner(busy_message):
            if callback is not None:
                result = callback(event)
                if result == "cancel":
                    return

            self.__set_user(None)
            self.__delete_cookie()
            # give sometime for the browser cookie to get deleted
            time.sleep(sleep_sec)
            st.rerun()

    # Default decoding of login username and get user information from active directory
    def get_info(self, conn: Connection, username: str) -> UserInfos | None:
        match = RegexEmail.match(username)
        if match is not None:
            return self.ldap_auth.get_info_by_user_principal_name(conn, username)

        match = RegexDomain.match(username)
        groups = match.groups() if match is not None else None
        name = username if groups is None else groups[1]
        return self.ldap_auth.get_info_by_sam_account_name(conn, name)

    def get_login_user_name(self, username: str) -> str:
        match = RegexEmail.match(username)
        if match is not None:
            return username

        match = RegexDomain.match(username)
        groups = match.groups() if match is not None else None
        domain = self.ldap_auth.config.domain if groups is None else groups[0]
        name = username if groups is None else groups[1]
        return f"{domain}\\{name}"
