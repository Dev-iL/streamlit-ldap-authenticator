# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — 2026-08-10

### Changed

- **Breaking:** authentication now uses Streamlit's native Okta OIDC flow;
  custom login forms, JWT cookies, encryption, session-state authentication,
  and logout fragments were removed.
- Streamlit now requires the `auth` extra at `>= 1.42`.
- Optional LDAP enrichment tries anonymous bind first and can fall back to
  `LDAP_SERVICE_ACCOUNT_USERNAME` and `LDAP_SERVICE_ACCOUNT_PASSWORD`.

### Removed

- `pyjwt`, `streamlit-cookies-controller`, and `streamlit-rsa-auth-ui`.
- `CookieConfig`, `EncryptorConfig`, `LoginConfig`, `LogoutConfig`, and
  `SessionStateConfig` from the public API.

## [0.3.0] — 2026-04-12

### Added

- `LoginConfig.use_dialog: bool = False` — opt-in modal dialog mode for the login
  form via `@st.dialog`. When `True`, the sign-in form is rendered inside a Streamlit
  dialog; existing callers that omit the parameter are unaffected.
- Package-level `logging.NullHandler` so library consumers can configure log output
  without receiving unexpected console noise.
- `pytest` and `pytest-mock` added as dev dependencies; full test scaffold covering
  all public methods and changed behaviours.

### Changed

- **JWT cookie format** — cookies now use the standard PyJWT `exp` claim (POSIX
  timestamp) instead of the custom `exp_date` float field. **All existing browser
  cookies are invalidated on upgrade**; users will be prompted to log in once.
- **Exception handling** — `__token_decode` now catches
  `(jwt.InvalidTokenError, CookieError)` silently (expected for anonymous visitors)
  with a fallback `logger.warning` for unexpected errors. `LdapAuthenticate.login()`
  now catches `LDAPException` as the primary type (preserving the server-path
  sanitisation) with a `logger.error` fallback for unexpected errors.
- **Logging** — all `print()` debug statements replaced with structured `logger`
  calls under the `streamlit_ldap_authenticator` logger name. Callers can attach
  handlers to this logger to capture authentication events.
- **Fragment isolation** — `login()` and `create_logout_form()` now use
  `@st.fragment` inner functions so form interactions do not trigger full-page
  reruns unnecessarily.
- **Post-logout rerun** — `create_logout_form` uses `st.rerun(scope='app')` for a
  full-page reload after logout (was a fragment-scoped rerun).
- **Cookie read path** — `__get_cookie()` uses `st.context.cookies` (Streamlit
  1.37+ native API) instead of `cookie_manager.get()`. The write and delete paths
  are unchanged.
- **Import fixes** — `StreamlitDuplicateElementKey` is now imported from
  `streamlit.errors` (public API, stable since 1.35.0) instead of the private
  `streamlit.elements.lib.utils` path.
- **Re-export form** — all symbols in `__init__.py` use the explicit `X as X`
  re-export form required by ruff F401 / PEP 484 for typed consumers.
- **Streamlit lower bound** — minimum supported Streamlit raised to `>= 1.37` to
  cover `streamlit.errors`, `st.context.cookies`, `@st.fragment`, and `@st.dialog`.
- **Installation** — package is now installed directly from GitHub (not PyPI):
  `pip install git+https://github.com/Dev-iL/streamlit-ldap-authenticator`
- Version bumped from 0.2.6.1 to 0.3.0.

### Fixed

- Removed module-level `ss = st.session_state` alias that caused stale-reference
  bugs when session state was replaced between reruns.
- `__init__.py` re-exports corrected so static analysis tools (mypy, pyright) can
  resolve all exported symbols without false-positive "not exported" errors.

## [0.2.6]

- Fix `expiry_days` and `delay_sec` is not parsed correctly from secrets.toml in
  `CookieConfig`.

## [0.2.5]

- Add optional `delay_sec` in cookie config for set and delete cookie.

## [0.2.4]

- Fix `no attribute in signinevent` when cookie option is disabled.

## [0.2.3]

- Enhance security by clearing password from `Connection` object after bind.

## [0.2.2]

- Fix misleading error message of "Wrong username or password" when there is an
  exception during LDAP connection.

## [0.2.1]

- Fix cannot log in if encryptor module is provided.
- Fix cookie auto-renewal not working when no `additionalCheck` parameter is
  provided.

## [0.2.0]

- Add callback argument in `login` and `logout`.

## [0.1.1]

- Add `pyjwt` as a requirement.

## [0.1.0]

- Add encryption module.
- Change user interface.
- More customizable form config.
- Remove `LoginFormConfig` and `LogoutFormConfig`.

## [0.0.6]

- Fix page application not working when auto-renewal for cookie config is
  configured.

## [0.0.5]

- Default `use_ssl` for LDAP connection changed to `True`.
- Added `use_ssl` configuration in `LdapConfig`.

## [0.0.4]

- Initial release.
