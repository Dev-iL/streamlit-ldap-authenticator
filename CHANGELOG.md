# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
