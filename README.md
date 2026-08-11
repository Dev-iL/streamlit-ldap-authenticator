# streamlit-ldap-authenticator

Streamlit-native Okta OIDC authentication with optional Active Directory enrichment and authorization.

## Installation

```bash
pip install streamlit-ldap-authenticator
```

The package requires `streamlit[auth] >= 1.42` and keeps `python-ldap` for
optional directory lookups.

## Configure Okta

Put the OIDC settings in `.streamlit/secrets.toml`:

```toml
[auth]
redirect_uri = "https://app.example.com/oauth2callback"
cookie_secret = "replace-with-a-long-random-secret"
client_id = "okta-client-id"
client_secret = "okta-client-secret"
server_metadata_url = "https://your-okta-domain/oauth2/default/.well-known/openid-configuration"
```

Register the redirect URI with Okta. Streamlit owns the OIDC redirect, browser
cookie, token handling, and provider logout.

## Use the native flow

```python
import streamlit as st

from streamlit_ldap_authenticator import Authenticate

auth = Authenticate()
user = auth.login()

if user is not None:
    auth.create_logout_form()
    st.write(f"Welcome, {user.get('name', user.get('email', 'user'))}")
```

`login()` returns an allowlisted OIDC claim dictionary after the user is
authenticated. It does not write authentication data to `st.session_state`.

## Optional LDAP enrichment

Pass an LDAP configuration only when the application needs AD attributes or an
AD-based authorization check:

```toml
[ldap]
server_path = "ldaps://ad.example.com"
domain = "EXAMPLE"
search_base = "dc=example,dc=com"
attributes = ["cn", "mail", "department"]
use_ssl = true
```

```python
import streamlit as st

from streamlit_ldap_authenticator import Authenticate

auth = Authenticate(st.secrets["ldap"])

def allow_user(connection, user):
    return user.get("department") == "Engineering"

user = auth.login(additional_check=allow_user)
```

LDAP lookup tries an anonymous bind first. If that cannot resolve the OIDC
identity, it may retry with a service account configured through deployment
environment variables:

```text
LDAP_SERVICE_ACCOUNT_USERNAME=svc-account@example.com
LDAP_SERVICE_ACCOUNT_PASSWORD=replace-with-a-secret
```

Both variables must be non-empty. Configure them in the deployment secret
store, never in `secrets.toml`; they are not logged. If neither is configured,
anonymous LDAP remains the only lookup attempt.

## Migration from the pre-OIDC API

This is a breaking change. Okta and Streamlit now own authentication, so
applications should remove the old LDAP password form and custom browser
authentication state. Remove the old `auth_cookie`, `session_state_names`, RSA
form, remember-me, and encryption setup, including `CookieConfig`,
`LoginConfig`, `LogoutConfig`, `EncryptorConfig`, and `SessionStateConfig`.

The `pyjwt`, `streamlit-cookies-controller`, and `streamlit-rsa-auth-ui`
dependencies are no longer needed. Existing custom cookies are not reused;
users authenticate through the configured Okta OIDC provider after upgrading.

The low-level
`LdapAuthenticate.login(username, password, get_info, additional_check=None)`
method remains available for code that explicitly needs direct LDAP
authentication. The top-level `Authenticate` flow never accepts a password.
