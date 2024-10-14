# About actix-web-oidc

A sample program that authenticates and logs in users with OIDC (OpenID Connect) on an Actix Web server.

# Tested Environment

* OS
    * Ubuntu 20.04.6 LTS
* Rust(rustc, cargo) version
    * 1.79.0

# Preparation

## Configure and deploy an Identity Provider to provide OIDC

Deploy OIDC endpoint's with Identity Provider. Examples of Identity Providers are Auth0, Keycloak, etc.<br>
For instance, with Auth0, you can create an application that provides an OIDC endpoint according to the following documentation.<br>
https://auth0.com/docs/get-started/applications/application-settings

The main URL paths used by the tool to link to IdPs are as follows. Please configure appropriately when creating OIDC endpoints.

* Path to redirect after OIDC authentication
    * ``http(s)://[your-hostname-and-port]/callback``
* Path to redirect after logout
    * ``http(s)://[your-hostname-and-port]/``

## Setting environment variables

Copy ``.env.sample`` to create ``.env`` and set the values according to your environment.<br>
Here is an example of ``.env`` configuration.

```sh:.env
OIDC_IDP_DOMAIN="some-identity-provider.com"

# Configure according to IdP specifications.
OIDC_AUTHORIZATION_URL="https://${OIDC_IDP_DOMAIN}/authorize"
OIDC_TOKEN_URL="https://${OIDC_IDP_DOMAIN}/oauth/token"
OIDC_LOGOUT_URL="https://${OIDC_IDP_DOMAIN}/v2/logout"
OIDC_SCOPES="openid,email,profile"

# Set the credential information previously set up in the IdP.
OIDC_CLIENT_ID="abcdefgh12345678..."
OIDC_CLIENT_SECRET="ABCDEFGH12345678..."

# Set the URL of this Web server.
SERVER_URL="https://your-relying-party.com"

# Secret key for encrypting the session cookie issued by this Web server.
# At least 64 characters are required.
SECRET_KEY="99l5RkdZqr9YEhyywWA8cZy5E0UfyYDm6B9tllnvw1ARU8TKI61JvIA6yKmJRwHzgdLfZwLK"

COOKIE_NAME="oidc-cookie"

# Query string key name used to store the URL the user was trying to access before being redirected to the login page.
# For example, if the user tries to access https://example.com/profile and is redirected to the login page, the query string will include the following:
# https://example.com/login?rd=https://example.com%2Fprofile
# This parameter is optional and is used as the redirect destination after a successful login.
AUTH_REDIRECT_PARAM="rd"
```

# Start Web server

By running the following command, a web server that listens on port 8080 will start.

```
cargo run --release
```

# About each path on the Web site

| path | authentication required | role |
| --- | --- | --- |
| ``/`` | not required | Public page accessible to all |
| ``/login`` | not required | Login page. After successful authentication, redirect to ``/show-payload`` |
| ``/logout`` | required | Logout page. Redirect to ``/`` |
| ``/show-payload`` | required | Display ID Token payload |
| ``/secret`` | required | Only authenticated users can access |

[AuthMiddleware](src/auth_middleware.rs) is used to determine if a request has been authenticated by a user.

# Author
 
showchan33

# License
"actix-web-oidc" is under [GPL license](https://www.gnu.org/licenses/licenses.en.html).
