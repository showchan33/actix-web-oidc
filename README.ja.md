# actix-web-oidc について

Actix WebのWebサーバに、OIDC(OpenID Connect)でユーザ認証してログインするサンプルプログラムです。

# 動作確認環境

* OS
    * Ubuntu 20.04.6 LTS
* Rust(rustc, cargo)のバージョン
    * 1.79.0

# 事前準備

## OIDCを提供するIdentity Providerの設定とデプロイ

Identity Provider（Auth0,Keycloak等）で、OIDCのエンドポイントをデプロイします。<br>
例えばAuth0では、以下のドキュメントにしたがってOIDCのエンドポイントを提供するアプリケーションを作成可能です。<br>
https://auth0.com/docs/get-started/applications/application-settings

尚、本ツールでIdPとの連携に使う主要なURLのパスは以下です。OIDCエンドポイント作成の際に適宜設定をお願いいたします。
* OIDC認証後にリダイレクトするパス
    * ``http(s)://[your-hostname-and-port]/callback``
* ログアウト後にリダイレクトするパス
    * ``http(s)://[your-hostname-and-port]/``

## 環境変数の設定

``.env.sample``をコピーして``.env``を作成し、お使いの環境に応じて値を設定します。<br>
以下は``.env``の設定例です。

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

# Webサーバの起動

以下のコマンドを実行すると、8080番のポートで受け付けるWebサーバが起動します。

```
cargo run --release
```

# Webサイトの各パスについて

| パス | 認証要否 | 内容 |
| --- | --- | --- |
| ``/`` | 不要 | 誰でもアクセスできるページ |
| ``/login`` | 不要 | ログイン用ページ。認証成功したら``/show-payload``にリダイレクトする |
| ``/logout`` | 必要 | ログアウト用ページ。``/``にリダイレクトする |
| ``/show-payload`` | 必要 | ID Tokenのpayloadを出力 |
| ``/secret`` | 必要 | 認証ユーザしかアクセスできないページ |

リクエストがユーザ認証済かのどうかの判定は、[AuthMiddleware](src/auth_middleware.rs)で行います。

# Author
 
showchan33

# License
"actix-web-oidc" is under [GPL license](https://www.gnu.org/licenses/licenses.en.html).
