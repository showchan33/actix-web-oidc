use dotenv::dotenv;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use std::env;

#[derive(Clone)]
pub struct OidcConfig {
  pub client: BasicClient,
  pub logout_url: String,
  pub scopes: Vec<String>,
  pub client_secret: String,
  pub server_url: String,
}

impl OidcConfig {
  pub fn new() -> Self {
    _ = dotenv();

    let authorization_url =
      env::var("OIDC_AUTHORIZATION_URL").expect("OIDC_AUTHORIZATION_URL must be set");
    let token_url = env::var("OIDC_TOKEN_URL").expect("OIDC_TOKEN_URL must be set");
    let logout_url = env::var("OIDC_LOGOUT_URL").expect("OIDC_LOGOUT_URL must be set");
    let scopes: Vec<String> = env::var("OIDC_SCOPES")
      .unwrap_or_else(|_| "openid,email,profile".to_string())
      .split(',')
      .map(|s| s.to_string())
      .collect();
    let client_id = env::var("OIDC_CLIENT_ID").expect("OIDC_CLIENT_ID must be set");
    let client_secret = env::var("OIDC_CLIENT_SECRET").expect("OIDC_CLIENT_SECRET must be set");

    let server_url = env::var("SERVER_URL").expect("SERVER_URL must be set");
    let redirect_url = format!("{server_url}/callback");

    let client = BasicClient::new(
      ClientId::new(client_id.to_string()),
      Some(ClientSecret::new(client_secret.to_string())),
      AuthUrl::new(authorization_url.clone()).unwrap(),
      Some(TokenUrl::new(token_url.clone()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_string()).unwrap());

    Self {
      client,
      logout_url,
      scopes,
      client_secret,
      server_url,
    }
  }
}
