use super::oidc_config::OidcConfig;
use actix_web::HttpRequest;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use serde_qs;
use std::collections::HashMap;
use urlencoding;

pub fn create_token_body(oidc_config: &OidcConfig, code: &String) -> String {
  #[derive(Serialize)]
  struct TokenBody {
    grant_type: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
  }

  let token_body = TokenBody {
    grant_type: format!("authorization_code"),
    client_id: oidc_config.client.client_id().to_string(),
    client_secret: oidc_config.client_secret.to_string(),
    code: code.clone(),
    redirect_uri: oidc_config.client.redirect_url().unwrap().to_string(),
  };

  serde_qs::to_string(&token_body).unwrap()
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
  access_token: String,
  id_token: String,
  scope: String,
  expires_in: u32,
  token_type: String,
}

pub fn get_payload(token_res: &String) -> Result<HashMap<String, Value>> {
  let token_res_de =
    serde_json::from_str::<TokenResponse>(token_res).context("Failed to parse token response")?;

  let token_str: Vec<String> = token_res_de
    .id_token
    .split('.')
    .map(|x| x.to_string())
    .collect();

  let jwt_u8_vec = URL_SAFE.decode(&token_str[1])?;

  let payload_str = std::str::from_utf8(&jwt_u8_vec)?;

  let payload = serde_json::from_str::<HashMap<String, Value>>(&payload_str)?;
  Ok(payload)
}

pub fn get_auth_redirect_url(request: &HttpRequest, oidc_config: &OidcConfig) -> Option<String> {
  let auth_redirect_param_unwrapped = oidc_config.auth_redirect_param.clone()?;

  let redirect_uri = request.query_string().split('&').find_map(|s| {
    let mut parts = s.splitn(2, '=');
    let key = parts.next()?;
    let value = parts.next()?;
    if key == auth_redirect_param_unwrapped {
      Some(urlencoding::decode(value).unwrap().to_string())
    } else {
      None
    }
  });

  return redirect_uri;
}
