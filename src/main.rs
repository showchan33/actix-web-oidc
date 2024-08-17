use actix_session::{
  config::CookieContentSecurity::Private, storage::CookieSessionStore, Session, SessionMiddleware,
};
use actix_web::middleware::Logger;
use actix_web::{cookie::Key, get, http, web, App, HttpRequest, HttpResponse, HttpServer};
use dotenv::dotenv;
use oauth2::{CsrfToken, Scope};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_qs;
use std::env;
mod oidc_config;
use chrono::Utc;
use oidc_config::OidcConfig;

mod auth_middleware;
use auth_middleware::AuthMiddleware;
mod cookie_utils;
mod oidc_handlers;

#[derive(Debug, Clone)]
pub struct CookieName(String);
#[derive(Debug, Clone)]
pub struct SecretKey(String);

#[get("/")]
async fn index() -> HttpResponse {
  HttpResponse::Ok().body("Welcome to the top page!")
}

#[get("/login")]
async fn login(oidc_config: web::Data<OidcConfig>) -> HttpResponse {
  // Generate the full authorization URL.
  let mut authz_request = oidc_config.client.authorize_url(CsrfToken::new_random);

  for scope in &oidc_config.scopes {
    authz_request = authz_request.add_scope(Scope::new(scope.clone()));
  }

  let (authz_url, _csrf_token) = authz_request.url();

  HttpResponse::Found()
    .append_header((http::header::LOCATION, authz_url.to_string()))
    .finish()
}

#[get("/callback")]
async fn callback(
  request: HttpRequest,
  oidc_config: web::Data<OidcConfig>,
  session: Session,
) -> HttpResponse {
  #[derive(Deserialize, Debug)]
  pub struct CallbackQs {
    pub code: String,
    pub state: String,
  }

  let qs = serde_qs::from_str::<CallbackQs>(request.uri().query().unwrap()).unwrap();

  let token_body = oidc_handlers::create_token_body(&oidc_config, &qs.code);

  let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build()
    .unwrap();

  let token_res = client
    .post(oidc_config.client.token_url().unwrap().as_str())
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(token_body)
    .send()
    .await;

  if token_res.is_err() {
    return HttpResponse::BadRequest().body("Failed to get token response.");
  }

  let token_res_string = token_res.unwrap().text().await.unwrap();

  let payload = oidc_handlers::get_payload(&token_res_string);

  if payload.is_err() {
    return HttpResponse::InternalServerError().body("Failed to parse token response.");
  }

  let cookie_data = cookie_utils::generate_cookie_data(payload.unwrap());

  let cookie_key = cookie_data.key;
  let cookie_value = cookie_data.value;
  session.insert(cookie_key, cookie_value).unwrap();

  HttpResponse::Found()
    .append_header((
      http::header::LOCATION,
      format!("{}/{}", oidc_config.server_url.to_string(), "show-payload"),
    ))
    .finish()
}

#[get("/logout")]
async fn logout(oidc_config: web::Data<OidcConfig>, session: Session) -> HttpResponse {
  session.purge();

  #[allow(non_snake_case)]
  #[derive(Serialize)]
  struct LogoutParams {
    returnTo: String,
    client_id: String,
  }

  let logout_params = LogoutParams {
    returnTo: oidc_config.server_url.to_string(),
    client_id: oidc_config.client.client_id().to_string(),
  };

  let redirect_url = format!(
    "{}?{}",
    oidc_config.logout_url,
    serde_qs::to_string(&logout_params).unwrap(),
  );

  HttpResponse::Found()
    .append_header((http::header::LOCATION, redirect_url))
    .finish()
}

#[get("/show-payload")]
async fn show_payload(
  request: HttpRequest,
  cookie_name: web::Data<CookieName>,
  secret_key: web::Data<SecretKey>,
) -> HttpResponse {
  let payload_result =
    cookie_utils::get_payload_from_cookie(&request, cookie_name.get_ref(), secret_key.get_ref());

  match payload_result {
    Ok(payload) => match serde_json::to_string_pretty(&payload) {
      Ok(payload_str) => HttpResponse::Ok()
        .content_type("application/json; charset=utf-8")
        .body(payload_str),
      Err(_) => HttpResponse::InternalServerError().body("Failed to parse payload"),
    },
    Err(_) => HttpResponse::InternalServerError().body("Failed to get payload"),
  }
}

#[get("/secret")]
async fn secret() -> HttpResponse {
  HttpResponse::Ok().body(format!(
    "This page is only accessible to authenticated users."
  ))
}

#[get("/auth-check")]
async fn auth_check(
  request: HttpRequest,
  cookie_name: web::Data<CookieName>,
  secret_key: web::Data<SecretKey>,
) -> HttpResponse {
  let result = auth_check_inner(&request, cookie_name.get_ref(), secret_key.get_ref());

  match result {
    Ok(_) => HttpResponse::Ok().body(""),
    Err(e) => HttpResponse::Unauthorized().body(e),
  }
}

pub fn auth_check_inner(
  request: &HttpRequest,
  cookie_name: &CookieName,
  secret_key: &SecretKey,
) -> Result<(), String> {
  let cookie_header = cookie_utils::get_cookie(&request, &cookie_name.0);

  match cookie_header {
    Some(_) => {
      let payload_result = cookie_utils::get_payload_from_cookie(request, cookie_name, secret_key);

      match payload_result {
        Ok(payload) => {
          if let Some(exp_value) = payload.get("exp") {
            if let Some(exp) = exp_value.as_i64() {
              let now = Utc::now().timestamp();
              if exp >= now {
                Ok(())
              } else {
                Err("Session expired.".to_string())
              }
            } else {
              Err("Invalid expiry date value.".to_string())
            }
          } else {
            Err("Invalid payload.".to_string())
          }
        }
        Err(_) => Err("Unauthorized".to_string()),
      }
    }
    None => Err("Unauthorized".to_string()),
  }
}

fn session_middleware(
  secret_key: &str,
  cookie_name: &str,
) -> SessionMiddleware<CookieSessionStore> {
  SessionMiddleware::builder(
    CookieSessionStore::default(),
    Key::from(secret_key.as_bytes()),
  )
  .cookie_name(String::from(cookie_name))
  .cookie_secure(false)
  .cookie_content_security(Private)
  .build()
}

#[actix_web::main]
async fn main() -> Result<(), actix_web::Error> {
  let _env = dotenv();

  std::env::set_var("RUST_LOG", "debug");
  env_logger::init();

  let cookie_name = CookieName(env::var("COOKIE_NAME").expect("COOKIE_NAME must be set"));
  let secret_key = SecretKey(env::var("SECRET_KEY").expect("SECRET_KEY must be set"));

  HttpServer::new(move || {
    App::new()
      .wrap(AuthMiddleware::new(cookie_name.clone(), secret_key.clone()))
      .wrap(session_middleware(&secret_key.0, &cookie_name.0))
      .wrap(Logger::default())
      .app_data(web::Data::new(OidcConfig::new()))
      .app_data(web::Data::new(cookie_name.clone()))
      .app_data(web::Data::new(secret_key.clone()))
      .service(index)
      .service(login)
      .service(callback)
      .service(logout)
      .service(show_payload)
      .service(secret)
      .service(auth_check)
  })
  .bind("0.0.0.0:8080")?
  .run()
  .await?;

  Ok(())
}
