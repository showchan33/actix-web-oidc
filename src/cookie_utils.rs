use super::{CookieName, SecretKey};
use actix_web::HttpRequest;
use anyhow::{anyhow, Context, Result};
use cookie::{Cookie, CookieJar, Key};
use rand::Rng;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fmt::Write;

pub fn cookie2hashmap(cookie: &str) -> HashMap<String, String> {
  let mut ret: HashMap<String, String> = HashMap::new();

  let cookie_split: Vec<&str> = cookie.split(';').collect();

  for kv in cookie_split {
    let re = Regex::new(r"^\s+").unwrap();
    let kv_rep = &re.replace(kv, "");
    let key_value: Vec<String> = kv_rep.split('=').map(|x| x.to_string()).collect();
    if key_value.len() == 2 {
      ret.insert(key_value[0].clone(), key_value[1].clone());
    }
  }

  return ret;
}

pub fn get_cookie(req: &HttpRequest, cookie_name: &str) -> Option<String> {
  match req.headers().get("cookie") {
    Some(v) => match v.to_str() {
      Ok(v2) => {
        let cookie_hashmap = cookie2hashmap(v2);
        match cookie_hashmap.get(cookie_name) {
          Some(value) => Some(value.to_string()),
          None => None,
        }
      }
      Err(_) => None,
    },
    None => None,
  }
}

#[derive(Deserialize, Debug, Clone)]
pub struct CookieData {
  pub key: String,
  pub value: HashMap<String, Value>,
}

pub fn generate_cookie_data(payload: HashMap<String, Value>) -> CookieData {
  CookieData {
    key: generate_random_sha1(),
    value: payload,
  }
}

fn generate_random_sha1() -> String {
  let mut rng = rand::thread_rng();
  let random_bytes: [u8; 16] = rng.gen();

  let mut hasher = Sha1::new();
  hasher.update(&random_bytes);
  let result = hasher.finalize();

  let mut hex_string = String::new();
  for byte in result {
    write!(&mut hex_string, "{:02x}", byte).expect("Unable to write");
  }

  hex_string
}

fn decrypt_cookie(cookie_name: &str, encrypted_cookie_value: &str, secret_key_str: &str) -> Value {
  let cookie_str = format!("{}={}", cookie_name, encrypted_cookie_value);

  let cookie = Cookie::parse_encoded(cookie_str).unwrap();

  let secret_key = Key::from(secret_key_str.as_bytes());

  let mut jar = CookieJar::new();
  jar.add_original(cookie.clone());

  let private_cookie = jar.private(&secret_key).get(cookie_name).unwrap();
  let cookie_json_text = private_cookie.value();

  serde_json::from_str(cookie_json_text).expect("Failed to parse JSON")
}

pub fn get_payload_from_cookie(
  request: &HttpRequest,
  cookie_name: &CookieName,
  secret_key: &SecretKey,
) -> Result<HashMap<String, Value>> {
  let cookie_header = get_cookie(&request, &cookie_name.0);
  let first_keyvalue_of_cookie =
    decrypt_and_get_keyvalue_of_cookie(&cookie_name.0, &cookie_header.unwrap(), &secret_key.0)?;

  match first_keyvalue_of_cookie.1 {
    Value::String(s) => serde_json::from_str::<HashMap<String, Value>>(&s)
      .context("Failed to deserialize cookie value"),
    _ => Err(anyhow!("Cookie value is not a string")),
  }
}

fn decrypt_and_get_keyvalue_of_cookie(
  cookie_name: &str,
  encrypted_cookie_value: &str,
  secret_key_str: &str,
) -> Result<(String, Value)> {
  let decrypted_cookie = decrypt_cookie(cookie_name, encrypted_cookie_value, secret_key_str);

  if let Value::Object(map) = decrypted_cookie {
    let key_value_map: HashMap<String, Value> = map.into_iter().collect();

    if let Some((key, value)) = key_value_map.iter().next() {
      return Ok((key.clone(), value.clone()));
    }
  }

  Err(anyhow!("Invalid cookie format"))
}
