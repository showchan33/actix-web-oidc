use super::{auth_check_inner, CookieName, SecretKey};
use actix_utils::future::{ready, Ready};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::HttpResponse;
use std::{future::Future, pin::Pin, rc::Rc};

pub struct AuthMiddleware {
  cookie_name: CookieName,
  secret_key: SecretKey,
}

impl AuthMiddleware {
  pub fn new(cookie_name: CookieName, secret_key: SecretKey) -> Self {
    AuthMiddleware {
      cookie_name,
      secret_key,
    }
  }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
  S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
  S::Future: 'static,
{
  type Response = ServiceResponse<B>;
  type Error = actix_web::Error;
  type Transform = InnerAuthMiddleware<S>;
  type InitError = ();
  type Future = Ready<Result<Self::Transform, Self::InitError>>;

  fn new_transform(&self, service: S) -> Self::Future {
    ready(Ok(InnerAuthMiddleware {
      service: Rc::new(service),
      cookie_name: self.cookie_name.clone(),
      secret_key: self.secret_key.clone(),
    }))
  }
}
pub struct InnerAuthMiddleware<S> {
  service: Rc<S>,
  cookie_name: CookieName,
  secret_key: SecretKey,
}

impl<S, B> Service<ServiceRequest> for InnerAuthMiddleware<S>
where
  S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
  S::Future: 'static,
{
  type Response = S::Response;
  type Error = actix_web::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

  forward_ready!(service);

  fn call(&self, req: ServiceRequest) -> Self::Future {
    let service = Rc::clone(&self.service);
    let cookie_name = self.cookie_name.clone();
    let secret_key = self.secret_key.clone();

    Box::pin(async move {
      let mut unauthorized = true;
      let path = req.path().to_string();

      if path == "/" || path == "/login" || path == "/callback" || path == "/logout" {
        unauthorized = false;
      } else {
        let result_auth_check = auth_check_inner(req.request(), &cookie_name, &secret_key);

        if result_auth_check.is_ok() {
          unauthorized = false;
        }
      }

      if !unauthorized {
        let res = service.call(req).await?;
        return Ok(res);
      }

      Err(
        actix_web::error::InternalError::from_response(
          "Unauthorized",
          HttpResponse::Unauthorized().body("Unauthorized"),
        )
        .into(),
      )
    })
  }
}
