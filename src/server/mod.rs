use std::time::SystemTime;

use actix::Message;
use actix_web::http::StatusCode;
use actix_web::{web, HttpResponse, ResponseError};
use leptos::ServerFnError;
use maud::html;
use redis::RedisError;
use serde::{Deserialize, Serialize};

use crate::db::db_helper::DbInstance;
use crate::db::models::{AppAdmin, DBUser};
use crate::db::DBError;
use crate::{AdminTask, AdminTaskType, HtmlError, User};

use crate::AuthError;

pub mod actors;
pub mod admin_handlers;
pub mod auth_functions;
pub mod auth_handlers;
pub mod oauth_handlers;
pub mod smtp;

impl AdminTaskMessage {
    pub fn into_admin_task(self) -> AdminTask {
        AdminTask {
            task_type: self.task_type,
            message: self.message,
            id: self.id,
        }
    }
}

#[derive(Message, Serialize, Deserialize, Clone)]
#[rtype(result = "Result<(), AuthError>")]
pub struct AdminTaskMessage {
    pub task_type: AdminTaskType,
    pub message: String,
    pub id: usize,
}

impl AuthError {
    pub fn to_server_fn_error(self) -> ServerFnError<AuthError> {
        ServerFnError::WrappedServerError(self)
    }
}

impl From<RedisError> for AuthError {
    fn from(err: RedisError) -> Self {
        AuthError::InternalServerError(err.to_string())
    }
}

impl From<DBError> for AuthError {
    fn from(err: DBError) -> Self {
        AuthError::InternalServerError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AuthError::InternalServerError(err.to_string())
    }
}

impl From<actix_web::Error> for AuthError {
    fn from(err: actix_web::Error) -> Self {
        AuthError::InternalServerError(err.to_string())
    }
}

impl ResponseError for HtmlError {
    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        let message = format!("{self}");
        let html_body = html! {
            head {
                title {"Forbidden"}
                style type="text/css" {
                    "body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #1e1e1e;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #444444;
                        border-radius: 8px;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    }
                    h1 {
                        color: #fff;
                    }
                    p {
                        margin-bottom: 20px;
                        color: #fff;
                    }"
                }
            }
            body{
                div class="container" {
                    h1 {"Forbidden"}
                    p{ (message) }
                }
            }
        }
        .into_string();

        let status_code = match *self {
            HtmlError::Forbidden => StatusCode::FORBIDDEN,
        };

        HttpResponse::build(status_code).body(html_body)
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        let error_message = format!("{}", self);

        eprintln!("{error_message}");

        let body = serde_json::json!({
            "success": false,
            "message": error_message
        });

        let status_code = match *self {
            AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AuthError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::PasswordConfirmationError => StatusCode::UNAUTHORIZED,
            AuthError::InvalidPassword => StatusCode::UNAUTHORIZED,
            AuthError::AccountLocked => StatusCode::UNAUTHORIZED,
            AuthError::TOTPError => StatusCode::UNAUTHORIZED,
            AuthError::Error(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            AuthError::Forbidden => StatusCode::FORBIDDEN,
        };

        HttpResponse::build(status_code).json(body)
    }
}

pub trait DatabaseUser {
    fn is_locked(&self) -> bool;
    fn last_failed_attempt(&self) -> Option<SystemTime>;
    fn pass_hash(&self) -> &String;
    fn two_factor_token(&self) -> Option<&String>;
    fn two_factor(&self) -> bool;
    fn verified(&self) -> bool;
    fn increment_password_tries(
        &self,
        db_instance: &web::Data<DbInstance>,
    ) -> Result<bool, DBError>;
    fn enable_2fa(&self, db_instance: &web::Data<DbInstance>) -> Result<(), DBError>;
    async fn save_2fa_token(
        &self,
        two_factor_token: &String,
        db_instance: &web::Data<DbInstance>,
    ) -> Result<(), DBError>;
}

impl DatabaseUser for DBUser {
    fn is_locked(&self) -> bool {
        self.locked
    }

    fn last_failed_attempt(&self) -> Option<SystemTime> {
        self.last_failed_attempt
    }

    fn pass_hash(&self) -> &String {
        &self.pass_hash
    }

    fn two_factor(&self) -> bool {
        self.two_factor
    }

    fn verified(&self) -> bool {
        self.verified
    }

    fn increment_password_tries(
        &self,
        db_instance: &web::Data<DbInstance>,
    ) -> Result<bool, DBError> {
        db_instance.increment_db_password_tries(&self.username)
    }

    fn two_factor_token(&self) -> Option<&String> {
        self.two_factor_token.as_ref()
    }

    fn enable_2fa(&self, db_instance: &web::Data<DbInstance>) -> Result<(), DBError> {
        db_instance.enable_2fa_for_db_user(&self.username)
    }

    async fn save_2fa_token(
        &self,
        two_factor_token: &String,
        db_instance: &web::Data<DbInstance>,
    ) -> Result<(), DBError> {
        db_instance
            .set_2fa_token_for_db_user(&self.username, two_factor_token)
            .await
    }
}

impl DatabaseUser for AppAdmin {
    fn is_locked(&self) -> bool {
        self.locked
    }

    fn last_failed_attempt(&self) -> Option<SystemTime> {
        self.last_failed_attempt
    }

    fn pass_hash(&self) -> &String {
        &self.pass_hash
    }

    fn two_factor(&self) -> bool {
        true
    }

    fn verified(&self) -> bool {
        self.initialized
    }

    fn increment_password_tries(
        &self,
        db_instance: &web::Data<DbInstance>,
    ) -> Result<bool, DBError> {
        db_instance.increment_admin_password_retries(&self.username)
    }

    fn two_factor_token(&self) -> Option<&String> {
        self.two_factor_token.as_ref()
    }

    fn enable_2fa(&self, _: &web::Data<DbInstance>) -> Result<(), DBError> {
        Ok(())
    }

    async fn save_2fa_token(
        &self,
        two_factor_token: &String,
        db_instance: &web::Data<DbInstance>,
    ) -> Result<(), DBError> {
        db_instance
            .initialize_admin(&self.username, two_factor_token)
            .await
    }
}

impl From<DBUser> for User {
    fn from(db_user: DBUser) -> Self {
        User {
            first_name: db_user.first_name,
            last_name: db_user.last_name,
            username: db_user.username,
            two_factor: db_user.two_factor,
            verified: db_user.verified,
            email: db_user.email,
        }
    }
}
