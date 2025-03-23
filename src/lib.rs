#![allow(async_fn_in_trait)]
use core::{fmt, str::FromStr};
#[cfg(feature = "ssr")]
use encryption_libs::EncryptableString;
#[cfg(feature = "ssr")]
use encryption_libs::HashableString;
use leptos_router::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;

pub mod client;
pub mod controllers;

#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub mod server;

pub mod app;
pub use app::*;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use app::*;
    use leptos::*;

    console_error_panic_hook::set_once();

    mount_to_body(App);
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AdminTask {
    pub task_type: AdminTaskType,
    pub message: String,
    pub id: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AdminTaskType {
    ApproveOauthClient { app_name: String, client_id: String },
}

impl AdminTaskType {
    pub fn to_display(&self) -> String {
        match self {
            AdminTaskType::ApproveOauthClient {
                app_name,
                client_id,
            } => format!(
                "New OAuth application {} with ID {} requires approval",
                &app_name, &client_id
            ),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum HtmlError {
    Forbidden,
}

impl fmt::Display for HtmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HtmlError::Forbidden => write!(f, "Client not allowed to access this resource"),
        }
    }
}

impl fmt::Debug for HtmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden => write!(f, "Client not allowed to access this resource"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AuthError {
    InvalidCredentials,
    InternalServerError(String),
    InvalidToken,
    PasswordConfirmationError,
    InvalidPassword,
    Error(String),
    TOTPError,
    AccountLocked,
    InvalidRequest(String),
    Forbidden,
}

impl From<aes_gcm::Error> for AuthError {
    fn from(err: aes_gcm::Error) -> Self {
        AuthError::InternalServerError(err.to_string())
    }
}

// Implement std::fmt::Display for AppError
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => {
                write!(f, "Invalid username or password")
            }
            AuthError::InternalServerError(error) => {
                write!(f, "{error}")
            }
            AuthError::InvalidToken => {
                write!(f, "Token invalid or expired")
            }
            AuthError::Error(msg) => {
                write!(f, "{msg}")
            }
            AuthError::PasswordConfirmationError => {
                write!(f, "Passwords do not match!")
            }
            AuthError::InvalidPassword => {
                write!(f, "Password does not meet minimum requirements!")
            }
            AuthError::TOTPError => {
                write!(f, "Error validating one time password!")
            }
            AuthError::AccountLocked => {
                write!(f, "Your account has been locked due to invalid attempts. Please try again later or reset your password")
            }
            AuthError::InvalidRequest(error) => {
                write!(f, "Invalid auth request: {error}")
            }
            AuthError::Forbidden => {
                write!(f, "Client not allowed to access this resource")
            }
        }
    }
}

// Implement std::fmt::Debug for AppError
impl fmt::Debug for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => {
                write!(f, "Invalid login attempt")
            }
            AuthError::InternalServerError(error) => {
                write!(f, "Internal error: {}", error)
            }
            AuthError::InvalidToken => {
                write!(f, "Invalid token attempt")
            }
            AuthError::Error(msg) => {
                write!(f, "{msg}")
            }
            AuthError::PasswordConfirmationError => {
                write!(f, "Passwords do not match!")
            }
            AuthError::InvalidPassword => {
                write!(f, "Password does not meet minimum requirements!")
            }
            AuthError::TOTPError => {
                write!(f, "Invalid TOTP attempt")
            }
            AuthError::AccountLocked => {
                write!(f, "Account locked")
            }
            AuthError::InvalidRequest(error) => {
                write!(f, "Invalid request: {error}")
            }
            AuthError::Forbidden => {
                write!(f, "Client not allowed to access this resource")
            }
        }
    }
}

impl FromStr for AuthError {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AuthError::Error(s.to_string()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OauthUserInfo {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
    verified: bool,
    email: String,
}

#[cfg(feature = "ssr")]
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
    verified: bool,
    email: EncryptableString,
}

#[cfg(feature = "ssr")]
impl From<User> for OauthUserInfo {
    fn from(value: User) -> Self {
        let User {
            first_name,
            last_name,
            username,
            two_factor,
            verified,
            email,
        } = value.into();
        OauthUserInfo {
            first_name,
            last_name,
            username,
            two_factor,
            verified,
            email: email.get_decrypted().to_string(),
        }
    }
}

#[cfg(feature = "ssr")]
impl From<User> for UserBasicInfo {
    fn from(user: User) -> Self {
        UserBasicInfo {
            first_name: user.first_name,
            last_name: user.last_name,
            username: user.username,
            two_factor: user.two_factor,
            verified: user.verified,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct UserBasicInfo {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
    verified: bool,
}

pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    Invalid,
}

impl GrantType {
    pub fn from(grant_type: &str) -> GrantType {
        match grant_type {
            "authorization_code" => GrantType::AuthorizationCode,
            "refresh_token" => GrantType::RefreshToken,
            _ => GrantType::Invalid,
        }
    }
}

#[cfg(feature = "ssr")]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: EncryptableString,
    pub pass_hash: HashableString,
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub data: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthResponse<T> {
    success: bool,
    message: String,
    response: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    scope: String,
    exp: i64,
    sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OauthClaims {
    scope: String,
    exp: i64,
    sub: String,
    iss: String,
    client_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterNewClientRequest {
    pub app_name: String,
    pub contact_email: String,
    pub redirect_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterNewClientResponse {
    pub success: bool,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReloadOauthClientsResponse {
    pub success: bool,
    pub clients_loaded: i32,
}

#[derive(leptos::Params, PartialEq, Deserialize, Debug)]
pub struct OAuthRequest {
    pub client_id: Option<String>,
    pub state: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OAuthRedirect {
    pub authorization_code: String,
    pub state: String,
    pub redirect_url: String,
}

#[derive(Deserialize)]
pub struct TokenRequestForm {
    pub grant_type: String,
    pub refresh_token: Option<String>,
    pub authorization_code: Option<String>,
}

#[derive(Serialize)]
pub struct AuthorizationCodeResponse {
    pub success: bool,
    pub access_token: String,
    pub refresh_token: String,
    pub username: String,
    pub expiry: i64,
}

#[derive(Serialize)]
pub struct RefreshTokenResponse {
    pub success: bool,
    pub access_token: String,
    pub refresh_token: String,
    pub username: String,
    pub expiry: i64,
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    pub success: bool,
    pub user_data: OauthUserInfo,
    pub timestamp: i64,
}
