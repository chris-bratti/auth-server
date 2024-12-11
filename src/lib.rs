use core::{fmt, str::FromStr};

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use redis::RedisError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use server::auth_functions::*;
use thiserror::Error;

pub mod db;
pub mod server;

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

impl From<aes_gcm::Error> for AuthError {
    fn from(err: aes_gcm::Error) -> Self {
        AuthError::InternalServerError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AuthError::InternalServerError(err.to_string())
    }
}

impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        let error_message = format!("{}", self);

        // Build the JSON response
        let body = serde_json::json!({
            "success": false,
            "message": error_message
        });

        // Customize the HTTP status code if needed
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
        };

        HttpResponse::build(status_code).json(body)
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
        }
    }
}

impl FromStr for AuthError {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AuthError::Error(s.to_string()))
    }
}

pub enum EncryptionKey {
    SmtpKey,
    TwoFactorKey,
    LoggerKey,
    OauthKey,
}

impl EncryptionKey {
    pub fn get(&self) -> String {
        let key = match self {
            EncryptionKey::SmtpKey => "SMTP_ENCRYPTION_KEY",
            EncryptionKey::TwoFactorKey => "TWO_FACTOR_KEY",
            EncryptionKey::LoggerKey => "LOG_KEY",
            EncryptionKey::OauthKey => "OAUTH_ENCRYPTION_KEY",
        };

        get_env_variable(key).expect("Encryption key is unset!")
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
    verified: bool,
    encrypted_email: String,
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

pub enum AuthType {
    Login,
    Signup,
    VerifyUser,
    ResetPassword,
    RequestPasswordReset,
    ChangePassword,
    VerifyOtp,
    Generate2Fa,
    Enable2Fa,
    Logout,
    Invalid,
}

impl AuthType {
    pub fn from(req_type: &str) -> AuthType {
        match req_type {
            "login" => AuthType::Login,
            "signup" => AuthType::Signup,
            "verify_user" => AuthType::VerifyUser,
            "reset_password" => AuthType::ResetPassword,
            "request_password_reset" => AuthType::RequestPasswordReset,
            "change_password" => AuthType::ChangePassword,
            "verify_otp" => AuthType::VerifyOtp,
            "generate_2fa" => AuthType::Generate2Fa,
            "enable_2fa" => AuthType::Enable2Fa,
            "logout" => AuthType::Logout,
            _ => AuthType::Invalid,
        }
    }
}

#[derive(Error, Debug)]
pub enum DBError {
    #[error("User not found: {0}")]
    NotFound(String),
    #[error("Internal server error: {0}")]
    InternalServerError(#[from] diesel::result::Error),
    #[error("Error: {0}")]
    Error(String),
    #[error("Database connection error: {0}")]
    ConnectionError(#[from] diesel::ConnectionError),
    #[error("Token invalid or expired")]
    TokenExpired,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub pass_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub data: Option<Value>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignupRequest {
    first_name: String,
    last_name: String,
    email: String,
    new_password_request: NewPasswordRequest,
}

#[derive(Serialize, Deserialize)]
pub struct NewPasswordRequest {
    password: String,
    confirm_password: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    new_password_request: NewPasswordRequest,
    current_password: String,
}

#[derive(Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    new_password_request: NewPasswordRequest,
    reset_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyUserRequest {
    verification_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyOtpRequest {
    otp: String,
    login_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Enable2FaRequest {
    otp: String,
    enable_2fa_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse<'a, T> {
    success: bool,
    message: &'a str,
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
struct LoginResponse {
    two_factor_enabled: bool,
    login_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Generate2FaResponse {
    qr_code: String,
    token: String,
    enable_2fa_token: String,
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

#[derive(Serialize, Deserialize)]
pub struct OAuthRequest {
    pub client_id: String,
    pub state: String,
}

#[derive(Serialize, Deserialize)]
pub struct OAuthResponse {
    pub success: bool,
    pub authorization_code: String,
    pub state: String,
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
