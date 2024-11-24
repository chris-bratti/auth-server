use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod auth;
pub mod db;
pub mod server;
pub mod smtp;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
    verified: bool,
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
            "change_password" => AuthType::ChangePassword,
            "verify_otp" => AuthType::VerifyOtp,
            "generate_2fa" => AuthType::Generate2Fa,
            "enable_2fa" => AuthType::Enable2Fa,
            "logout" => AuthType::Logout,
            _ => AuthType::Invalid,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub data: Value,
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
    reset_token: String,
}
