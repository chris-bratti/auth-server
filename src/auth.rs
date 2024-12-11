use core::{convert::Into, result::Result::Ok};
use std::sync::Arc;

use actix_identity::Identity;
use actix_web::{
    get, http::StatusCode, post, web, HttpMessage, HttpRequest, HttpResponse, Responder, Result,
};
use redis::Commands;
use tokio::task;

use crate::smtp::generate_reset_email_body;
use crate::{
    db::db_helper::*, server::auth_functions::*, AuthError, ChangePasswordRequest,
    Enable2FaRequest, EncryptionKey, ResetPasswordRequest, SignupRequest, VerifyOtpRequest,
    VerifyUserRequest,
};
use crate::{
    smtp::{self, generate_welcome_email_body},
    LoginRequest,
};
use crate::{
    AuthResponse, AuthorizationCodeResponse, Generate2FaResponse, LoginResponse,
    NewPasswordRequest, UserInfo,
};

use lazy_static::lazy_static;

lazy_static! {
    static ref REDIS_CLIENT: redis::Client = redis::Client::open(
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!")
    )
    .unwrap();
}

/// Server function to log in user
pub async fn handle_login(
    username: String,
    info: LoginRequest,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let LoginRequest { password } = info;

    let encrypted_username: String = encrypt_string(&username, EncryptionKey::LoggerKey)
        .await
        .expect("Error encrypting username");

    println!("Logging in user: {}", encrypted_username);

    // Case insensitive usernames
    let username: String = username.trim().to_lowercase();

    if db_instance
        .is_user_locked(&username)
        .map_err(|_| AuthError::InvalidCredentials)?
    {
        println!("User is locked");
        return Err(AuthError::AccountLocked);
    }

    // Retrieve pass hash from DB
    let pass_result = db_instance
        .get_pass_hash_for_username(&username)
        .map_err(|_| AuthError::InvalidCredentials);

    // Verify password hash with Argon2
    let verified_result = verify_hash(&password, &pass_result?);

    if verified_result.is_err() || !verified_result.unwrap() {
        println!("Failed login attempt for {}", &encrypted_username);
        let user_not_locked = db_instance
            .increment_db_password_tries(&username)
            .expect("Error marking login attempt as failed");

        if !user_not_locked {
            return Err(AuthError::AccountLocked);
        }
        return Err(AuthError::InvalidCredentials);
    }

    let two_factor = db_instance
        .user_has_2fa_enabled(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    println!("User OTP: {}", two_factor);

    if two_factor {
        let pending_token = generate_jwt_token(&username, "verify_otp".to_string(), 600)
            .await
            .map_err(|_| {
                AuthError::InternalServerError(String::from("Error generating pending token"))
            })?;
        Ok(HttpResponse::Ok().json(AuthResponse {
            success: false,
            message: "User has 2FA enabled",
            response: Some(LoginResponse {
                two_factor_enabled: true,
                login_token: Some(pending_token),
            }),
        }))
    } else {
        // Attach user to current session
        Identity::login(&request.extensions(), username.clone().into()).unwrap();

        Ok(HttpResponse::Ok().json(AuthResponse {
            success: true,
            message: "Login success",
            response: Some(LoginResponse {
                two_factor_enabled: false,
                login_token: None,
            }),
        }))
    }
}

/// Retrieves the User information based on username in current session
#[get("/user")]
pub async fn get_user_from_session(
    user: Option<Identity>,
    db_instance: web::Data<DbInstance>,
) -> Result<web::Json<crate::User>, AuthError> {
    // If user exists in session, gets User entry from DB
    if let Some(user) = user {
        match db_instance.find_user_by_username(&user.id().unwrap()) {
            Ok(some_user) => match some_user {
                Some(user) => Ok(web::Json(user)),
                None => Err(AuthError::Error("User not found".to_string())),
            },
            Err(err) => Err(AuthError::InternalServerError(format!("{}", err))),
        }
    } else {
        println!("No user found");
        Err(AuthError::Error("User not found".to_string()))
    }
}

/// Server function to create a new user
pub async fn handle_signup(
    username: String,
    info: SignupRequest,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let SignupRequest {
        first_name,
        last_name,
        email,
        new_password_request,
    } = info;

    let NewPasswordRequest {
        confirm_password,
        password,
    } = new_password_request;

    // This should have been done on the form submit, but just in case something snuck through
    if confirm_password != password {
        return Err(AuthError::PasswordConfirmationError);
    }

    // Do server side password strength validation
    if !check_valid_password(&password) {
        return Err(AuthError::InvalidPassword);
    }

    // Usernames should case insensitive
    let username: String = username.trim().to_lowercase();

    // Checks db to ensure unique usernames
    match db_instance.does_user_exist(&username) {
        Ok(username_exists) => {
            if username_exists {
                return Err(AuthError::Error("Invalid username!".to_string()));
            }
        }
        Err(err) => return Err(AuthError::InternalServerError(err.to_string())),
    }

    println!(
        "Signing up user: {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );

    // TODO: Check to ensure unique emails - Maybe I'll end up eliminating usernames all together

    // Hash password
    let pass_hash = hash_string(&password);

    let encrypted_email = encrypt_string(&email, EncryptionKey::SmtpKey);

    // Create user info to interact with DB
    let user_info = UserInfo {
        username: username.clone(),
        first_name: first_name.clone(),
        last_name,
        pass_hash: pass_hash.await.expect("Error hashing password"),
        email: encrypted_email.await.expect("Error encrypting email"),
    };

    // Creates DB user
    let user = db_instance.create_user(user_info);
    // Generate random 32 bit verification token path
    let generated_token = generate_token();

    // Hash token
    let verification_token = hash_string(&generated_token)
        .await
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    let user = user
        .await
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    // Save token hash to DB
    db_instance
        .save_verification_token_to_db(&username, &verification_token)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    // Send verification email
    task::spawn_blocking(move || {
        smtp::send_email(
            &email,
            "Welcome!".to_string(),
            generate_welcome_email_body(&first_name, &generated_token),
            &first_name,
        )
    });

    println!("Saving user to session: {}", user.username);
    Identity::login(&request.extensions(), user.username.into()).unwrap();

    Ok(HttpResponse::Ok().json(AuthResponse::<()> {
        success: true,
        message: "New user enrolled",
        response: None,
    }))
}

/// Server function to update user password
pub async fn handle_change_password(
    username: String,
    info: ChangePasswordRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let ChangePasswordRequest {
        new_password_request,
        current_password,
    } = info;

    let NewPasswordRequest {
        password,
        confirm_password,
    } = new_password_request;
    // Retrieve and check if supplied current password matches against store password hash
    let pass_result = db_instance
        .get_pass_hash_for_username(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()));

    let verified_result = verify_hash(&current_password, &pass_result?);

    // Check supplied current password is valid
    if verified_result.is_err() || !verified_result.unwrap() {
        return Err(AuthError::InvalidCredentials);
    }

    // Server side password confirmation
    if password != confirm_password {
        return Err(AuthError::PasswordConfirmationError);
    }

    // Do server side password strength validation
    if !check_valid_password(&password) {
        return Err(AuthError::InvalidPassword);
    }

    println!(
        "Changing password for user: {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );

    // Hash new password
    let pass_hash = hash_string(&password)
        .await
        .expect("Error hashing password");

    // Store new password in database
    db_instance
        .update_db_password(&username, &pass_hash)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    Ok(HttpResponse::Ok().json(AuthResponse::<()> {
        success: true,
        message: "Password change successful",
        response: None,
    }))
}

pub async fn handle_reset_password(
    username: String,
    info: ResetPasswordRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let ResetPasswordRequest {
        new_password_request,
        reset_token,
    } = info;

    let NewPasswordRequest {
        password,
        confirm_password,
    } = new_password_request;

    println!("Requesting to reset password");
    // Verify reset token
    let token_verification = verify_reset_token(&username, &reset_token, &db_instance)?;

    // If token does not match or is no longer valid, return
    if !token_verification {
        println!("Tokens don't match!");
        return Err(AuthError::InvalidToken);
    }

    // Server side password confirmation
    if password != confirm_password {
        return Err(AuthError::PasswordConfirmationError);
    }

    // Do server side password strength validation
    if !check_valid_password(&password) {
        return Err(AuthError::InvalidPassword);
    }

    // Hash new password
    let pass_hash = hash_string(&password)
        .await
        .expect("Error hashing password");

    // Store new password in database
    db_instance
        .update_db_password(&username, &pass_hash)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    db_instance
        .delete_db_reset_token(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    db_instance
        .unlock_db_user(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    Ok(HttpResponse::Ok().json(AuthResponse::<()> {
        success: true,
        message: "Password reset successful",
        response: None,
    }))
}

pub async fn handle_request_password_reset(
    username: String,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    // Checks if user exists. If it doesn't, stops process but produces no error
    // This is to maintain username security
    match db_instance.does_user_exist(&username) {
        Ok(username_exists) => {
            if !username_exists {
                return Ok(HttpResponse::new(StatusCode::OK));
            }
        }
        Err(_err) => {
            return Err(AuthError::InternalServerError(
                "Something went wrong".to_string(),
            ))
        }
    }

    // Generate random 32 bit reset token path
    let generated_token = generate_token();

    // Hash token
    let reset_token = hash_string(&generated_token)
        .await
        .map_err(|_| AuthError::InternalServerError("Something went wrong".to_string()))?;

    // Save token hash to DB
    db_instance
        .save_reset_token_to_db(&username, &reset_token)
        .map_err(|_| AuthError::InternalServerError("Something went wrong".to_string()))?;

    let user = db_instance
        .find_user_by_username(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?
        .expect("No user found!");

    let name = user.first_name;

    let user_email = decrypt_string(&user.encrypted_email, EncryptionKey::SmtpKey)
        .await
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    task::spawn_blocking(move || {
        smtp::send_email(
            &user_email,
            "Reset Password".to_string(),
            generate_reset_email_body(&generated_token, &name),
            &name,
        )
    });

    Ok(HttpResponse::Ok().json(AuthResponse::<()> {
        success: true,
        message: "Password reset request successful",
        response: None,
    }))
}

pub async fn handle_verify_user(
    username: String,
    info: VerifyUserRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let VerifyUserRequest { verification_token } = info;

    println!("Attempting to verify user");
    // Verify reset token
    let token_verification =
        verify_confirmation_token(&username, &verification_token, &db_instance)?;

    // If token does not match or is no longer valid, return
    if !token_verification {
        return Err(AuthError::InvalidToken);
    }

    db_instance
        .set_db_user_as_verified(&username)
        .map_err(|_| AuthError::InternalServerError("Something went wrong".to_string()))
        .expect("Error setting user as verified");

    db_instance
        .delete_db_verification_token(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    Ok(HttpResponse::Ok().json(AuthResponse::<()> {
        success: true,
        message: "User verified",
        response: None,
    }))
}

pub async fn handle_generate_2fa(
    username: String,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let two_factor_enabled = db_instance
        .user_has_2fa_enabled(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    if two_factor_enabled {
        return Err(AuthError::Error(
            "Two Factor already enabled for user!".to_string(),
        ));
    }

    let (qr_code, token) = create_2fa_for_user(&username)
        .await
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    let encrypted_token = encrypt_string(&token, EncryptionKey::TwoFactorKey)
        .await
        .expect("Error encrypting token");

    db_instance
        .set_2fa_token_for_db_user(&username, &encrypted_token)
        .map_err(|_| {
            AuthError::InternalServerError("Error saving token to database".to_string())
        })?;

    let enable_2fa_token = generate_jwt_token(&username, "enable_2fa".to_string(), 600)
        .await
        .map_err(|_| AuthError::InternalServerError("Error creating pending_token".to_string()))?;
    Ok(HttpResponse::Ok().json(web::Json(Generate2FaResponse {
        qr_code,
        token,
        enable_2fa_token,
    })))
}

pub async fn handle_enable_2fa(
    username: String,
    info: Enable2FaRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let Enable2FaRequest {
        otp,
        enable_2fa_token,
    } = info;

    let two_factor_enabled = db_instance
        .user_has_2fa_enabled(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    if two_factor_enabled {
        return Err(AuthError::Error(
            "Two Factor already enabled for user!".to_string(),
        ));
    }

    validate_pending_token(
        &username,
        enable_2fa_token,
        "enable_2fa".to_string(),
        &db_instance,
    )
    .await
    .map_err(|_| AuthError::TOTPError)?;

    let totp = get_totp(&username, &db_instance)
        .await
        .expect("Error validating token")
        .trim()
        .to_string();

    if otp != totp {
        return Err(AuthError::TOTPError);
    }

    db_instance
        .enable_2fa_for_db_user(&username)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    Ok(HttpResponse::Ok().json(AuthResponse::<()> {
        success: true,
        message: "2FA enabled",
        response: None,
    }))
}

pub async fn handle_verify_otp(
    username: String,
    info: VerifyOtpRequest,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let VerifyOtpRequest { otp, login_token } = info;

    println!("Verifying OTP for {}", username);
    let otp = otp.trim().to_string();

    validate_pending_token(
        &username,
        login_token,
        "verify_otp".to_string(),
        &db_instance,
    )
    .await
    .map_err(|_| AuthError::TOTPError)?;

    let totp = get_totp(&username, &db_instance)
        .await
        .expect("Error validating token")
        .trim()
        .to_string();

    if !otp.eq(&totp) {
        return Err(AuthError::TOTPError);
    }

    // Attach user to current session
    Identity::login(&request.extensions(), username.clone().into()).unwrap();

    Ok(HttpResponse::Ok().json(AuthResponse::<()> {
        success: true,
        message: "OTP was successful",
        response: None,
    }))
}

pub async fn handle_authorization_token(
    authorization_code: String,
    client_id: &String,
    db_instance: &web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let mut con = REDIS_CLIENT.get_connection()?;

    let stored_token: Option<String> = con.hget("auth_codes", &client_id)?;

    let stored_token = stored_token.ok_or_else(|| AuthError::InvalidCredentials)?;

    let (stored_auth_code, username) = stored_token.split_once(':').ok_or_else(|| {
        AuthError::InternalServerError("Error validating token, please try again".to_string())
    })?;

    if stored_auth_code.to_string() != authorization_code {
        return Err(AuthError::InvalidCredentials);
    }

    let username = username.to_string();
    let expiry = chrono::Utc::now().timestamp() + 600;
    let access_token = generate_oauth_token(client_id, expiry, &username).await?;
    let refresh_token = generate_token();

    // Clone the data necessary for the async work
    let stored_instance = Arc::clone(db_instance);
    let stored_id = client_id.clone();
    let stored_token = refresh_token.clone();
    let stored_username = username.clone();

    tokio::spawn(async move {
        if let Err(err) = stored_instance
            .add_refresh_token(&stored_id, &stored_token, &stored_username)
            .await
        {
            eprintln!("Error saving refresh token to DB: {:?}", err);
        }
    });

    Ok(HttpResponse::Ok().json(AuthorizationCodeResponse {
        success: true,
        username,
        access_token,
        refresh_token,
        expiry,
    }))
}

#[post("/logout")]
async fn logout(user: Identity) -> impl Responder {
    user.logout();
    HttpResponse::Ok()
}
