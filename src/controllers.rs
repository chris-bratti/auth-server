use crate::AuthError;
use cfg_if::cfg_if;
use leptos::server;
use leptos::ServerFnError;
cfg_if! {
    if #[cfg(feature = "ssr")] {
        use actix_web::{web};
        use leptos::{use_context};
        use leptos_actix::extract;
        use actix_session::SessionExt;


        use crate::{
            db::db_helper::DbInstance,
            server::auth_handlers::{handle_login, handle_verify_otp},
        };
        use crate::server::auth_handlers::handle_signup;
        use crate::server::auth_handlers::{
            handle_change_password, handle_enable_2fa, handle_generate_2fa, handle_request_password_reset,
            handle_reset_password, handle_verify_user,
        };
        use actix_identity::Identity;
        use crate::client::client_helpers::get_request_data;
        use crate::client::client_helpers;
        use crate::get_env_variable;
        use crate::server::admin_handlers::handle_signup_admin;
        use crate::DatabaseUser;
    }
}

#[server(Logout, "/api")]
pub async fn logout() -> Result<(), ServerFnError<AuthError>> {
    let identity: Option<Identity> = extract().await.map_err(|err| {
        ServerFnError::WrappedServerError(AuthError::InternalServerError(err.to_string()))
    })?;
    Identity::logout(identity.expect("No user found in session!"));
    leptos_actix::redirect("/");
    Ok(())
}

#[server(AdminLogin, "/api")]
pub async fn admin_login(
    username: String,
    password: String,
) -> Result<String, ServerFnError<AuthError>> {
    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;
    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    // Case insensitive usernames
    let username: String = username.trim().to_lowercase();

    let user = db_instance
        .get_admin_from_username(&username)
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let _ = handle_login(&username, password, user, req, db_instance)
        .await
        .map_err(|err| err.to_server_fn_error())?;

    Ok(username)
}

#[server(SignupAdmin, "/api")]
pub async fn signup_admin(
    username: String,
    password: String,
    confirm_password: String,
    admin_key: String,
) -> Result<String, ServerFnError<AuthError>> {
    println!("Registering admin");
    if admin_key != get_env_variable("ADMIN_KEY").unwrap() {
        return Err(AuthError::InvalidCredentials.to_server_fn_error());
    }
    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;

    handle_signup_admin(&username, password, confirm_password, db_instance).await?;

    Ok(username)
}

#[server(AdminGenerate2fa, "/api")]
pub async fn admin_generate_2fa(
    username: String,
) -> Result<(String, String), ServerFnError<AuthError>> {
    let (req, db_instance) = get_request_data().await?;

    let admin = db_instance
        .get_admin_from_username(&username)
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let (qr_code, token) = handle_generate_2fa(username, admin, db_instance, req).await?;

    Ok((qr_code, token))
}

#[server(AdminEnable2fa, "/api")]
pub async fn admin_enable_2fa(
    username: String,
    otp: String,
) -> Result<bool, ServerFnError<AuthError>> {
    let (req, db_instance) = get_request_data().await?;

    // Extract login_token from user session
    let two_factor_token: String = req
        .get_session()
        .get("2fa")
        .map_err(|_| AuthError::InternalServerError("Error getting session!".to_string()))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let admin = db_instance
        .get_admin_from_username(&username)
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    handle_enable_2fa(username, admin, otp, two_factor_token, db_instance).await?;

    req.get_session().remove("2fa");

    leptos_actix::redirect("/test");

    Ok(true)
}

#[server(VerifyAdminOtp, "/api")]
pub async fn verify_admin_otp(
    username: String,
    otp: String,
) -> Result<(), ServerFnError<AuthError>> {
    let (req, db_instance) = get_request_data().await?;

    // Extract login_token from user session
    let login_token: String = req
        .get_session()
        .get("otp")
        .map_err(|_| AuthError::InternalServerError("Error getting session!".to_string()))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let admin = db_instance
        .get_admin_from_username(&username)
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    handle_verify_otp(&username, otp, admin, login_token, &req, db_instance)
        .await
        .map_err(|err| err.to_server_fn_error())?;

    req.get_session().remove("otp");

    Ok(())
}

#[server(Login, "/api")]
pub async fn login(
    username: String,
    password: String,
    client_id: String,
    state: String,
) -> Result<String, ServerFnError<AuthError>> {
    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;
    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    // Case insensitive usernames
    let username: String = username.trim().to_lowercase();

    let user = db_instance
        .get_user_from_username(&username)
        .await
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let two_factor_enabled = handle_login(&username, password, user, req, db_instance)
        .await
        .map_err(|err| err.to_server_fn_error())?;

    if two_factor_enabled {
        return Ok(username);
    } else {
        client_helpers::user_server_side_redirect(username, client_id, state).await?;
        return Ok("".to_string());
    }
}

#[server(Signup, "/api")]
async fn signup(
    username: String,
    first_name: String,
    last_name: String,
    email: String,
    password: String,
    confirm_password: String,
    client_id: Option<String>,
    state: Option<String>,
) -> Result<(), ServerFnError<AuthError>> {
    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;
    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    handle_signup(
        &username,
        first_name,
        last_name,
        email,
        password,
        confirm_password,
        req,
        db_instance,
    )
    .await?;

    if client_id.is_none() && state.is_none() {
        leptos_actix::redirect("/user");
    } else {
        client_helpers::user_server_side_redirect(username, client_id.unwrap(), state.unwrap())
            .await?;
    }

    Ok(())
}

#[server(VerifyOtp, "/api")]
async fn verify_otp(
    username: String,
    otp: String,
    client_id: String,
    state: String,
) -> Result<(), ServerFnError<AuthError>> {
    let (req, db_instance) = get_request_data().await?;

    // Extract login_token from user session
    let login_token: String = req
        .get_session()
        .get("otp")
        .map_err(|_| AuthError::InternalServerError("Error getting session!".to_string()))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let db_user = db_instance
        .get_user_from_username(&username)
        .await
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    handle_verify_otp(&username, otp, db_user, login_token, &req, db_instance)
        .await
        .map_err(|err| err.to_server_fn_error())?;

    req.get_session().remove("otp");

    // If not redirected from another app, go to user page
    if client_id.is_empty() && state.is_empty() {
        leptos_actix::redirect("/user");
    } else {
        client_helpers::user_server_side_redirect(username, client_id, state).await?;
    }

    Ok(())
}

#[server(PasswordReset, "/api")]
pub async fn reset_password(
    username: String,
    reset_token: String,
    password: String,
    confirm_password: String,
) -> Result<(), ServerFnError<AuthError>> {
    // Get HttpRequest
    let (_, db_instance) = get_request_data().await?;

    handle_reset_password(
        username,
        reset_token,
        password,
        confirm_password,
        db_instance,
    )
    .await?;

    Ok(())
}

#[server(RequestPasswordReset, "/api")]
pub async fn request_password_reset(username: String) -> Result<(), ServerFnError<AuthError>> {
    let (_, db_instance) = get_request_data().await?;

    handle_request_password_reset(username, db_instance).await?;

    Ok(())
}

#[server(VerifyUser, "/api")]
pub async fn verify_user(
    username: String,
    verification_token: String,
) -> Result<(), ServerFnError<AuthError>> {
    let (_, db_instance) = get_request_data().await?;
    handle_verify_user(username, verification_token, db_instance).await?;
    leptos_actix::redirect("/login");
    Ok(())
}

#[server(Generate2FA, "/api")]
pub async fn generate_2fa(username: String) -> Result<(String, String), ServerFnError<AuthError>> {
    let (req, db_instance) = get_request_data().await?;

    let db_user = db_instance
        .get_user_from_username(&username)
        .await
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    if db_user.two_factor {
        return Err(
            AuthError::Error("Two Factor already enabled for user!".to_string())
                .to_server_fn_error(),
        );
    }

    let (qr_code, token) = handle_generate_2fa(username, db_user, db_instance, req).await?;

    Ok((qr_code, token))
}

#[server(Enable2FA, "/api")]
pub async fn enable_2fa(username: String, otp: String) -> Result<bool, ServerFnError<AuthError>> {
    let (req, db_instance) = get_request_data().await?;

    // Extract login_token from user session
    let two_factor_token: String = req
        .get_session()
        .get("2fa")
        .map_err(|_| AuthError::InternalServerError("Error getting session!".to_string()))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let db_user = db_instance
        .get_user_from_username(&username)
        .await
        .map_err(|err| AuthError::from(err))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    if db_user.two_factor {
        return Err(
            AuthError::Error("Two Factor already enabled for user!".to_string())
                .to_server_fn_error(),
        );
    }

    handle_enable_2fa(username, db_user, otp, two_factor_token, db_instance).await?;

    req.get_session().remove("2fa");

    Ok(true)
}

#[server(UpdatePassword, "/api")]
pub async fn change_password(
    username: String,
    current_password: String,
    password: String,
    confirm_password: String,
) -> Result<(), ServerFnError<AuthError>> {
    let (_, db_instance) = get_request_data().await?;

    handle_change_password(
        username,
        current_password,
        password,
        confirm_password,
        db_instance,
    )
    .await?;

    Ok(())
}
