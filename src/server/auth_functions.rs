use core::{option::Option::None, result::Result::Ok};
use std::{collections::HashMap, env};

use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

use actix_web::{web, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use dotenvy::dotenv;
use redis::{Client, Commands};

use crate::{db::db_helper::DbInstance, Claims, DBError, DatabaseUser};
use crate::{AuthError, EncryptionKey, OauthClaims};
use totp_rs::{Algorithm, Secret, TOTP};

use regex::Regex;

use lazy_static::lazy_static;

use super::oauth_handlers::handle_reload_oauth_clients;

lazy_static! {
    static ref JWT_SECRET: String = get_env_variable("JWT_KEY").expect("JWT_KEY is unset!");
}

pub fn get_env_variable(variable: &str) -> Option<String> {
    match std::env::var(variable) {
        Ok(env_variable) => Some(env_variable.trim().to_string()),
        Err(_) => {
            dotenv().ok();

            match env::var(variable) {
                Ok(var_from_file) => Some(var_from_file.trim().to_string()),
                Err(_) => None,
            }
        }
    }
}

pub fn get_totp_config(username: &String, token: &String) -> TOTP {
    let app_name = get_env_variable("APP_NAME").expect("APP_NAME is unset!");
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(token.as_bytes().to_vec()).to_bytes().unwrap(),
        Some(app_name),
        username.to_string(),
    )
    .unwrap()
}

pub async fn create_2fa_for_user(username: &String) -> Result<(String, String), AuthError> {
    let token = generate_token();
    let totp = get_totp_config(username, &token);
    let qr_code = totp.get_qr_base64().expect("Error generating QR code");
    Ok((qr_code, token))
}

pub async fn get_totp(username: &String, two_factor_token: &String) -> Result<String, AuthError> {
    let decrypted_token = decrypt_string(&two_factor_token, EncryptionKey::TwoFactorKey)
        .await
        .expect("Error decrypting string!");
    get_totp_config(&username, &decrypted_token)
        .generate_current()
        .map_err(|err| AuthError::InternalServerError(err.to_string()))
}

/// Hash password with Argon2
pub async fn hash_string(password: &String) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}

/// Verifies password against hash
pub fn verify_hash(
    password: &String,
    password_hash: &String,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(&password_hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Server side password strength validation
pub fn check_valid_password(password: &String) -> bool {
    // Rust's Regex crate does not support Lookahead matching, so have to break criteria into multiple patterns
    let contains_digit = Regex::new("\\d+").expect("Error parsing regex");
    let contains_capital = Regex::new("[A-Z]+").expect("Error parsing regex");
    let contains_special = Regex::new("[!:@#$^;%&?]+").expect("Error parsing regex");

    let valid = contains_digit.is_match(password)
        && contains_capital.is_match(password)
        && contains_special.is_match(password);

    valid && password.len() >= 8 && password.len() <= 24
}

pub fn generate_token() -> String {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();

    let generated_token: String = (&mut rng)
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    generated_token
}

pub fn verify_reset_token(
    username: &String,
    reset_token: &String,
    db: &web::Data<DbInstance>,
) -> Result<bool, AuthError> {
    let token_hash = db
        .get_reset_hash(username)
        .map_err(|err| AuthError::Error(err.to_string()))?;

    verify_hash(reset_token, &token_hash).map_err(|_| AuthError::InvalidToken)
}

pub fn verify_confirmation_token(
    username: &String,
    confirmation_token: &String,
    db: &web::Data<DbInstance>,
) -> Result<bool, AuthError> {
    let verification_hash = db
        .get_verification_hash(username)
        .map_err(|_| AuthError::InvalidToken)?;

    verify_hash(confirmation_token, &verification_hash).map_err(|_| AuthError::InvalidToken)
}

pub async fn encrypt_string(
    data: &String,
    encryption_key: EncryptionKey,
) -> Result<String, aes_gcm::Error> {
    let encryption_key = encryption_key.get();

    let key = Key::<Aes256Gcm>::from_slice(&encryption_key.as_bytes());

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data.as_bytes())?;

    let mut encrypted_data: Vec<u8> = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);

    let output = hex::encode(encrypted_data);
    Ok(output)
}

pub async fn decrypt_string(
    encrypted: &String,
    encryption_key: EncryptionKey,
) -> Result<String, aes_gcm::Error> {
    let encryption_key = encryption_key.get();

    let encrypted_data = hex::decode(encrypted).expect("failed to decode hex string into vec");

    let key = Key::<Aes256Gcm>::from_slice(encryption_key.as_bytes());

    // 12 digit nonce is prepended to encrypted data. Split nonce from encrypted email
    let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_arr);

    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphered_data)
        .expect("failed to decrypt data");

    Ok(String::from_utf8(plaintext).expect("failed to convert vector of bytes to string"))
}

pub async fn generate_oauth_token(
    token_id: &String,
    exp: i64,
    username: &String,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = OauthClaims {
        exp,
        scope: "read write".to_string(),
        iss: "Auth Server".to_string(),
        sub: username.clone(),
        client_id: token_id.clone(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_ref()),
    )?;

    Ok(token)
}

pub async fn validate_oauth_token(
    oauth_token: String,
    redis_client: &web::Data<Client>,
    username: &String,
) -> Result<bool, AuthError> {
    let mut connection = redis_client.get_connection()?;

    let token: OauthClaims = decode::<OauthClaims>(
        &oauth_token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)?
    .claims;

    if &token.sub != username {
        return Err(AuthError::InvalidCredentials);
    }

    let client_secret: Option<String> = connection.hget("oauth_clients", &token.client_id)?;

    if client_secret.is_none()
        || token.scope != "read write".to_string()
        || token.iss != "Auth Server".to_string()
    {
        return Err(AuthError::InvalidCredentials);
    }

    Ok(true)
}

pub async fn generate_jwt_token(
    token_id: &String,
    scope: String,
    timeout: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let utc_timestamp = chrono::Utc::now().timestamp();

    let claims = Claims {
        exp: utc_timestamp + timeout,
        scope,
        sub: token_id.clone(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_ref()),
    )?;

    Ok(token)
}

pub async fn validate_pending_token(
    username: &String,
    pending_token: String,
    scope: String,
    db: &web::Data<DbInstance>,
) -> Result<(), AuthError> {
    let token = decode::<Claims>(
        &pending_token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)?
    .claims;

    if &token.sub != username {
        return Err(AuthError::InvalidCredentials);
    }

    let user_exists = if db.does_user_exist(&token.sub).await? {
        true
    } else {
        db.does_admin_exist(&token.sub).await?
    };

    if token.scope == scope && user_exists {
        Ok(())
    } else {
        Err(AuthError::TOTPError)
    }
}

pub async fn load_oauth_clients(
    db: &web::Data<DbInstance>,
) -> Result<HashMap<String, (String, String)>, AuthError> {
    let clients = db
        .get_oauth_clients()
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?
        .unwrap_or_default()
        .into_iter()
        .map(|c| (c.client_id, (c.client_secret, c.redirect_url)))
        .collect();

    Ok(clients)
}

pub async fn is_user_locked<T>(db_user: &T) -> Result<bool, DBError>
where
    T: DatabaseUser,
{
    if db_user.is_locked() {
        let timestamp: DateTime<Utc> =
            DateTime::from(db_user.last_failed_attempt().expect("No timestamp!"));

        // Get the current time
        let current_time = Utc::now();

        // Calculate the difference in minutes
        let minutes_since_last_attempt =
            current_time.signed_duration_since(timestamp).num_minutes();

        if minutes_since_last_attempt > 10 {
            return Ok(false);
        }
    }
    Ok(db_user.is_locked())
}

pub async fn approve_oauth_client(
    client_id: &String,
    redis_client: &web::Data<Client>,
    db_instance: &web::Data<DbInstance>,
) -> Result<(), AuthError> {
    db_instance.approve_oauth_client(&client_id)?;
    handle_reload_oauth_clients(&db_instance, &redis_client).await?;

    Ok(())
}

#[cfg(test)]
mod test_auth {

    use core::{assert_eq, assert_ne};

    use crate::{check_valid_password, decrypt_string, verify_hash, EncryptionKey};

    use super::{encrypt_string, get_totp_config, hash_string};

    #[tokio::test]
    async fn test_password_hashing() {
        let password = "whatALovelyL!ttleP@s$w0rd".to_string();

        let hashed_password = hash_string(&password.clone()).await;

        assert!(hashed_password.is_ok());

        let hashed_password = hashed_password.unwrap();

        assert_ne!(password, hashed_password);

        let pass_match = verify_hash(&password, &hashed_password);

        assert!(pass_match.is_ok());

        assert_eq!(pass_match.unwrap(), true);
    }

    #[tokio::test]
    async fn test_email_encryption() {
        let email = String::from("test@test.com");
        let encrypted_email = encrypt_string(&email, EncryptionKey::SmtpKey)
            .await
            .expect("There was an error encrypting");

        assert_ne!(encrypted_email, email);

        let decrypted_email = decrypt_string(&encrypted_email, EncryptionKey::SmtpKey)
            .await
            .expect("There was an error decrypting");

        assert_eq!(email, decrypted_email);
    }

    #[tokio::test]
    async fn test_log_encryption() {
        let username = String::from("testuser123");
        let encrypted_username = encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("There was an error encrypting!");

        assert_ne!(encrypted_username, username);

        let decrypted_username = decrypt_string(&encrypted_username, EncryptionKey::LoggerKey)
            .await
            .expect("There was an error decrypting!");

        assert_eq!(username, decrypted_username);
    }

    #[test]
    fn test_password_validation() {
        let valid_password = String::from("Password123!");

        assert!(check_valid_password(&valid_password));

        let valid_password = String::from("g00dP@ssw0rd2");

        assert!(check_valid_password(&valid_password));

        let invalid_password = String::from("password2");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("Thispasswordislongerthanwhatisallowed222222!!!!!");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("$H0rt");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("nocapital123!");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("noSpecial1112");

        assert!(!check_valid_password(&invalid_password));

        let invalid_password = String::from("noNumbers!!");

        assert!(!check_valid_password(&invalid_password));
    }

    #[test]
    fn test_totp() {
        let token = "TestSecretSuperSecret".to_string();
        let username = "exampleuser".to_string();

        let totp1 = get_totp_config(&username, &token);

        let totp2 = get_totp_config(&username, &token);

        let otp1 = totp1.generate_current().expect("Error generating OTP");

        let otp2 = totp2.generate_current().expect("Error generating OTP");

        assert_eq!(otp1, otp2);
    }
}
