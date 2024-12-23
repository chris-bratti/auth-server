use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use dotenvy::dotenv;
use quote::{ToTokens, quote};
use std::env;

#[macro_export]
macro_rules! encrypt_log {
    ($fmt:expr, $($arg:tt)*) => {
        {
            let formatted_message = format!($fmt, $($arg)*);

            let encrypted_value = encrypt_string($($arg)*, EncryptionKey::LoggerKey).unwrap();

            println!($fmt, encrypted_value);
        }
    };
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

impl ToTokens for EncryptionKey {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let token = match self {
            EncryptionKey::SmtpKey => quote! { EncryptionKey::SmtpKey },
            EncryptionKey::TwoFactorKey => quote! { EncryptionKey::TwoFactorKey },
            EncryptionKey::LoggerKey => quote! { EncryptionKey::LoggerKey },
            EncryptionKey::OauthKey => quote! { EncryptionKey::OauthKey },
        };
        tokens.extend(token);
    }
}

impl From<&String> for EncryptionKey {
    fn from(value: &String) -> Self {
        match value.to_lowercase().as_str() {
            "smtpkey" => EncryptionKey::SmtpKey,
            "twofactorkey" => EncryptionKey::TwoFactorKey,
            "loggerkey" => EncryptionKey::LoggerKey,
            "oauthkey" => EncryptionKey::OauthKey,
            _ => EncryptionKey::TwoFactorKey,
        }
    }
}

pub enum EncryptionKey {
    SmtpKey,
    TwoFactorKey,
    LoggerKey,
    OauthKey,
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

pub struct HashableString {
    pub hashed: bool,
    pub value: String,
}

#[derive(Debug)]
pub struct EncryptableString {
    pub encrypted: bool,
    pub value: String,
}

impl EncryptableString {
    pub fn from(value: &str) -> Self {
        EncryptableString {
            encrypted: false,
            value: value.to_string(),
        }
    }
}

impl From<String> for EncryptableString {
    fn from(value: String) -> Self {
        EncryptableString {
            encrypted: false,
            value,
        }
    }
}

pub trait Encryptable {
    fn encrypt(&mut self);
    fn decrypt(&mut self);
}

pub fn encrypt_string(
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

pub fn decrypt_string(
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

/// Hash password with Argon2
pub fn hash_field(password: &String) -> Result<String, argon2::password_hash::Error> {
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
