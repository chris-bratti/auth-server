use std::env;

use dotenvy::dotenv;

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

impl From<String> for EncryptionKey {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "smtp" => EncryptionKey::SmtpKey,
            "twofactor" => EncryptionKey::TwoFactorKey,
            "logger" => EncryptionKey::LoggerKey,
            "oauth" => EncryptionKey::OauthKey,
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

pub trait AutoEncryption {
    fn encrypt(&self) -> Self;
    fn decrypt(&self) -> Self;
}

pub fn test_encryption(val: &String) -> String {
    String::from("encrypted")
}

pub fn test_decryption(val: &String) -> String {
    String::from("decrypted")
}

pub fn encrypt_value(val: String, key: EncryptionKey) -> String {
    eprintln!("Encrypting {val} with {:#?}", key.get());
    String::from("Blah blah")
}

pub fn decrypt_value(val: String, key: EncryptionKey) -> String {
    eprintln!("Decrypting {val} with {:#?}", key.get());
    String::from("Blah blah")
}
