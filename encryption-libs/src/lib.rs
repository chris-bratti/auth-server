use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use diesel::{
    backend::Backend,
    deserialize::{FromSql, FromSqlRow},
    expression::AsExpression,
    serialize::ToSql,
    sql_types::Text,
};
use dotenvy::dotenv;
use quote::{ToTokens, quote};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fmt::{self},
};
use zeroize::{Zeroize, Zeroizing};

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

#[derive(Clone, FromSqlRow, AsExpression, Serialize, Deserialize)]
#[diesel(sql_type = Text)]
pub struct HashableString {
    value: String,
}

impl HashableString {
    pub fn from_str(value: &str) -> Self {
        HashableString::from(value.to_string())
    }

    pub fn get(&self) -> &String {
        &self.value
    }

    pub fn verify(&self, mut value: String) -> Result<bool, argon2::password_hash::Error> {
        let result = verify_hash(&value, &self.value)?;
        value.zeroize();
        Ok(result)
    }

    pub fn eq_hash(&self, hash: &String) -> bool {
        &self.value == hash
    }
}

impl From<String> for HashableString {
    fn from(mut value: String) -> Self {
        let hashed_value = hash_field(&value).unwrap();
        value.zeroize();
        HashableString {
            value: hashed_value,
        }
    }
}

impl From<&String> for HashableString {
    fn from(value: &String) -> Self {
        let owned = value.to_owned();
        HashableString::from(owned)
    }
}

impl fmt::Debug for HashableString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashableString")
            .field("value", &"**hashed**")
            .finish()
    }
}

impl fmt::Display for HashableString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "**hashed**")
    }
}

impl PartialEq for HashableString {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
    }
}

#[derive(Clone, FromSqlRow, AsExpression, Serialize, Deserialize)]
#[diesel(sql_type = Text)]
pub struct EncryptableString {
    encrypted_value: String,
}

impl EncryptableString {
    pub fn from_str(value: &str) -> Self {
        EncryptableString::from(value.to_string())
    }

    pub fn get(&self) -> &String {
        &self.encrypted_value
    }

    pub fn get_decrypted(&self) -> Zeroizing<String> {
        let decrypted = decrypt_string(&self.encrypted_value, EncryptionKey::SmtpKey).unwrap();
        Zeroizing::new(decrypted)
    }

    pub fn eq_encrypted(&self, val: &String) -> bool {
        &self.encrypted_value == val
    }

    pub fn eq_decrypted(&self, val: &String) -> bool {
        &self.get_decrypted().to_string() == val
    }
}

impl From<String> for EncryptableString {
    fn from(value: String) -> Self {
        let encrypted_value = encrypt_string(&value.to_string(), EncryptionKey::SmtpKey).unwrap();
        EncryptableString { encrypted_value }
    }
}

impl From<&String> for EncryptableString {
    fn from(value: &String) -> Self {
        let owned = value.to_owned();
        EncryptableString::from(owned)
    }
}

impl fmt::Display for EncryptableString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "**encrypted**")
    }
}

impl fmt::Debug for EncryptableString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptableString")
            .field("encrypted_value", &self.encrypted_value)
            .finish()
    }
}

impl PartialEq for EncryptableString {
    fn eq(&self, other: &Self) -> bool {
        self.encrypted_value == other.encrypted_value
    }

    fn ne(&self, other: &Self) -> bool {
        !self.eq(other)
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

impl<DB: Backend> ToSql<Text, DB> for EncryptableString
where
    String: ToSql<Text, DB>,
{
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, DB>,
    ) -> diesel::serialize::Result {
        self.encrypted_value.to_sql(out)
    }
}

impl<DB: Backend> FromSql<Text, DB> for EncryptableString
where
    String: FromSql<Text, DB>,
{
    fn from_sql(bytes: <DB as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        let encrypted_value = String::from_sql(bytes)?;
        Ok(EncryptableString { encrypted_value })
    }
}

impl<DB: Backend> ToSql<Text, DB> for HashableString
where
    String: ToSql<Text, DB>,
{
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, DB>,
    ) -> diesel::serialize::Result {
        self.value.to_sql(out)
    }
}

impl<DB: Backend> FromSql<Text, DB> for HashableString
where
    String: FromSql<Text, DB>,
{
    fn from_sql(bytes: <DB as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        let value = String::from_sql(bytes)?;
        Ok(HashableString { value })
    }
}
