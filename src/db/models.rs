use std::time::SystemTime;

use crate::db::schema::*;
use auto_encryption::Encryptable;
use diesel::prelude::*;
use encryption_libs::Encryptable;
use encryption_libs::EncryptionKey;

#[derive(Queryable, Selectable, Identifiable, Debug, Encryptable)]
#[diesel(table_name = crate::db::schema::admins)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AppAdmin {
    pub id: i32,
    pub username: String,
    #[encrypted(EncryptionKey::SmtpKey)]
    pub email: String,
    #[hashed]
    pub pass_hash: String,
    pub initialized: bool,
    pub two_factor_token: Option<String>,
    pub locked: bool,
    pub pass_retries: Option<i32>,
    pub last_failed_attempt: Option<SystemTime>,
}

#[derive(Insertable, Debug, Encryptable)]
#[diesel(table_name = admins)]
pub struct NewAppAdmin {
    pub username: String,
    #[encrypted(EncryptionKey::SmtpKey)]
    pub email: String,
    #[hashed]
    pub pass_hash: String,
    pub initialized: bool,
    pub locked: bool,
}

#[derive(Queryable, Selectable, Identifiable, Debug, Encryptable)]
#[diesel(table_name = crate::db::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DBUser {
    pub id: i32,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    #[encrypted(EncryptionKey::SmtpKey)]
    pub email: String,
    #[hashed]
    pub pass_hash: String,
    pub verified: bool,
    pub two_factor: bool,
    #[encrypted(EncryptionKey::TwoFactorKey)]
    pub two_factor_token: Option<String>,
    pub locked: bool,
    pub pass_retries: Option<i32>,
    pub last_failed_attempt: Option<SystemTime>,
}

#[derive(
    Queryable, Selectable, Identifiable, Debug, serde::Deserialize, serde::Serialize, Encryptable,
)]
#[diesel(table_name = crate::db::schema::oauth_clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OauthClient {
    pub id: i32,
    pub app_name: String,
    #[encrypted(EncryptionKey::SmtpKey)]
    pub contact_email: String,
    pub client_id: String,
    #[hashed]
    pub client_secret: String,
    pub redirect_url: String,
    pub approved: bool,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq, Encryptable)]
#[diesel(table_name = refresh_tokens)]
#[diesel(belongs_to(OauthClient, foreign_key = client_id))]
pub struct RefreshToken {
    pub client_id: i32,
    pub id: i32,
    #[encrypted(EncryptionKey::OauthKey)]
    pub refresh_token: String,
    pub token_id: String,
    pub username: String,
    pub expiry: SystemTime,
}

#[derive(Insertable, Debug, Encryptable)]
#[diesel(table_name = refresh_tokens)]
pub struct NewRefreshToken<'a> {
    pub client_id: &'a i32,
    #[encrypted(EncryptionKey::OauthKey)]
    pub refresh_token: String,
    pub token_id: &'a str,
    pub username: &'a str,
    pub expiry: &'a SystemTime,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq, Encryptable)]
#[diesel(table_name = password_reset_tokens)]
#[diesel(belongs_to(DBUser, foreign_key = user_id))]
pub struct DBResetToken {
    pub user_id: i32,
    pub id: i32,
    #[hashed]
    pub reset_token: String,
    pub reset_token_expiry: SystemTime,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq, Encryptable)]
#[diesel(table_name = verification_tokens)]
#[diesel(belongs_to(DBUser, foreign_key = user_id))]
pub struct DBVerificationToken {
    pub user_id: i32,
    pub id: i32,
    #[hashed]
    pub confirm_token: String,
    pub confirm_token_expiry: SystemTime,
}

#[derive(Insertable, Debug, Encryptable)]
#[diesel(table_name = verification_tokens)]
pub struct NewDBVerificationToken<'a> {
    #[hashed]
    pub confirm_token: String,
    pub confirm_token_expiry: &'a SystemTime,
    pub user_id: &'a i32,
}

#[derive(Insertable, Debug, Encryptable)]
#[diesel(table_name = password_reset_tokens)]
pub struct NewDBResetToken<'a> {
    #[hashed]
    pub reset_token: String,
    pub reset_token_expiry: &'a SystemTime,
    pub user_id: &'a i32,
}

#[derive(Insertable, Debug, Encryptable)]
#[diesel(table_name = users)]
pub struct NewDBUser<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub username: &'a str,
    #[encrypted(EncryptionKey::SmtpKey)]
    pub email: String,
    #[hashed]
    pub pass_hash: String,
    pub verified: &'a bool,
    pub two_factor: &'a bool,
    pub locked: &'a bool,
}

#[derive(Insertable, Debug, Encryptable)]
#[diesel(table_name = oauth_clients)]
pub struct NewOauthClient<'a> {
    pub app_name: &'a str,
    #[encrypted[EncryptionKey::SmtpKey]]
    pub contact_email: String,
    pub client_id: &'a str,
    #[hashed]
    pub client_secret: String,
    pub redirect_url: &'a str,
    pub approved: &'a bool,
}
