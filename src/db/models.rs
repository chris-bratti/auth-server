use std::time::SystemTime;

use crate::db::schema::*;
use diesel::prelude::*;
use encryption_libs::{EncryptableString, HashableString};

#[derive(Queryable, Selectable, Identifiable, Debug)]
#[diesel(table_name = crate::db::schema::admins)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AppAdmin {
    pub id: i32,
    pub username: String,
    pub email: EncryptableString,
    pub pass_hash: HashableString,
    pub initialized: bool,
    pub two_factor_token: Option<EncryptableString>,
    pub locked: bool,
    pub pass_retries: Option<i32>,
    pub last_failed_attempt: Option<SystemTime>,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = admins)]
pub struct NewAppAdmin {
    pub username: String,
    pub email: EncryptableString,
    pub pass_hash: HashableString,
    pub initialized: bool,
    pub locked: bool,
}

#[derive(Queryable, Selectable, Identifiable, Debug)]
#[diesel(table_name = crate::db::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DBUser {
    pub id: i32,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: EncryptableString,
    pub pass_hash: HashableString,
    pub verified: bool,
    pub two_factor: bool,
    pub two_factor_token: Option<EncryptableString>,
    pub locked: bool,
    pub pass_retries: Option<i32>,
    pub last_failed_attempt: Option<SystemTime>,
}

#[derive(Queryable, Selectable, Identifiable, Debug, serde::Deserialize, serde::Serialize)]
#[diesel(table_name = crate::db::schema::oauth_clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OauthClient {
    pub id: i32,
    pub app_name: String,
    pub contact_email: EncryptableString,
    pub client_id: String,
    pub client_secret: EncryptableString,
    pub redirect_url: String,
    pub approved: bool,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(table_name = refresh_tokens)]
#[diesel(belongs_to(OauthClient, foreign_key = client_id))]
pub struct RefreshToken {
    pub client_id: i32,
    pub id: i32,
    pub refresh_token: EncryptableString,
    pub token_id: String,
    pub username: String,
    pub expiry: SystemTime,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = refresh_tokens)]
pub struct NewRefreshToken<'a> {
    pub client_id: &'a i32,
    pub refresh_token: EncryptableString,
    pub token_id: &'a str,
    pub username: &'a str,
    pub expiry: &'a SystemTime,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(table_name = password_reset_tokens)]
#[diesel(belongs_to(DBUser, foreign_key = user_id))]
pub struct DBResetToken {
    pub user_id: i32,
    pub id: i32,
    pub reset_token: HashableString,
    pub reset_token_expiry: SystemTime,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(table_name = verification_tokens)]
#[diesel(belongs_to(DBUser, foreign_key = user_id))]
pub struct DBVerificationToken {
    pub user_id: i32,
    pub id: i32,
    pub confirm_token: HashableString,
    pub confirm_token_expiry: SystemTime,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = verification_tokens)]
pub struct NewDBVerificationToken<'a> {
    pub confirm_token: HashableString,
    pub confirm_token_expiry: &'a SystemTime,
    pub user_id: &'a i32,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = password_reset_tokens)]
pub struct NewDBResetToken<'a> {
    pub reset_token: HashableString,
    pub reset_token_expiry: &'a SystemTime,
    pub user_id: &'a i32,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewDBUser<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub username: &'a str,
    pub email: EncryptableString,
    pub pass_hash: HashableString,
    pub verified: &'a bool,
    pub two_factor: &'a bool,
    pub locked: &'a bool,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = oauth_clients)]
pub struct NewOauthClient<'a> {
    pub app_name: &'a str,
    pub contact_email: EncryptableString,
    pub client_id: &'a str,
    pub client_secret: EncryptableString,
    pub redirect_url: &'a str,
    pub approved: &'a bool,
}
