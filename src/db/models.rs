use std::time::SystemTime;

use crate::db::schema::*;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Identifiable, Debug)]
#[diesel(table_name = crate::db::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DBUser {
    pub id: i32,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: String,
    pub pass_hash: String,
    pub verified: bool,
    pub two_factor: bool,
    pub two_factor_token: Option<String>,
    pub locked: bool,
    pub pass_retries: Option<i32>,
    pub last_failed_attempt: Option<SystemTime>,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(table_name = password_reset_tokens)]
#[diesel(belongs_to(DBUser, foreign_key = user_id))]
pub struct DBResetToken {
    pub user_id: i32,
    pub id: i32,
    pub reset_token: String,
    pub reset_token_expiry: SystemTime,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(table_name = verification_tokens)]
#[diesel(belongs_to(DBUser, foreign_key = user_id))]
pub struct DBVerificationToken {
    pub user_id: i32,
    pub id: i32,
    pub confirm_token: String,
    pub confirm_token_expiry: SystemTime,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = verification_tokens)]
pub struct NewDBVerificationToken<'a> {
    pub confirm_token: &'a str,
    pub confirm_token_expiry: &'a SystemTime,
    pub user_id: &'a i32,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = password_reset_tokens)]
pub struct NewDBResetToken<'a> {
    pub reset_token: &'a str,
    pub reset_token_expiry: &'a SystemTime,
    pub user_id: &'a i32,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewDBUser<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub username: &'a str,
    pub email: &'a str,
    pub pass_hash: &'a str,
    pub verified: &'a bool,
    pub two_factor: &'a bool,
    pub locked: &'a bool,
}
