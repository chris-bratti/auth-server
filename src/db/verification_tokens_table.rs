use super::models::NewDBVerificationToken;
use super::schema::verification_tokens;
use super::users_db::establish_connection;
use crate::db::models::{DBUser, DBVerificationToken};
use crate::db::schema::verification_tokens::user_id;
use crate::db::schema::{self};
use diesel::{prelude::*, select};
use schema::users::dsl::*;
use std::time::Duration;

pub fn save_verification_token_to_db(
    uname: &String,
    vtoken: &String,
) -> Result<(), diesel::result::Error> {
    let mut connection = establish_connection();

    let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut connection)?;

    // Gets 20 minutes from current time
    let token_expiry = now
        .checked_add(Duration::new(1200, 0))
        .expect("Error parsing time");

    let db_user: Option<DBUser> = users
        .filter(username.eq(uname))
        .limit(1)
        .select(DBUser::as_select())
        .first(&mut connection)
        .optional()?;

    match db_user {
        Some(user) => {
            let db_verification_token = NewDBVerificationToken {
                confirm_token: vtoken,
                confirm_token_expiry: &token_expiry,
                user_id: &user.id,
            };
            diesel::insert_into(verification_tokens::table)
                .values(&db_verification_token)
                .returning(DBVerificationToken::as_returning())
                .get_result(&mut connection)?;
            Ok(())
        }
        None => Err(diesel::result::Error::NotFound),
    }
}

pub fn get_verification_token_from_db(
    uname: &String,
) -> Result<Option<DBVerificationToken>, diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    let db_user = users
        .filter(username.eq(uname))
        .select(DBUser::as_select())
        .get_result(&mut connection)?;

    // get pages for a book
    let pass_reset_token = DBVerificationToken::belonging_to(&db_user)
        .limit(1)
        .select(DBVerificationToken::as_select())
        .first(&mut connection)
        .optional()?;

    Ok(pass_reset_token)
}

pub fn delete_db_verification_token(uname: &String) -> Result<usize, diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    let db_user: Option<DBUser> = users
        .filter(username.eq(uname))
        .limit(1)
        .select(DBUser::as_select())
        .first(&mut connection)
        .optional()?;

    match db_user {
        Some(user) => diesel::delete(verification_tokens::table.filter(user_id.eq(user.id)))
            .execute(&mut connection),
        None => Err(diesel::result::Error::NotFound),
    }
}
