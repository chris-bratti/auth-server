use crate::db::models::{DBResetToken, DBUser, NewDBResetToken};
use crate::db::schema::password_reset_tokens::user_id;
use crate::db::schema::{self, password_reset_tokens};
use crate::db::users_db::establish_connection;
use diesel::{prelude::*, select};
use std::time::Duration;

pub fn get_reset_token_from_db(
    uname: &String,
) -> Result<Option<DBResetToken>, diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    let db_user = users
        .filter(username.eq(uname))
        .select(DBUser::as_select())
        .get_result(&mut connection)?;

    let pass_reset_token = DBResetToken::belonging_to(&db_user)
        .limit(1)
        .select(DBResetToken::as_select())
        .first(&mut connection)
        .optional()?;

    Ok(pass_reset_token)
}

pub fn save_reset_token_to_db(
    uname: &String,
    rtoken: &String,
) -> Result<(), diesel::result::Error> {
    use schema::users::dsl::*;

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
            let db_reset_token = NewDBResetToken {
                reset_token: rtoken,
                reset_token_expiry: &token_expiry,
                user_id: &user.id,
            };
            diesel::insert_into(password_reset_tokens::table)
                .values(&db_reset_token)
                .returning(DBResetToken::as_returning())
                .get_result(&mut connection)?;
            Ok(())
        }
        None => Err(diesel::result::Error::NotFound),
    }
}

pub fn delete_db_reset_token(uname: &String) -> Result<usize, diesel::result::Error> {
    use schema::users::dsl::*;

    let mut connection = establish_connection();

    let db_user: Option<DBUser> = users
        .filter(username.eq(uname))
        .limit(1)
        .select(DBUser::as_select())
        .first(&mut connection)
        .optional()?;

    match db_user {
        Some(user) => diesel::delete(password_reset_tokens::table.filter(user_id.eq(user.id)))
            .execute(&mut connection),
        None => Err(diesel::result::Error::NotFound),
    }
}
