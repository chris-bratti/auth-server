use crate::db::db_helper::establish_connection;
use crate::db::models::{DBResetToken, DBUser, NewDBResetToken};
use crate::db::schema::password_reset_tokens::user_id;
use crate::db::schema::{self, password_reset_tokens};
use crate::DBError;
use diesel::{prelude::*, select};
use schema::users::dsl::*;
use std::time::Duration;

pub fn get_reset_token_from_db(uname: &String) -> Result<Option<DBResetToken>, DBError> {
    let mut connection = establish_connection()?;

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

pub fn save_reset_token_to_db(uname: &String, rtoken: &String) -> Result<(), DBError> {
    let mut connection = establish_connection()?;

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
        None => Err(DBError::NotFound(uname.to_string())),
    }
}

pub fn delete_db_reset_token(uname: &String) -> Result<usize, DBError> {
    let mut connection = establish_connection()?;

    let db_user: Option<DBUser> = users
        .filter(username.eq(uname))
        .limit(1)
        .select(DBUser::as_select())
        .first(&mut connection)
        .optional()?;

    match db_user {
        Some(user) => diesel::delete(password_reset_tokens::table.filter(user_id.eq(user.id)))
            .execute(&mut connection)
            .map_err(DBError::from),
        None => Err(DBError::NotFound(uname.to_string())),
    }
}
