use super::db_helper::DbInstance;
use super::models::NewDBVerificationToken;
use super::schema::verification_tokens;
use super::DBError;
use crate::db::models::{DBUser, DBVerificationToken};
use crate::db::schema::verification_tokens::user_id;
use crate::db::schema::{self};
use diesel::{prelude::*, select};
use encryption_libs::HashableString;
use schema::users::dsl::*;
use std::time::Duration;

impl DbInstance {
    pub fn save_verification_token_to_db(
        &self,
        uname: &String,
        vtoken: &String,
    ) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

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
                    confirm_token: HashableString::from(vtoken),
                    confirm_token_expiry: &token_expiry,
                    user_id: &user.id,
                };
                diesel::insert_into(verification_tokens::table)
                    .values(&db_verification_token)
                    .returning(DBVerificationToken::as_returning())
                    .get_result(&mut connection)?;
                Ok(())
            }
            None => Err(DBError::NotFound(uname.to_string())),
        }
    }

    pub fn get_verification_token_from_db(
        &self,
        uname: &String,
    ) -> Result<Option<DBVerificationToken>, DBError> {
        let mut connection = self.db_connection.connect()?;

        let db_user = users
            .filter(username.eq(uname))
            .select(DBUser::as_select())
            .get_result(&mut connection)?;

        let pass_reset_token = DBVerificationToken::belonging_to(&db_user)
            .limit(1)
            .select(DBVerificationToken::as_select())
            .first(&mut connection)
            .optional()?;

        Ok(pass_reset_token)
    }

    pub fn delete_db_verification_token(&self, uname: &String) -> Result<usize, DBError> {
        let mut connection = self.db_connection.connect()?;

        let db_user: Option<DBUser> = users
            .filter(username.eq(uname))
            .limit(1)
            .select(DBUser::as_select())
            .first(&mut connection)
            .optional()?;

        match db_user {
            Some(user) => diesel::delete(verification_tokens::table.filter(user_id.eq(user.id)))
                .execute(&mut connection)
                .map_err(DBError::from),
            None => Err(DBError::NotFound(uname.to_string())),
        }
    }
}
