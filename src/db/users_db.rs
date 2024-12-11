use crate::db::models::{DBUser, NewDBUser};
use crate::db::schema::{self};
use crate::{DBError, UserInfo};
use chrono::{DateTime, Utc};
use diesel::{prelude::*, select};
use schema::users::dsl::*;

use super::db_helper::DbInstance;
use super::schema::users;

impl DbInstance {
    pub fn create_db_user(&self, user_info: UserInfo) -> Result<DBUser, DBError> {
        let mut conn = self.db_connection.connect()?;
        let new_user = NewDBUser {
            first_name: &user_info.first_name,
            last_name: &user_info.last_name,
            username: &user_info.username,
            pass_hash: &user_info.pass_hash,
            email: &user_info.email,
            verified: &false,
            two_factor: &false,
            locked: &false,
        };

        diesel::insert_into(users::table)
            .values(&new_user)
            .returning(DBUser::as_returning())
            .get_result(&mut conn)
            .map_err(|err| DBError::Error(format!("Error creating user {}", err)))
    }

    pub fn get_user_from_username(&self, uname: &String) -> Result<Option<DBUser>, DBError> {
        let mut connection = self.db_connection.connect()?;

        users
            .filter(username.eq(uname))
            .limit(1)
            .select(DBUser::as_select())
            .first(&mut connection)
            .optional()
            .map_err(DBError::from)
    }

    pub fn unlock_db_user(&self, uname: &String) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(users.filter(username.eq(uname)))
            .set((locked.eq(false), pass_retries.eq(0)))
            .returning(DBUser::as_returning())
            .get_result(&mut connection)
            .map_err(DBError::from)?;

        Ok(())
    }

    // Increments password retries and returns if the user is locked or not
    // Should probably move this logic to the db_helper for consistency
    pub fn increment_db_password_tries(&self, uname: &String) -> Result<bool, DBError> {
        let mut connection = self.db_connection.connect()?;
        let current_time =
            select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut connection)?;

        let db_user = users
            .filter(username.eq(uname))
            .limit(1)
            .select(DBUser::as_select())
            .first(&mut connection)?;

        let incremented_password_retries = db_user.pass_retries.unwrap_or(0) + 1;

        if incremented_password_retries >= 5 {
            let last_attempt = db_user.last_failed_attempt.expect("No timestamp");

            let timestamp: DateTime<Utc> = DateTime::from(last_attempt);

            // Get the current time
            let current_time_utc: DateTime<Utc> = DateTime::from(current_time);

            // Calculate the difference in minutes
            let minutes_since_failed = current_time_utc
                .signed_duration_since(timestamp)
                .num_minutes();

            if minutes_since_failed < 10 {
                diesel::update(users.filter(username.eq(uname)))
                    .set(locked.eq(true))
                    .returning(DBUser::as_returning())
                    .get_result(&mut connection)?;
                return Ok(false);
            }
        }

        diesel::update(users.filter(username.eq(uname)))
            .set((
                pass_retries.eq(incremented_password_retries),
                last_failed_attempt.eq(current_time),
            ))
            .returning(DBUser::as_returning())
            .get_result(&mut connection)?;

        Ok(true)
    }

    pub fn enable_2fa_for_db_user(&self, uname: &String) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(users.filter(username.eq(uname)))
            .set(two_factor.eq(true))
            .returning(DBUser::as_returning())
            .get_result(&mut connection)?;

        Ok(())
    }

    pub fn set_2fa_token_for_db_user(
        &self,
        uname: &String,
        tf_token: &String,
    ) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(users.filter(username.eq(uname)))
            .set(two_factor_token.eq(tf_token))
            .returning(DBUser::as_returning())
            .get_result(&mut connection)?;

        Ok(())
    }

    pub fn set_db_user_as_verified(&self, uname: &String) -> Result<DBUser, DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(users.filter(username.eq(uname)))
            .set(verified.eq(true))
            .returning(DBUser::as_returning())
            .get_result(&mut connection)
            .map_err(DBError::from)
    }

    pub fn update_db_username(
        &self,
        uname: &String,
        new_uname: &String,
    ) -> Result<DBUser, DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(users.filter(username.eq(uname)))
            .set(username.eq(new_uname))
            .returning(DBUser::as_returning())
            .get_result(&mut connection)
            .map_err(DBError::from)
    }

    pub fn update_db_password(&self, uname: &String, new_pass: &String) -> Result<DBUser, DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(users.filter(username.eq(uname)))
            .set(pass_hash.eq(new_pass))
            .returning(DBUser::as_returning())
            .get_result(&mut connection)
            .map_err(DBError::from)
    }

    pub fn delete_db_user(&self, uname: &String) -> Result<usize, DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::delete(users.filter(username.eq(uname)))
            .execute(&mut connection)
            .map_err(DBError::from)
    }
}

#[cfg(test)]
pub mod test_db {

    use chrono::{DateTime, Utc};

    use crate::{db::db_helper::DbInstance, UserInfo};

    use lazy_static::lazy_static;

    lazy_static! {
        static ref DB_INSTANCE: DbInstance = DbInstance::new();
    }

    #[test]
    fn test_user_crud() {
        let user_info = UserInfo {
            first_name: String::from("Foo"),
            last_name: String::from("Barley"),
            username: String::from("foobar"),
            pass_hash: String::from("superdupersecrethash"),
            email: String::from("foo@bar.com"),
        };

        // Create
        let db_user = DB_INSTANCE
            .create_db_user(user_info.clone())
            .expect("Error creating user");

        assert_eq!(db_user.first_name, user_info.first_name);
        assert_eq!(db_user.last_name, user_info.last_name);
        assert_eq!(db_user.username, user_info.username);
        assert_eq!(db_user.pass_hash, user_info.pass_hash);

        // Read
        let read_db_user = DB_INSTANCE
            .get_user_from_username(&user_info.username)
            .expect("Error reading user from db");

        assert!(read_db_user.is_some());

        let read_db_user = read_db_user.unwrap();

        assert_eq!(db_user.first_name, read_db_user.first_name);
        assert_eq!(db_user.last_name, read_db_user.last_name);
        assert_eq!(db_user.username, read_db_user.username);
        assert_eq!(db_user.pass_hash, read_db_user.pass_hash);

        // Update - username
        let new_username = String::from("barfoo");
        let updated_db_user = DB_INSTANCE.update_db_username(&user_info.username, &new_username);

        assert!(updated_db_user.is_ok());

        let updated_db_user = updated_db_user.unwrap();

        assert_eq!(db_user.first_name, updated_db_user.first_name);
        assert_eq!(db_user.last_name, updated_db_user.last_name);
        assert_ne!(db_user.username, updated_db_user.username);
        assert_eq!(db_user.pass_hash, updated_db_user.pass_hash);

        assert_eq!(updated_db_user.username, new_username);

        // Update - password
        let new_password = String::from("newsecretpassword");
        let updated_db_user =
            DB_INSTANCE.update_db_password(&String::from("barfoo"), &new_password);
        assert!(updated_db_user.is_ok());

        let updated_db_user = updated_db_user.unwrap();

        assert_eq!(db_user.first_name, updated_db_user.first_name);
        assert_eq!(db_user.last_name, updated_db_user.last_name);
        assert_ne!(db_user.pass_hash, updated_db_user.pass_hash);

        assert_eq!(updated_db_user.username, new_username);
        assert_eq!(updated_db_user.pass_hash, new_password);

        // Delete

        let count = DB_INSTANCE.delete_db_user(&new_username);

        assert!(count.is_ok());

        let count = count.unwrap();

        assert_eq!(count, 1);
    }

    #[test]
    fn test_reset_tokens() {
        let user_info = UserInfo {
            first_name: String::from("Foo"),
            last_name: String::from("Barley"),
            username: String::from("veryunique"),
            pass_hash: String::from("superdupersecrethash"),
            email: String::from("foo@bar.com"),
        };

        // Create a new user
        let _db_user = DB_INSTANCE
            .create_db_user(user_info.clone())
            .expect("Error creating user");

        let reset_token = String::from("superSecrettokenHash");

        // Create reset token for user
        DB_INSTANCE
            .save_reset_token_to_db(&user_info.username, &reset_token)
            .expect("Error saving to DB");

        // Read reset token
        let retrieved_token = DB_INSTANCE
            .get_reset_token_from_db(&user_info.username)
            .expect("Error reading from DB");

        assert!(retrieved_token.is_some());

        let retrieved_token = retrieved_token.unwrap();

        // Make sure reset token is the same
        assert_eq!(reset_token, retrieved_token.reset_token);

        // Make sure the expiration timestamp was create correctly
        let expiry = retrieved_token.reset_token_expiry;
        let timestamp: DateTime<Utc> = DateTime::from(expiry);

        // Get the current time
        let current_time = Utc::now();

        // Calculate the difference in minutes
        let time_until_expiry = current_time.signed_duration_since(timestamp).num_minutes();

        assert!(time_until_expiry >= -20);

        let count = DB_INSTANCE
            .delete_db_reset_token(&user_info.username)
            .expect("Error deleting reset token!");

        assert_eq!(count, 1);

        let count = DB_INSTANCE
            .delete_db_user(&user_info.username)
            .expect("Error deleting user!");

        assert_eq!(count, 1);
    }

    #[test]
    fn test_verification_tokens() {
        let user_info = UserInfo {
            first_name: String::from("Foo"),
            last_name: String::from("Barley"),
            username: String::from("evenmoreunique"),
            pass_hash: String::from("superdupersecrethash"),
            email: String::from("foo@bar.com"),
        };

        // Create a new user
        let _db_user = DB_INSTANCE
            .create_db_user(user_info.clone())
            .expect("Error creating user");

        let verification_token = String::from("superSecrettokenHash");

        // Create reset token for user
        DB_INSTANCE
            .save_verification_token_to_db(&user_info.username, &verification_token)
            .expect("Error saving to DB");

        // Read reset token
        let retrieved_token = DB_INSTANCE
            .get_verification_token_from_db(&user_info.username)
            .expect("Error reading from DB");

        assert!(retrieved_token.is_some());

        let retrieved_token = retrieved_token.unwrap();

        // Make sure reset token is the same
        assert_eq!(verification_token, retrieved_token.confirm_token);

        // Make sure the expiration timestamp was create correctly
        let expiry = retrieved_token.confirm_token_expiry;
        let timestamp: DateTime<Utc> = DateTime::from(expiry);

        // Get the current time
        let current_time = Utc::now();

        // Calculate the difference in minutes
        let time_until_expiry = current_time.signed_duration_since(timestamp).num_minutes();

        assert!(time_until_expiry >= -20);

        let count = DB_INSTANCE
            .delete_db_verification_token(&user_info.username)
            .expect("Error deleting reset token!");

        assert_eq!(count, 1);

        let count = DB_INSTANCE
            .delete_db_user(&user_info.username)
            .expect("Error deleting user!");

        assert_eq!(count, 1);
    }
}
