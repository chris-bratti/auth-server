use core::convert::From;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::{DBError, User, UserInfo};

use super::models::DbConnection;

pub struct DbInstance {
    pub db_connection: Arc<DbConnection>,
}

impl Clone for DbInstance {
    fn clone(&self) -> Self {
        DbInstance {
            db_connection: self.db_connection.clone(),
        }
    }
}

impl DbInstance {
    pub fn new() -> Self {
        let db_connection = Arc::new(DbConnection::new());

        DbInstance { db_connection }
    }

    pub fn does_user_exist(&self, username: &String) -> Result<bool, DBError> {
        let db_user = self.get_user_from_username(username)?;

        Ok(db_user.is_some())
    }

    pub fn get_user_2fa_token(&self, username: &String) -> Result<Option<String>, DBError> {
        let db_user = self.get_user_from_username(username)?;

        match db_user {
            Some(user) => Ok(user.two_factor_token),
            None => Err(DBError::NotFound(username.to_string())),
        }
    }

    pub fn get_pass_hash_for_username(&self, username: &String) -> Result<String, DBError> {
        let db_user = self.get_user_from_username(username)?;

        match db_user {
            Some(user) => Ok(user.pass_hash),
            None => Err(DBError::NotFound(username.to_string())),
        }
    }

    pub fn user_has_2fa_enabled(&self, username: &String) -> Result<bool, DBError> {
        let db_user = self.get_user_from_username(username)?;

        match db_user {
            Some(user) => Ok(user.two_factor),
            None => Err(DBError::NotFound(username.to_string())),
        }
    }

    pub fn is_user_locked(&self, username: &String) -> Result<bool, DBError> {
        let db_user = self.get_user_from_username(username)?;

        match db_user {
            Some(user) => {
                if user.locked {
                    let timestamp: DateTime<Utc> =
                        DateTime::from(user.last_failed_attempt.expect("No timestamp!"));

                    // Get the current time
                    let current_time = Utc::now();

                    // Calculate the difference in minutes
                    let minutes_since_last_attempt =
                        current_time.signed_duration_since(timestamp).num_minutes();

                    if minutes_since_last_attempt > 10 {
                        self.unlock_db_user(username)?;
                        return Ok(false);
                    }
                }
                Ok(user.locked)
            }
            None => Err(DBError::NotFound(username.to_string())),
        }
    }

    pub fn get_verification_hash(&self, username: &String) -> Result<String, DBError> {
        let verification_token = self.get_verification_token_from_db(username)?;

        match verification_token {
            Some(token) => {
                let expiry = token.confirm_token_expiry;
                let timestamp: DateTime<Utc> = DateTime::from(expiry);

                // Get the current time
                let current_time = Utc::now();

                // Calculate the difference in minutes
                let time_until_expiry = current_time.signed_duration_since(timestamp).num_minutes();

                if time_until_expiry >= 0 {
                    return Err(DBError::Error("Token expired".to_string()));
                }
                Ok(token.confirm_token)
            }
            None => Err(DBError::NotFound(username.clone())),
        }
    }

    pub fn get_reset_hash(&self, username: &String) -> Result<String, DBError> {
        let rest_token = self.get_reset_token_from_db(username)?;

        match rest_token {
            Some(token) => {
                let expiry = token.reset_token_expiry;
                let timestamp: DateTime<Utc> = DateTime::from(expiry);

                // Get the current time
                let current_time = Utc::now();

                // Calculate the difference in minutes
                let time_until_expiry = current_time.signed_duration_since(timestamp).num_minutes();

                if time_until_expiry >= 0 {
                    return Err(DBError::Error("Token expired".to_string()));
                }
                Ok(token.reset_token)
            }
            None => Err(DBError::NotFound("Reset token".to_string())),
        }
    }

    pub async fn create_user(&self, user_info: UserInfo) -> Result<User, DBError> {
        let db_user = self.create_db_user(user_info)?;

        let user = User {
            first_name: db_user.first_name,
            last_name: db_user.last_name,
            username: db_user.username,
            two_factor: false,
            verified: false,
            encrypted_email: db_user.email,
        };

        Ok(user)
    }

    pub fn find_user_by_username(&self, username: &String) -> Result<Option<User>, DBError> {
        let db_user = self.get_user_from_username(username)?;

        match db_user {
            Some(db_user) => {
                let user = User {
                    first_name: db_user.first_name,
                    last_name: db_user.last_name,
                    username: db_user.username,
                    two_factor: db_user.two_factor,
                    verified: db_user.verified,
                    encrypted_email: db_user.email,
                };
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    pub fn delete_user(&self, username: &String) -> Result<(), DBError> {
        let records_deleted = self.delete_db_user(username)?;

        if records_deleted > 1 {
            panic!(
                "Multiple records deleted!! 1 should have been deleted, actual: {}",
                records_deleted
            );
        }

        Ok(())
    }

    pub fn get_user_email(&self, username: &String) -> Result<String, DBError> {
        let db_user = self.get_user_from_username(username)?;

        match db_user {
            Some(user) => Ok(user.email),
            None => Err(DBError::NotFound(username.clone())),
        }
    }
}

#[cfg(test)]
pub mod test_db_helpers {
    use core::assert_eq;

    use crate::{db::db_helper::DbInstance, UserInfo};

    #[tokio::test]
    async fn test_user_process() {
        let user_info = UserInfo {
            first_name: String::from("foo"),
            last_name: String::from("bar"),
            username: String::from("foobar2"),
            pass_hash: String::from("supersecretpassword"),
            email: String::from("foo@bar.com"),
        };

        let db = DbInstance::new();

        // Create

        let created_user = db
            .create_user(user_info.clone())
            .await
            .expect("Error getting user");

        assert_eq!(created_user.first_name, user_info.first_name);
        assert_eq!(created_user.last_name, user_info.last_name);
        assert_eq!(created_user.username, user_info.username);
        assert_eq!(created_user.verified, false);

        // Test if user exists
        let user_exists = db
            .does_user_exist(&created_user.username)
            .expect("Error searching for user");

        assert!(user_exists);

        // Verify password hash is retrieved correctly
        let pass_hash = db
            .get_pass_hash_for_username(&created_user.username)
            .expect("Error getting password hash");

        assert_eq!(pass_hash, user_info.pass_hash);

        // Search for user by username
        let user_response = db
            .find_user_by_username(&user_info.username)
            .expect("Error searching for user");

        assert!(user_response.is_some());

        let user_response = user_response.unwrap();

        assert_eq!(user_response.first_name, user_info.first_name);
        assert_eq!(user_response.last_name, user_info.last_name);
        assert_eq!(user_response.username, user_info.username);

        // Delete user
        db.delete_user(&user_info.username)
            .expect("Error deleting records");

        // Verify the user does not exist
        let user_exists = db
            .does_user_exist(&created_user.username)
            .expect("Error searching for user");

        assert!(!user_exists);

        // Search for user by username
        let user_response = db
            .find_user_by_username(&user_info.username)
            .expect("Error searching for user");

        assert!(user_response.is_none());
    }
}
