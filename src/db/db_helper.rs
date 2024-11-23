use std::fmt;

use chrono::{DateTime, Utc};

use crate::{auth::UserInfo, User};

use super::{
    reset_token_table::{delete_db_reset_token, get_reset_token_from_db, save_reset_token_to_db},
    users_db::{
        add_2fa_for_db_user, create_db_user, delete_db_user, get_user_from_username,
        increment_db_password_tries, set_db_user_as_verified, unlock_db_user, update_db_password,
        update_db_username,
    },
    verification_tokens_table::{
        delete_db_verification_token, get_verification_token_from_db, save_verification_token_to_db,
    },
};

pub fn does_user_exist(username: &String) -> Result<bool, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    Ok(db_user.is_some())
}

pub fn enable_2fa_for_user(username: &String, encrypted_token: &String) -> Result<(), DBError> {
    add_2fa_for_db_user(username, encrypted_token).map_err(|err| DBError::InternalServerError(err))
}

pub fn get_user_2fa_token(username: &String) -> Result<Option<String>, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    match db_user {
        Some(user) => Ok(user.two_factor_token),
        None => Err(DBError::NotFound(username.to_string())),
    }
}

pub fn get_pass_hash_for_username(username: &String) -> Result<String, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    match db_user {
        Some(user) => Ok(user.pass_hash),
        None => Err(DBError::NotFound(username.clone())),
    }
}

pub fn user_has_2fa_enabled(username: &String) -> Result<bool, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    match db_user {
        Some(user) => Ok(user.two_factor),
        None => Err(DBError::NotFound(username.clone())),
    }
}

pub fn unlock_user(username: &String) -> Result<(), DBError> {
    unlock_db_user(username).map_err(|err| DBError::InternalServerError(err))
}

pub fn is_user_locked(username: &String) -> Result<bool, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

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
                    unlock_db_user(username).map_err(|err| DBError::InternalServerError(err))?;
                    return Ok(false);
                }
            }
            Ok(user.locked)
        }
        None => Err(DBError::NotFound(username.clone())),
    }
}

pub fn failed_login_attempt(username: &String) -> Result<bool, DBError> {
    increment_db_password_tries(username).map_err(|err| DBError::InternalServerError(err))
}

pub fn set_user_as_verified(username: &String) -> Result<(), DBError> {
    set_db_user_as_verified(username).map_err(|err| DBError::InternalServerError(err))?;
    Ok(())
}

pub fn get_verification_hash(username: &String) -> Result<String, DBError> {
    let verification_token = get_verification_token_from_db(username)
        .map_err(|err| DBError::InternalServerError(err))?;

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

pub fn remove_reset_token(username: &String) -> Result<(), DBError> {
    let _ = delete_db_reset_token(username).map_err(|err| DBError::InternalServerError(err))?;

    Ok(())
}

pub fn remove_verification_token(username: &String) -> Result<(), DBError> {
    let _ =
        delete_db_verification_token(username).map_err(|err| DBError::InternalServerError(err))?;

    Ok(())
}

pub fn get_reset_hash(username: &String) -> Result<String, DBError> {
    let rest_token =
        get_reset_token_from_db(username).map_err(|err| DBError::InternalServerError(err))?;

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
        None => Err(DBError::NotFound(username.clone())),
    }
}

pub fn update_user_password(username: &String, new_pass_hash: &String) -> Result<(), DBError> {
    update_db_password(username, new_pass_hash).map_err(|err| DBError::InternalServerError(err))?;

    Ok(())
}

pub async fn create_user(user_info: UserInfo) -> Result<User, DBError> {
    let db_user = create_db_user(user_info).map_err(|err| DBError::InternalServerError(err))?;

    let user = User {
        first_name: db_user.first_name,
        last_name: db_user.last_name,
        username: db_user.username,
        two_factor: false,
        verified: false,
    };

    Ok(user)
}

pub fn find_user_by_username(username: &String) -> Result<Option<User>, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    match db_user {
        Some(db_user) => {
            let user = User {
                first_name: db_user.first_name,
                last_name: db_user.last_name,
                username: db_user.username,
                two_factor: db_user.two_factor,
                verified: db_user.verified,
            };
            Ok(Some(user))
        }
        None => Ok(None),
    }
}

pub fn update_username(username: &String, new_username: &String) -> Result<(), DBError> {
    let db_user = update_db_username(username, new_username);

    match db_user {
        Ok(_) => Ok(()),
        Err(err) => match err {
            diesel::result::Error::NotFound => Err(DBError::NotFound(username.clone())),
            _ => Err(DBError::InternalServerError(err)),
        },
    }
}

pub fn delete_user(username: &String) -> Result<(), DBError> {
    let records_deleted =
        delete_db_user(username).map_err(|err| DBError::InternalServerError(err))?;

    if records_deleted > 1 {
        panic!(
            "Multiple records deleted!! 1 should have been deleted, actual: {}",
            records_deleted
        );
    }

    Ok(())
}

pub fn save_reset(username: &String, reset_token: &String) -> Result<(), DBError> {
    if !does_user_exist(username)? {
        return Err(DBError::NotFound(username.clone()));
    }

    save_reset_token_to_db(username, reset_token).map_err(|err| DBError::InternalServerError(err))
}

pub fn save_verification(username: &String, verification_token: &String) -> Result<(), DBError> {
    save_verification_token_to_db(username, verification_token)
        .map_err(|err| DBError::InternalServerError(err))
}

pub fn get_user_email(username: &String) -> Result<String, DBError> {
    let db_user =
        get_user_from_username(username).map_err(|err| DBError::InternalServerError(err))?;

    match db_user {
        Some(user) => Ok(user.email),
        None => Err(DBError::NotFound(username.clone())),
    }
}

pub enum DBError {
    NotFound(String),
    InternalServerError(diesel::result::Error),
    Error(String),
}

// Implement std::fmt::Display for AppError
impl fmt::Display for DBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DBError::NotFound(_data) => {
                write!(f, "User not found!")
            }
            DBError::InternalServerError(_diesel_error) => {
                write!(f, "There was an error on our side :(")
            }
            DBError::Error(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

// Implement std::fmt::Debug for AppError
impl fmt::Debug for DBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DBError::NotFound(data) => {
                write!(f, "Data could not be found: {}", data)
            }
            DBError::InternalServerError(diesel_error) => {
                write!(f, "Diesel error: {}", diesel_error)
            }
            DBError::Error(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

#[cfg(test)]
pub mod test_db_helpers {
    use core::assert_eq;

    use crate::{
        auth::UserInfo,
        db::db_helper::{
            delete_user, does_user_exist, find_user_by_username, get_pass_hash_for_username,
        },
    };

    use super::create_user;

    #[tokio::test]
    async fn test_user_process() {
        let user_info = UserInfo {
            first_name: String::from("foo"),
            last_name: String::from("bar"),
            username: String::from("foobar2"),
            pass_hash: String::from("supersecretpassword"),
            email: String::from("foo@bar.com"),
        };

        // Create

        let created_user = create_user(user_info.clone())
            .await
            .expect("Error getting user");

        assert_eq!(created_user.first_name, user_info.first_name);
        assert_eq!(created_user.last_name, user_info.last_name);
        assert_eq!(created_user.username, user_info.username);
        assert_eq!(created_user.verified, false);

        // Test if user exists
        let user_exists =
            does_user_exist(&created_user.username).expect("Error searching for user");

        assert!(user_exists);

        // Verify password hash is retrieved correctly
        let pass_hash = get_pass_hash_for_username(&created_user.username)
            .expect("Error getting password hash");

        assert_eq!(pass_hash, user_info.pass_hash);

        // Search for user by username
        let user_response =
            find_user_by_username(&user_info.username).expect("Error searching for user");

        assert!(user_response.is_some());

        let user_response = user_response.unwrap();

        assert_eq!(user_response.first_name, user_info.first_name);
        assert_eq!(user_response.last_name, user_info.last_name);
        assert_eq!(user_response.username, user_info.username);

        // Delete user
        delete_user(&user_info.username).expect("Error deleting records");

        // Verify the user does not exist
        let user_exists =
            does_user_exist(&created_user.username).expect("Error searching for user");

        assert!(!user_exists);

        // Search for user by username
        let user_response =
            find_user_by_username(&user_info.username).expect("Error searching for user");

        assert!(user_response.is_none());
    }
}
