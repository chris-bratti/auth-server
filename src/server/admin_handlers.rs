use actix_web::web;

use crate::{
    check_valid_password, db::db_helper::DbInstance, encrypt_string, AuthError, EncryptionKey,
};

pub async fn handle_signup_admin(
    username: &String,
    password: String,
    confirm_password: String,
    db_instance: web::Data<DbInstance>,
) -> Result<(), AuthError> {
    // This should have been done on the form submit, but just in case something snuck through
    if confirm_password != password {
        return Err(AuthError::PasswordConfirmationError);
    }

    // Do server side password strength validation
    if !check_valid_password(&password) {
        return Err(AuthError::InvalidPassword);
    }

    println!("Valid passowrd");

    // Usernames should case insensitive
    let username: String = username.trim().to_lowercase();

    println!(
        "Creating new admin: {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );

    db_instance.create_admin(&username, &password).await?;

    println!("Created admin");

    Ok(())
}
