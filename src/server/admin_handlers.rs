use actix_web::web;
use encryption_libs::EncryptionKey;
use redis::{Client, Commands};

use crate::{
    db::db_helper::DbInstance,
    server::auth_functions::{check_valid_password, encrypt_string},
    AdminTask, AuthError,
};

pub async fn handle_signup_admin(
    username: &String,
    email: &String,
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

    // Usernames should case insensitive
    let username: String = username.trim().to_lowercase();

    println!(
        "Creating new admin: {}",
        encrypt_string(&username, EncryptionKey::LoggerKey)
            .await
            .expect("Error encrypting username")
    );

    db_instance
        .create_admin(&username, &password, email)
        .await?;

    println!("Registered new admin");

    Ok(())
}

pub async fn handle_get_admin_tasks(
    redis_client: web::Data<Client>,
) -> Result<Vec<AdminTask>, AuthError> {
    let mut con = redis_client.get_connection()?;
    let tasks: Vec<String> = con.lrange("admin_tasks", 0, -1)?;

    let admin_tasks: Vec<AdminTask> = tasks
        .into_iter()
        .map(|task_string| serde_json::from_str(&task_string))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    Ok(admin_tasks)
}
