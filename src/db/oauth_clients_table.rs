use super::db_helper::establish_connection;
use super::models::{NewOauthClient, OauthClient};
use crate::db::schema::{self};
use crate::{encrypt_string, DBError};
use diesel::prelude::*;
use schema::oauth_clients::dsl::*;

pub fn get_oauth_clients() -> Result<Option<Vec<OauthClient>>, DBError> {
    let mut connection = establish_connection()?;

    let clients = oauth_clients
        .select(OauthClient::as_select())
        .load(&mut connection)
        .optional()
        .map_err(DBError::from)?;

    Ok(clients)
}

pub async fn add_new_oauth_client(
    name: &String,
    email: &String,
    c_id: &String,
    c_secret: &String,
    url: &String,
) -> Result<String, DBError> {
    let mut connection = establish_connection()?;

    let encrypted_email = encrypt_string(email, crate::EncryptionKey::SmtpKey)
        .await
        .unwrap();

    let encrypted_secret = encrypt_string(c_secret, crate::EncryptionKey::TwoFactorKey)
        .await
        .unwrap();

    let new_client = NewOauthClient {
        app_name: name,
        contact_email: &encrypted_email,
        client_id: c_id,
        client_secret: &encrypted_secret,
        redirect_url: url,
    };

    diesel::insert_into(oauth_clients)
        .values(&new_client)
        .returning(OauthClient::as_returning())
        .get_result(&mut connection)?;
    Ok(encrypted_secret)
}
