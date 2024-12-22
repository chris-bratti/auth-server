use super::db_helper::DbInstance;
use super::models::{NewRefreshToken, OauthClient};
use super::schema::{oauth_clients, refresh_tokens};
use super::DBError;
use crate::db::schema::{self};
use crate::server::auth_functions::{decrypt_string, encrypt_string};
use diesel::dsl::select;
use diesel::prelude::*;
use encryption_libs::EncryptionKey;
use schema::refresh_tokens::dsl::*;
use std::time::Duration;

impl DbInstance {
    pub async fn add_refresh_token(
        &self,
        c_id: &String,
        r_token: &String,
        t_id: &String,
        uname: &String,
    ) -> Result<(), DBError> {
        let mut con = self.db_connection.connect()?;

        if self.get_refresh_token_from_id(c_id, uname).await.is_ok() {
            return self
                .update_refresh_token(c_id, uname, r_token, t_id)
                .await
                .map(|_| ());
        }

        let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut con)?;

        let oauth_client: OauthClient = oauth_clients::table
            .filter(oauth_clients::client_id.eq(c_id))
            .limit(1)
            .select(OauthClient::as_select())
            .first(&mut con)
            .optional()?
            .ok_or_else(|| DBError::NotFound(uname.to_string()))?;

        let token_expiry = now
            .checked_add(Duration::new(604800, 0))
            .expect("Error parsing time");

        let encrypted_token = encrypt_string(r_token, EncryptionKey::OauthKey)
            .await
            .unwrap();

        let new_refresh_token = NewRefreshToken {
            client_id: &oauth_client.id,
            refresh_token: &encrypted_token,
            token_id: t_id,
            username: uname,
            expiry: &token_expiry,
        };
        diesel::insert_into(refresh_tokens)
            .values(&new_refresh_token)
            .execute(&mut con)?;
        Ok(())
    }

    pub async fn get_username_from_refresh_token(
        &self,
        c_id: &String,
        r_id: &String,
    ) -> Result<(String, String), DBError> {
        let mut con = self.db_connection.connect()?;

        let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut con)?;

        let (stored_token, uname, expiration): (String, String, std::time::SystemTime) =
            refresh_tokens
                .inner_join(oauth_clients::table)
                .filter(
                    oauth_clients::client_id
                        .eq(c_id)
                        .and(refresh_tokens::token_id.eq(r_id)),
                )
                .limit(1)
                .select((refresh_token, username, expiry))
                .first(&mut con)
                .optional()?
                .ok_or_else(|| DBError::NotFound("Refresh token for client id".to_string()))?;

        if now > expiration {
            return Err(DBError::TokenExpired);
        }

        Ok((
            decrypt_string(&stored_token, EncryptionKey::OauthKey)
                .await
                .unwrap(),
            uname,
        ))
    }

    pub async fn get_refresh_token_from_id(
        &self,
        c_id: &String,
        uname: &String,
    ) -> Result<String, DBError> {
        let mut con = self.db_connection.connect()?;

        let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut con)?;

        let token_data: Option<(String, std::time::SystemTime)> = refresh_tokens
            .inner_join(oauth_clients::table)
            .filter(
                oauth_clients::client_id
                    .eq(c_id)
                    .and(refresh_tokens::username.eq(uname)),
            )
            .limit(1)
            .select((refresh_token, expiry))
            .first(&mut con)
            .optional()?;

        let (token, expiration) = token_data
            .ok_or_else(|| DBError::NotFound(c_id.clone()))?
            .into();

        if now > expiration {
            return Err(DBError::TokenExpired);
        }

        let decrypted_token = decrypt_string(&token, EncryptionKey::OauthKey)
            .await
            .map_err(|err| DBError::Error(err.to_string()))?;

        Ok(decrypted_token)
    }

    pub async fn update_refresh_token(
        &self,
        c_id: &String,
        uname: &String,
        new_token: &String,
        new_token_id: &String,
    ) -> Result<usize, DBError> {
        let mut con = self.db_connection.connect()?;

        let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut con)?;

        let token_expiry = now
            .checked_add(Duration::new(604800, 0))
            .expect("Error parsing time");

        let client: OauthClient = oauth_clients::table
            .filter(oauth_clients::client_id.eq(c_id))
            .limit(1)
            .select(OauthClient::as_select())
            .first(&mut con)
            .optional()?
            .ok_or_else(|| DBError::NotFound(c_id.clone()))?;

        let encrypted_token = encrypt_string(new_token, EncryptionKey::OauthKey)
            .await
            .unwrap();

        diesel::update(refresh_tokens.filter(client_id.eq(client.id).and(username.eq(uname))))
            .set((
                refresh_token.eq(encrypted_token),
                expiry.eq(token_expiry),
                token_id.eq(new_token_id),
            ))
            .execute(&mut con)
            .map_err(DBError::from)
    }

    pub fn delete_refresh_token(&self, c_id: &String, uname: &String) -> Result<usize, DBError> {
        let mut con = self.db_connection.connect()?;

        let client: OauthClient = oauth_clients::table
            .filter(oauth_clients::client_id.eq(c_id))
            .limit(1)
            .select(OauthClient::as_select())
            .first(&mut con)
            .optional()?
            .ok_or_else(|| DBError::NotFound(c_id.clone()))?;

        diesel::delete(
            refresh_tokens.filter(
                refresh_tokens::client_id
                    .eq(client.id)
                    .and(refresh_tokens::username.eq(uname)),
            ),
        )
        .execute(&mut con)
        .map_err(DBError::from)
    }
}
