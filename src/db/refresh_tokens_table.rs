use super::db_helper::DbInstance;
use super::models::{NewRefreshToken, OauthClient};
use super::schema::{oauth_clients, refresh_tokens};
use crate::db::schema::{self};
use crate::{encrypt_string, DBError};
use diesel::dsl::select;
use diesel::prelude::*;
use schema::refresh_tokens::dsl::*;
use std::time::Duration;

impl DbInstance {
    pub async fn add_refresh_token(
        &self,
        c_id: &String,
        r_token: &String,
        uname: &String,
    ) -> Result<(), DBError> {
        let mut con = self.db_connection.connect()?;

        if self.get_refresh_token_from_id(c_id, uname).is_ok() {
            return self
                .update_refresh_token(c_id, uname, r_token)
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

        let encrypted_token = encrypt_string(r_token, crate::EncryptionKey::OauthKey)
            .await
            .unwrap();

        let new_refresh_token = NewRefreshToken {
            client_id: &oauth_client.id,
            refresh_token: &encrypted_token,
            username: uname,
            expiry: &token_expiry,
        };
        diesel::insert_into(refresh_tokens)
            .values(&new_refresh_token)
            .execute(&mut con)?;
        Ok(())
    }

    pub fn get_refresh_token_from_id(
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

        Ok(token)
    }

    pub async fn update_refresh_token(
        &self,
        c_id: &String,
        uname: &String,
        new_token: &String,
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

        let encrypted_token = encrypt_string(new_token, crate::EncryptionKey::OauthKey)
            .await
            .unwrap();

        diesel::update(refresh_tokens.filter(client_id.eq(client.id).and(username.eq(uname))))
            .set((refresh_token.eq(encrypted_token), expiry.eq(token_expiry)))
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
