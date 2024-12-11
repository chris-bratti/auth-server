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
    ) -> Result<String, DBError> {
        let mut con = self.db_connection.connect()?;

        let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut con)?;

        let oauth_client: Option<OauthClient> = oauth_clients::table
            .filter(oauth_clients::client_id.eq(c_id))
            .limit(1)
            .select(OauthClient::as_select())
            .first(&mut con)
            .optional()?;

        let token_expiry = now
            .checked_add(Duration::new(604800, 0))
            .expect("Error parsing time");

        match oauth_client {
            Some(client) => {
                let encrypted_token = encrypt_string(r_token, crate::EncryptionKey::TwoFactorKey)
                    .await
                    .unwrap();

                let new_refresh_token = NewRefreshToken {
                    client_id: &client.id,
                    refresh_token: &encrypted_token,
                    username: uname,
                    expiry: &token_expiry,
                };
                diesel::insert_into(refresh_tokens)
                    .values(&new_refresh_token)
                    .execute(&mut con)?;
                Ok(encrypted_token)
            }
            None => Err(DBError::NotFound(uname.to_string())),
        }
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
            .optional()
            .map_err(DBError::from)?;

        let (token, expiration) = token_data
            .ok_or_else(|| DBError::NotFound(c_id.clone()))?
            .into();

        if now > expiration {
            return Err(DBError::TokenExpired);
        }

        Ok(token)
    }

    pub fn delete_refresh_token(&self, c_id: &String, uname: &String) -> Result<usize, DBError> {
        let mut con = self.db_connection.connect()?;

        let client: Option<OauthClient> = oauth_clients::table
            .filter(oauth_clients::client_id.eq(c_id))
            .limit(1)
            .select(OauthClient::as_select())
            .first(&mut con)
            .optional()
            .map_err(DBError::from)?;

        match client {
            Some(oa_client) => diesel::delete(
                refresh_tokens.filter(
                    refresh_tokens::client_id
                        .eq(oa_client.id)
                        .and(refresh_tokens::username.eq(uname)),
                ),
            )
            .execute(&mut con)
            .map_err(DBError::from),
            None => Err(DBError::NotFound(c_id.to_string())),
        }
    }
}
