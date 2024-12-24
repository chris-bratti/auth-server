use super::db_helper::DbInstance;
use super::models::{NewRefreshToken, OauthClient, RefreshToken};
use super::schema::{oauth_clients, refresh_tokens};
use super::DBError;
use crate::db::schema::{self};
use diesel::dsl::select;
use diesel::prelude::*;
use encryption_libs::EncryptableString;
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

        let new_refresh_token = NewRefreshToken {
            client_id: &oauth_client.id,
            refresh_token: EncryptableString::from(r_token),
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
    ) -> Result<(EncryptableString, String), DBError> {
        let mut con = self.db_connection.connect()?;

        let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut con)?;

        let token: RefreshToken = refresh_tokens
            .inner_join(oauth_clients::table)
            .filter(
                oauth_clients::client_id
                    .eq(c_id)
                    .and(refresh_tokens::token_id.eq(r_id)),
            )
            .limit(1)
            .select(RefreshToken::as_returning())
            .first(&mut con)
            .optional()?
            .ok_or_else(|| DBError::NotFound("Refresh token for client id".to_string()))?;

        if now > token.expiry {
            return Err(DBError::TokenExpired);
        }

        Ok((token.refresh_token, token.username))
    }

    pub async fn get_refresh_token_from_id(
        &self,
        c_id: &String,
        uname: &String,
    ) -> Result<EncryptableString, DBError> {
        let mut con = self.db_connection.connect()?;

        let now = select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut con)?;

        let token: RefreshToken = refresh_tokens
            .inner_join(oauth_clients::table)
            .filter(
                oauth_clients::client_id
                    .eq(c_id)
                    .and(refresh_tokens::username.eq(uname)),
            )
            .limit(1)
            .select(RefreshToken::as_returning())
            .first(&mut con)
            .optional()?
            .ok_or_else(|| DBError::NotFound(c_id.clone()))?;

        if now > token.expiry {
            return Err(DBError::TokenExpired);
        }

        Ok(token.refresh_token)
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

        diesel::update(refresh_tokens.filter(client_id.eq(client.id).and(username.eq(uname))))
            .set((
                refresh_token.eq(EncryptableString::from(new_token)),
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
