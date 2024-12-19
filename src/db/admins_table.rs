use crate::server::auth_functions::{encrypt_string, hash_string};

use super::{
    db_helper::DbInstance,
    models::{AppAdmin, NewAppAdmin},
    schema::{self},
    DBError,
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::select;
use schema::admins::dsl::*;

impl DbInstance {
    pub async fn create_admin(
        &self,
        uname: &String,
        pass: &String,
        plaintext_email: &String,
    ) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

        let hashed_pass = hash_string(pass).await.unwrap();

        let encrypted_email = encrypt_string(plaintext_email, crate::EncryptionKey::TwoFactorKey)
            .await
            .unwrap();

        let new_admin = NewAppAdmin {
            username: uname,
            email: &encrypted_email,
            pass_hash: &hashed_pass,
            initialized: &false,
            locked: &false,
        };

        diesel::insert_into(admins)
            .values(&new_admin)
            .execute(&mut connection)?;

        Ok(())
    }

    pub async fn initialize_admin(&self, uname: &String, tf_token: &String) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

        let encrypted_token = encrypt_string(tf_token, crate::EncryptionKey::TwoFactorKey)
            .await
            .unwrap();

        diesel::update(admins.filter(username.eq(uname)))
            .set((two_factor_token.eq(encrypted_token), initialized.eq(true)))
            .execute(&mut connection)?;

        Ok(())
    }

    pub fn increment_admin_password_retries(&self, uname: &String) -> Result<bool, DBError> {
        let mut connection = self.db_connection.connect()?;
        let current_time =
            select(diesel::dsl::now).get_result::<std::time::SystemTime>(&mut connection)?;

        let admin = admins
            .filter(username.eq(uname))
            .limit(1)
            .select(AppAdmin::as_select())
            .first(&mut connection)?;

        let incremented_password_retries = admin.pass_retries.unwrap_or(0) + 1;

        if incremented_password_retries >= 5 {
            let last_attempt = admin.last_failed_attempt.expect("No timestamp");

            let timestamp: DateTime<Utc> = DateTime::from(last_attempt);

            // Get the current time
            let current_time_utc: DateTime<Utc> = DateTime::from(current_time);

            // Calculate the difference in minutes
            let minutes_since_failed = current_time_utc
                .signed_duration_since(timestamp)
                .num_minutes();

            if minutes_since_failed < 10 {
                diesel::update(admins.filter(username.eq(uname)))
                    .set(locked.eq(true))
                    .execute(&mut connection)?;
                return Ok(false);
            }
        }

        diesel::update(admins.filter(username.eq(uname)))
            .set((
                pass_retries.eq(incremented_password_retries),
                last_failed_attempt.eq(current_time),
            ))
            .execute(&mut connection)?;

        Ok(true)
    }

    pub fn unlock_admin(&self, uname: &String) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(admins.filter(username.eq(uname)))
            .set((locked.eq(false), pass_retries.eq(0)))
            .execute(&mut connection)?;

        Ok(())
    }

    pub fn get_admin_from_username(&self, uname: &String) -> Result<Option<AppAdmin>, DBError> {
        let mut connection = self.db_connection.connect()?;

        admins
            .filter(username.eq(uname))
            .limit(1)
            .select(AppAdmin::as_select())
            .first(&mut connection)
            .optional()
            .map_err(DBError::from)
    }

    pub fn admin_exists(&self) -> Result<bool, DBError> {
        let mut connection = self.db_connection.connect()?;

        let num_admins: i64 = admins
            .filter(initialized.eq(true))
            .count()
            .get_result(&mut connection)?;

        Ok(num_admins > 0)
    }
}
