use super::db_helper::DbInstance;
use super::models::{NewOauthClient, OauthClient};
use crate::db::schema::{self};
use crate::{encrypt_string, DBError};
use diesel::prelude::*;
use schema::oauth_clients::dsl::*;

impl DbInstance {
    pub fn get_oauth_clients(&self) -> Result<Option<Vec<OauthClient>>, DBError> {
        let mut connection = self.db_instance.connect()?;
        let clients = oauth_clients
            .select(OauthClient::as_select())
            .load(&mut connection)
            .optional()
            .map_err(DBError::from)?;

        Ok(clients)
    }

    pub async fn add_new_oauth_client(
        &self,
        name: &String,
        email: &String,
        c_id: &String,
        c_secret: &String,
        url: &String,
    ) -> Result<String, DBError> {
        let mut connection = self.db_instance.connect()?;

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

    pub fn delete_oauth_client(&self, c_id: &String) -> Result<usize, DBError> {
        let mut connection = self.db_instance.connect()?;
        diesel::delete(oauth_clients.filter(client_id.eq(c_id)))
            .execute(&mut connection)
            .map_err(DBError::from)
    }
}

#[cfg(test)]
pub mod test_oauth_dbs {

    use serial_test::serial;

    use crate::{db::db_helper::DbInstance, decrypt_string, generate_token};

    use lazy_static::lazy_static;

    lazy_static! {
        static ref DB_INSTANCE: DbInstance = DbInstance::new();
    }

    #[tokio::test]
    #[serial]
    async fn test_oauth_crud() {
        let name = String::from("A Test Client");
        let email = String::from("team.member@testclient.org");
        let c_id = String::from("randomCliEntIdblahblah");
        let c_secret = String::from("supersecureandreallysensitiveclientsecret");
        let url = String::from("https://localhost:8080");

        // Create
        let encrypted_secret = DB_INSTANCE
            .add_new_oauth_client(&name, &email, &c_id, &c_secret, &url)
            .await
            .unwrap();

        let unencrypted_secret =
            decrypt_string(&encrypted_secret, crate::EncryptionKey::TwoFactorKey)
                .await
                .unwrap();

        assert_eq!(unencrypted_secret, c_secret);

        // Read
        let clients = DB_INSTANCE.get_oauth_clients().unwrap().unwrap();

        assert_eq!(clients.len(), 1);

        let read_client = clients.get(0).unwrap();

        let decrypted_email =
            decrypt_string(&read_client.contact_email, crate::EncryptionKey::SmtpKey)
                .await
                .unwrap();

        assert_eq!(read_client.app_name, name);
        assert_eq!(decrypted_email, email);
        assert_eq!(read_client.client_id, c_id);
        assert_eq!(read_client.client_secret, encrypted_secret);
        assert_eq!(read_client.redirect_url, url);

        // Delete

        let count = DB_INSTANCE.delete_oauth_client(&c_id).unwrap();

        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_refresh_token_crud() {
        let name = String::from("Another Test Client");
        let email = String::from("team.member@testclient.org");
        let c_id = String::from("anotherRnadomClientDIFEf");
        let c_secret = String::from("anothersupersensitivesecretblahblah");
        let url = String::from("https://localhost:8080");

        let uname = String::from("testuser");

        let second_uname = String::from("secondtestuser");

        let r_token = generate_token();

        // Create
        let _ = DB_INSTANCE
            .add_new_oauth_client(&name, &email, &c_id, &c_secret, &url)
            .await
            .unwrap();

        let encrypted_token = DB_INSTANCE
            .add_refresh_token(&c_id, &r_token, &uname)
            .await
            .unwrap();

        let decrypted_token = decrypt_string(&encrypted_token, crate::EncryptionKey::TwoFactorKey)
            .await
            .unwrap();

        assert_eq!(r_token, decrypted_token);

        // Add another
        let second_token = generate_token();

        let second_encrypted_token = DB_INSTANCE
            .add_refresh_token(&c_id, &second_token, &second_uname)
            .await
            .unwrap();

        // Read first
        let read_refresh_token = DB_INSTANCE
            .get_refresh_token_from_id(&c_id, &uname)
            .unwrap();

        assert_eq!(read_refresh_token, encrypted_token);

        // Read second
        let second_read_refresh_token = DB_INSTANCE
            .get_refresh_token_from_id(&c_id, &second_uname)
            .unwrap();

        assert_eq!(second_read_refresh_token, second_encrypted_token);

        // Delete first
        let num_deleted = DB_INSTANCE.delete_refresh_token(&c_id, &uname).unwrap();

        assert_eq!(num_deleted, 1);

        // Delete second
        let num_deleted = DB_INSTANCE
            .delete_refresh_token(&c_id, &second_uname)
            .unwrap();

        assert_eq!(num_deleted, 1);

        // Delete client
        let num_deleted = DB_INSTANCE.delete_oauth_client(&c_id).unwrap();

        assert_eq!(num_deleted, 1);
    }
}
