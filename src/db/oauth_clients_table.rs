use super::db_helper::DbInstance;
use super::models::{NewOauthClient, OauthClient};
use super::DBError;
use crate::db::schema::{self};
use diesel::prelude::*;
use encryption_libs::{encrypt_string, EncryptionKey};
use schema::oauth_clients::dsl::*;

impl DbInstance {
    pub fn get_oauth_clients(&self) -> Result<Option<Vec<OauthClient>>, DBError> {
        let mut connection = self.db_connection.connect()?;
        let clients = oauth_clients
            .filter(approved.eq(true))
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
    ) -> Result<OauthClient, DBError> {
        let mut connection = self.db_connection.connect()?;

        let encrypted_email = encrypt_string(email, EncryptionKey::SmtpKey).unwrap();

        let encrypted_secret = encrypt_string(c_secret, EncryptionKey::OauthKey).unwrap();

        let new_client = NewOauthClient {
            app_name: name,
            contact_email: &encrypted_email,
            client_id: c_id,
            client_secret: &encrypted_secret,
            redirect_url: url,
            approved: &false,
        };

        diesel::insert_into(oauth_clients)
            .values(&new_client)
            .returning(OauthClient::as_returning())
            .get_result(&mut connection)
            .map_err(DBError::from)
    }

    pub fn delete_oauth_client(&self, c_id: &String) -> Result<usize, DBError> {
        let mut connection = self.db_connection.connect()?;
        diesel::delete(oauth_clients.filter(client_id.eq(c_id)))
            .execute(&mut connection)
            .map_err(DBError::from)
    }

    pub fn approve_oauth_client(&self, c_id: &String) -> Result<(), DBError> {
        let mut connection = self.db_connection.connect()?;

        diesel::update(oauth_clients.filter(client_id.eq(c_id)))
            .set(approved.eq(true))
            .execute(&mut connection)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test_oauth_dbs {

    use encryption_libs::{decrypt_string, EncryptionKey};
    use serial_test::serial;

    use crate::{db::db_helper::DbInstance, server::auth_functions::generate_token};

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
        let returned_client = DB_INSTANCE
            .add_new_oauth_client(&name, &email, &c_id, &c_secret, &url)
            .await
            .unwrap();

        let unencrypted_secret =
            decrypt_string(&returned_client.client_secret, EncryptionKey::OauthKey).unwrap();

        assert_eq!(unencrypted_secret, c_secret);

        //Approve client
        DB_INSTANCE.approve_oauth_client(&c_id).unwrap();

        // Read
        let clients = DB_INSTANCE.get_oauth_clients().unwrap().unwrap();

        let read_client = clients.iter().find(|c| c.client_id == c_id);

        assert!(read_client.is_some());

        let read_client = read_client.unwrap();

        let decrypted_email =
            decrypt_string(&read_client.contact_email, EncryptionKey::SmtpKey).unwrap();

        assert_eq!(read_client.app_name, name);
        assert_eq!(decrypted_email, email);
        assert_eq!(read_client.client_id, c_id);
        assert_eq!(read_client.client_secret, returned_client.client_secret);
        assert_eq!(read_client.redirect_url, url);

        // Delete

        let count = DB_INSTANCE.delete_oauth_client(&c_id).unwrap();

        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_overwrite_token() {
        let name = String::from("Client Test");
        let email = String::from("user@testclient.org");
        let c_id = String::from("clientIDFEFEJ");
        let c_secret = String::from("superusupersupersecret");
        let url = String::from("https://localhost:8080");

        let uname = String::from("test_user1");

        let r_token = generate_token();

        let r_id = generate_token().get(0..8).unwrap().to_string();

        // Create client
        DB_INSTANCE
            .add_new_oauth_client(&name, &email, &c_id, &c_secret, &url)
            .await
            .unwrap();

        // Create refresh token
        DB_INSTANCE
            .add_refresh_token(&c_id, &r_token, &r_id, &uname)
            .await
            .unwrap();

        // Read refresh token
        let read_token = DB_INSTANCE
            .get_refresh_token_from_id(&c_id, &uname)
            .await
            .unwrap();

        // Verify token was saved correctly
        assert_eq!(r_token, read_token);

        // Create and save new refresh token
        let new_r_token = generate_token();

        let new_r_id = generate_token().get(0..8).unwrap().to_string();

        DB_INSTANCE
            .add_refresh_token(&c_id, &new_r_token, &new_r_id, &uname)
            .await
            .unwrap();

        // Read refresh token
        let read_token = DB_INSTANCE
            .get_refresh_token_from_id(&c_id, &uname)
            .await
            .unwrap();

        assert_eq!(new_r_token, read_token);

        // Clean up
        DB_INSTANCE.delete_refresh_token(&c_id, &uname).unwrap();

        DB_INSTANCE.delete_oauth_client(&c_id).unwrap();
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

        let r_id = generate_token().get(0..8).unwrap().to_string();

        // Create
        DB_INSTANCE
            .add_new_oauth_client(&name, &email, &c_id, &c_secret, &url)
            .await
            .unwrap();

        DB_INSTANCE
            .add_refresh_token(&c_id, &r_token, &r_id, &uname)
            .await
            .unwrap();

        // Add another
        let second_token = generate_token();

        let second_token_id = generate_token().get(0..8).unwrap().to_string();

        DB_INSTANCE
            .add_refresh_token(&c_id, &second_token, &second_token_id, &second_uname)
            .await
            .unwrap();

        // Read first
        let read_refresh_token = DB_INSTANCE
            .get_refresh_token_from_id(&c_id, &uname)
            .await
            .unwrap();

        assert_eq!(read_refresh_token, r_token);

        // Read second
        let second_read_refresh_token = DB_INSTANCE
            .get_refresh_token_from_id(&c_id, &second_uname)
            .await
            .unwrap();

        assert_eq!(second_read_refresh_token, second_token);

        // Update first
        let new_token = generate_token();
        let new_token_id = generate_token().get(0..8).unwrap().to_string();
        let num_updated = DB_INSTANCE
            .update_refresh_token(&c_id, &uname, &new_token, &new_token_id)
            .await
            .unwrap();

        assert_eq!(num_updated, 1);

        // Read first again
        let read_token = DB_INSTANCE
            .get_refresh_token_from_id(&c_id, &uname)
            .await
            .unwrap();

        assert_eq!(read_token, new_token);

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
