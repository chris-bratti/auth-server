use encryption_libs::Encryptable;
use thiserror::Error;

pub mod admins_table;
pub mod db_helper;
pub mod models;
pub mod oauth_clients_table;
pub mod refresh_tokens_table;
pub mod reset_token_table;
pub mod schema;
pub mod users_db;
pub mod verification_tokens_table;

#[derive(Error, Debug)]
pub enum DBError {
    #[error("User not found: {0}")]
    NotFound(String),
    #[error("Internal server error: {0}")]
    InternalServerError(#[from] diesel::result::Error),
    #[error("Error: {0}")]
    Error(String),
    #[error("Database connection error: {0}")]
    ConnectionError(#[from] diesel::ConnectionError),
    #[error("Token invalid or expired")]
    TokenExpired,
}

use diesel::{r2d2::ConnectionManager, PgConnection};
use r2d2::{Pool, PooledConnection};

use crate::server::auth_functions::get_env_variable;

pub struct DbConnection {
    connection_pool: Pool<ConnectionManager<PgConnection>>,
}

impl DbConnection {
    pub fn connect(&self) -> Result<PooledConnection<ConnectionManager<PgConnection>>, DBError> {
        self.connection_pool
            .get()
            .map_err(|_| DBError::Error("Error establishing connection!".to_string()))
    }

    pub fn new() -> Self {
        println!("Establishing database connection");
        let database_url = get_env_variable("DATABASE_URL").unwrap();
        let manager = ConnectionManager::<PgConnection>::new(&database_url);
        let connection_pool = Pool::builder()
            .test_on_check_out(true)
            .max_size(15)
            .build(manager)
            .unwrap();
        DbConnection { connection_pool }
    }
}

pub struct DatabaseEncryption<T>
where
    T: Encryptable,
{
    pub encrypted: bool,
    pub data: T,
}

impl<T> DatabaseEncryption<T>
where
    T: Encryptable,
{
    pub fn from_encrypted(data: T) -> Self {
        DatabaseEncryption {
            encrypted: true,
            data,
        }
    }

    pub fn from_unencrypted(data: T) -> Self {
        DatabaseEncryption {
            encrypted: false,
            data,
        }
    }

    pub fn decrypted(&mut self) -> &T {
        self.data.decrypt();

        &self.data
    }

    pub fn encrypted(&mut self) -> &T {
        self.data.encrypt();

        &self.data
    }
}
