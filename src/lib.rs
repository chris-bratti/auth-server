use serde::{Deserialize, Serialize};

pub mod auth;
pub mod db;
pub mod server;
pub mod smtp;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct User {
    first_name: String,
    last_name: String,
    username: String,
    two_factor: bool,
    verified: bool,
}
