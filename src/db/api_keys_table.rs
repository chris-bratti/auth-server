use super::db_helper::establish_connection;
use super::models::NewApiKey;
use crate::db::schema::{self};
use crate::DBError;
use diesel::prelude::*;
use schema::api_keys::dsl::*;

use super::{models::ApiKey, schema::api_keys};

pub fn get_api_keys() -> Result<Option<Vec<ApiKey>>, DBError> {
    let mut connection = establish_connection()?;

    let keys = api_keys
        .select(ApiKey::as_select())
        .load(&mut connection)
        .optional()
        .map_err(DBError::from)?;

    Ok(keys)
}

pub fn add_new_api_key(app: &String, key: &String) -> Result<(), DBError> {
    let mut connection = establish_connection()?;

    let new_api_key = NewApiKey {
        app_name: app,
        api_key: key,
    };

    diesel::insert_into(api_keys::table)
        .values(&new_api_key)
        .returning(ApiKey::as_returning())
        .get_result(&mut connection)?;
    Ok(())
}

pub fn delete_api_key(app: &String) -> Result<usize, DBError> {
    let mut connection = establish_connection()?;

    diesel::delete(api_keys.filter(app_name.eq(app)))
        .execute(&mut connection)
        .map_err(DBError::from)
}
