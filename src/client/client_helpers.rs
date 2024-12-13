use crate::AuthError;
use cfg_if::cfg_if;
use leptos::server;
use leptos::ServerFnError;
cfg_if! {
    if #[cfg(feature = "ssr")] {
        use actix_identity::Identity;
        use actix_web::web;
        use leptos_actix::extract;

        use crate::{db::db_helper::DbInstance};
    }
}

#[server]
pub async fn get_user_from_session() -> Result<crate::User, ServerFnError<AuthError>> {
    let (user, db_instance): (Option<Identity>, web::Data<DbInstance>) =
        extract().await.map_err(|_| {
            AuthError::InternalServerError("Invalid session data!".to_string()).to_server_fn_error()
        })?;
    // If user exists in session, gets User entry from DB
    if let Some(user) = user {
        match db_instance.find_user_by_username(&user.id().unwrap()) {
            Ok(some_user) => match some_user {
                Some(user) => Ok(user),
                None => Err(AuthError::Error("User not found".to_string()).to_server_fn_error()),
            },
            Err(err) => {
                Err(AuthError::InternalServerError(format!("{}", err)).to_server_fn_error())
            }
        }
    } else {
        println!("No user found");
        Err(AuthError::Error("User not found".to_string()).to_server_fn_error())
    }
}
