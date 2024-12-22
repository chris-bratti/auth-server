use std::sync::Arc;

use actix::prelude::*;
use actix_web::web;
use encryption_libs::EncryptionKey;
use rand::Rng;
use redis::{Client, Commands};

use crate::{db::models::OauthClient, AdminTask, AuthError};

use super::{
    auth_functions::decrypt_string,
    smtp::{generate_new_oauth_client_body, send_email},
};

const TASK_KEY: &str = "admin_tasks";

#[derive(Message)]
#[rtype(result = "Result<(), AuthError>")]
pub struct OAuthClientCreated(Arc<OauthClient>);

#[derive(Message)]
#[rtype(result = "()")]
pub struct CreateClient(pub OauthClient);

/// Subscribe to order shipped event.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe(pub Recipient<OAuthClientCreated>);

/// Actor that provides client created event subscriptions
pub struct OAuthClientEvents {
    subscribers: Vec<Recipient<OAuthClientCreated>>,
}

impl OAuthClientEvents {
    pub fn new() -> Self {
        OAuthClientEvents {
            subscribers: vec![],
        }
    }
}

impl Actor for OAuthClientEvents {
    type Context = Context<Self>;
}

impl OAuthClientEvents {
    /// Send event to all subscribers
    fn notify(&mut self, oauth_client: OauthClient) {
        let shared_client = Arc::new(oauth_client);
        for subscr in &self.subscribers {
            subscr.do_send(OAuthClientCreated(shared_client.clone()));
        }
    }
}

/// Subscribe to client event
impl Handler<Subscribe> for OAuthClientEvents {
    type Result = ();

    fn handle(&mut self, msg: Subscribe, _: &mut Self::Context) {
        self.subscribers.push(msg.0);
    }
}

/// Subscribe to client message
impl Handler<CreateClient> for OAuthClientEvents {
    type Result = ();

    fn handle(&mut self, msg: CreateClient, _ctx: &mut Self::Context) {
        self.notify(msg.0);
        System::current().stop();
    }
}

/// Email Subscriber
pub struct EmailSubscriber;

impl Actor for EmailSubscriber {
    type Context = Context<Self>;
}

impl Handler<OAuthClientCreated> for EmailSubscriber {
    type Result = ResponseFuture<Result<(), AuthError>>;

    fn handle(&mut self, msg: OAuthClientCreated, _ctx: &mut Self::Context) -> Self::Result {
        Box::pin(async move {
            let decrypted_secret = decrypt_string(&msg.0.client_secret, EncryptionKey::OauthKey)
                .await
                .unwrap();

            let decrypted_email = decrypt_string(&msg.0.contact_email, EncryptionKey::SmtpKey)
                .await
                .unwrap();
            let email_body = generate_new_oauth_client_body(
                &msg.0.app_name,
                &msg.0.client_id,
                &decrypted_secret,
                &msg.0.redirect_url,
            );

            send_email(
                &decrypted_email,
                "OAuth Access".to_string(),
                email_body,
                &msg.0.app_name,
            );
            Ok(())
        })
    }
}

/// Redis subscriber
pub struct TaskQueueSubscriber {
    redis_client: web::Data<Client>,
}

impl TaskQueueSubscriber {
    pub fn new(redis_client: web::Data<Client>) -> Self {
        Self { redis_client }
    }
}

impl Actor for TaskQueueSubscriber {
    type Context = Context<Self>;
}

impl Handler<OAuthClientCreated> for TaskQueueSubscriber {
    type Result = ResponseFuture<Result<(), AuthError>>;

    fn handle(&mut self, msg: OAuthClientCreated, _ctx: &mut Self::Context) -> Self::Result {
        let redis_client = self.redis_client.clone();

        let admin_task = AdminTask {
            task_type: crate::AdminTaskType::ApproveOauthClient {
                app_name: msg.0.app_name.clone(),
                client_id: msg.0.client_id.clone(),
            },
            message: "New OAuth client requires approval".into(),
            id: rand::thread_rng().gen_range(1..=50000),
        };

        let serialized_task = serde_json::to_string(&admin_task).unwrap();

        // Push the serialized task into a Redis list
        Box::pin(async move {
            let mut conn: redis::Connection = redis_client.get_connection()?;

            let result: Result<(), redis::RedisError> = conn.lpush(TASK_KEY, serialized_task);

            match result {
                Ok(_) => {
                    println!("New Admin Task created");
                    Ok(())
                }
                Err(e) => Err(AuthError::InternalServerError(e.to_string())),
            }
        })
    }
}
