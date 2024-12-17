use actix::prelude::*;
use actix_web::web;
use redis::{Client, Commands};

use crate::{AdminTaskMessage, AuthError};

const TASK_KEY: &str = "admin_tasks";

pub struct AdminTaskActor {
    redis_client: web::Data<Client>,
}

impl AdminTaskActor {
    pub fn new(redis_client: web::Data<Client>) -> Self {
        Self { redis_client }
    }
}

impl Actor for AdminTaskActor {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Context<Self>) {
        println!("Started admin task actor");
    }

    fn stopped(&mut self, _ctx: &mut Context<Self>) {
        println!("Stopped admin task actor");
    }
}

// Implement a handler for AdminTaskMessage
impl Handler<AdminTaskMessage> for AdminTaskActor {
    type Result = ResponseFuture<Result<(), AuthError>>;

    fn handle(&mut self, msg: AdminTaskMessage, _ctx: &mut Context<Self>) -> Self::Result {
        let redis_client = self.redis_client.clone();
        let serialized_task = serde_json::to_string(&msg).unwrap();

        println!("Received a message");

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
