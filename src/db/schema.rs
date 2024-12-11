// @generated automatically by Diesel CLI.

diesel::table! {
    api_keys (id) {
        id -> Int4,
        app_name -> Text,
        api_key -> Text,
    }
}

diesel::table! {
    oauth_clients (id) {
        id -> Int4,
        app_name -> Text,
        contact_email -> Text,
        client_id -> Text,
        client_secret -> Text,
        redirect_url -> Text,
    }
}

diesel::table! {
    password_reset_tokens (id) {
        id -> Int4,
        reset_token -> Text,
        reset_token_expiry -> Timestamp,
        user_id -> Int4,
    }
}

diesel::table! {
    refresh_tokens (id) {
        id -> Int4,
        client_id -> Int4,
        refresh_token -> Text,
        username -> Text,
        expiry -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        first_name -> Text,
        last_name -> Text,
        username -> Text,
        pass_hash -> Text,
        email -> Text,
        verified -> Bool,
        two_factor -> Bool,
        two_factor_token -> Nullable<Text>,
        locked -> Bool,
        pass_retries -> Nullable<Int4>,
        last_failed_attempt -> Nullable<Timestamp>,
    }
}

diesel::table! {
    verification_tokens (id) {
        id -> Int4,
        confirm_token -> Text,
        confirm_token_expiry -> Timestamp,
        user_id -> Int4,
    }
}

diesel::joinable!(password_reset_tokens -> users (user_id));
diesel::joinable!(refresh_tokens -> oauth_clients (client_id));
diesel::joinable!(verification_tokens -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    api_keys,
    oauth_clients,
    password_reset_tokens,
    refresh_tokens,
    users,
    verification_tokens,
);
