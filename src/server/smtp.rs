use crate::server::auth_functions::get_env_variable;
use encryption_libs::EncryptableString;
use lettre::message::header::{self};
use lettre::message::{MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use maud::html;

pub fn generate_reset_email_body(reset_token: &String, first_name: &String) -> String {
    // The recipient's name. We might obtain this from a form or their email address.
    // Create the html we want to send.

    let uri = get_env_variable("REDIRECT_URL").expect("REDIRECT_URL not set!");
    let reset_link = format!("{}/reset/{}", uri, reset_token);

    // HTML shamelessly generated with Chat-GPT. Adapted to a maud template
    html! {
        head {
            title {"Password Reset"}
            style type="text/css" {
                "body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: #333;
                }
                p {
                    margin-bottom: 20px;
                    color: #666;
                }
                .btn {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #FEFEFE;
                    text-decoration: none;
                    border-radius: 4px;
                }
                .btn:hover {
                    background-color: #0056b3;
                }"
            }
        }
        body{
            div class="container" {
                h1 {"Password Reset"}
                p{ "Hello, " (first_name) }
                p{"You have requested to reset your password. Please click the button below to proceed"}
                a class="btn" href={ (reset_link) } {
                    "Reset Password"
                }
                p{"If you did not request this, please contact us."}

            }
        }
    }.into_string()
}

pub fn generate_welcome_email_body(first_name: &String, verification_token: &String) -> String {
    let uri = get_env_variable("REDIRECT_URL").expect("REDIRECT_URL is unset!");
    let app_name = get_env_variable("APP_NAME").expect("APP NAME is unset!");
    let verification_link = format!("{}/verify/{}", uri, verification_token);
    // HTML shamelessly generated with Chat-GPT. Adapted to a maud template
    html! {
        head {
            title {"Welcome!"}
            style type="text/css" {
                "body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: #333;
                }
                p {
                    margin-bottom: 20px;
                    color: #666;
                }
                .btn {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #FEFEFE;
                    text-decoration: none;
                    border-radius: 4px;
                }
                .btn:hover {
                    background-color: #0056b3;
                }"
            }
        }
        body{
            div class="container" {
                h1 {"Welcome!"}
                p{ "Hi " (first_name) "!"}
                p{"Welcome to " (app_name) ". Its great having you!"}
                p{"Click the link below to confirm your email!"}
                a class="btn" href={ (verification_link) } {
                    "Confirm Email"
                }
            }
        }
    }
    .into_string()
}

pub fn generate_new_oauth_client_body(
    app_name: &String,
    client_id: &String,
    client_secret: &String,
    redirect_url: &String,
) -> String {
    let auth_app_name = get_env_variable("APP_NAME").expect("APP NAME is unset!");
    // HTML shamelessly generated with Chat-GPT. Adapted to a maud template
    html! {
        head {
            title {"{OAuth Access}"}
            style type="text/css" {
                "body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                h1 {
                    color: #333;
                }
                p {
                    margin-bottom: 20px;
                    color: #666;
                }
                .btn {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #FEFEFE;
                    text-decoration: none;
                    border-radius: 4px;
                }
                .btn:hover {
                    background-color: #0056b3;
                }"
            }
        }
        body{
            div class="container" {
                h1 {"Welcome!"}
                p{ "Hi " (app_name) ","}
                p{"Thank you for requesting OAuth access to " (auth_app_name) "."}
                p{"Below are your credentials, be sure to store these in a safe place"}
                ul{
                    li{ "Client ID:     " (client_id) }
                    li{ "Client Secret: " (client_secret) }
                    li{ "Redirect URL:  " (redirect_url) }
                }
                p{ b{"Your account is still pending approval. "} "We'll let you know once your credentials have been approved!"}
                {p{"For now, check out our " a href={"https://github.com/chris-bratti/auth-server/blob/master/endpoints.md"} { "documentation" } " for instructions on getting integrated with OAuth!"}}
            }
        }
    }
    .into_string()
}

pub fn send_email(
    email: &EncryptableString,
    subject: String,
    email_body: String,
    first_name: &String,
) {
    use crate::server::auth_functions::get_env_variable;

    let from_email = get_env_variable("FROM_EMAIL").expect("FROM_EMAIL is unset!");
    let smtp_key = get_env_variable("SMTP_KEY").expect("SMTP_KEY is unset!");
    let app_name = get_env_variable("APP_NAME").expect("APP_NAME is unset!");
    let plaintext_email = email.get_decrypted().to_string();
    let generated_email = Message::builder()
        .from(format!("{app_name} <{from_email}>").parse().unwrap())
        .to(format!("{first_name} <{plaintext_email}>").parse().unwrap())
        .subject(subject)
        .multipart(
            MultiPart::alternative() // This is composed of two parts.
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(String::from(
                            "There was an error formatting your email, please contact us.",
                        )), // Every message should have a plain text fallback.
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(email_body),
                ),
        )
        .expect("failed to build email");

    let creds = Credentials::new(from_email, smtp_key);

    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&generated_email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {e:?}"),
    }
}
