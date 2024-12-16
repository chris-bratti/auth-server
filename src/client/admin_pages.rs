#![allow(non_snake_case)]
use crate::{
    client::client_helpers::{admin_exists, admin_logged_in},
    controllers::*,
};
use leptos::*;
use leptos_router::*;

static PASSWORD_PATTERN: &str =
    "^.*(?=.{8,}).*(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@!:#$^;%&?]).+$";

#[component]
pub fn AdminPage() -> impl IntoView {
    let admin_result = create_blocking_resource(|| (), |_| async move { admin_exists().await });
    let admin_exists = move || admin_result.get().is_some() && admin_result.get().unwrap().unwrap();
    let admin_session_result =
        create_blocking_resource(|| (), |_| async move { admin_logged_in().await });
    let admin_logged_in = move || {
        admin_session_result.get().is_some() && admin_session_result.get().unwrap().unwrap()
    };

    view! {
       <Suspense fallback=|| {
           view! { <h1>Loading....</h1> }
       }>
           {move ||{
                if admin_exists() {
                    if admin_logged_in(){
                        view! {<AdminLogin/>}
                    }else{
                        view! {<AdminHomepage/>}
                    }
                }else{
                    view! {<AdminSignup/>}
                }
            }
           }
       </Suspense>
    }
}

#[component]
pub fn AdminHomepage() -> impl IntoView {
    view! {
        <h1>"You've made it to the admin page!"</h1>
    }
}

#[component]
pub fn AdminLogin() -> impl IntoView {
    // Uses Login server function
    let login = create_server_action::<AdminLogin>();
    // Used to fetch any errors returned from the Login function
    let login_value = login.value();

    let pending = login.pending();

    let verify_otp = create_server_action::<VerifyAdminOtp>();

    let _verify_otp_value = verify_otp.value();

    let (username, set_username) = create_signal(None);

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <div class="container">
                {move || {
                    if username.get().is_some() {
                        view! {
                            <ActionForm class="login-form" action=verify_otp>
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="username"
                                    value=username.get().unwrap()
                                />
                                <div class="mb-3">
                                    <label class="form-label">
                                        <input
                                            class="form-control"
                                            type="text"
                                            name="otp"
                                            placeholder="OTP"
                                        />
                                    </label>
                                </div>
                                <input class="btn btn-primary" type="submit" value="Verify OTP"/>
                            </ActionForm>
                            {move || {
                                match _verify_otp_value.get() {
                                    Some(response) => {
                                        match response{
                                            Ok(_) => view! {}.into_view(),
                                            Err(err) => view! { <p>{format!("{}", err)}</p> }.into_view()
                                        }
                                    }
                                    None => view! {}.into_view(),
                                }
                            }}
                        }
                            .into_view()
                    } else if username.get().is_none() {
                        view! {
                            <h1>"Welcome to Leptos!"</h1>
                            <ActionForm class="login-form" action=login>
                                <div class="mb-3">
                                    <label class="form-label">
                                        <input
                                            class="form-control"
                                            type="text"
                                            name="username"
                                            placeholder="Username"
                                        />
                                    </label>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">
                                        <input
                                            class="form-control"
                                            type="password"
                                            name="password"
                                            placeholder="Password"
                                        />
                                    </label>
                                </div>
                                <input class="btn btn-primary" type="submit" value="Login"/>
                                <A class="forgot-password-btn" href="/forgotpassword">
                                    "Forgot Password?"
                                </A>
                            </ActionForm>

                            {move || {
                                if pending() {
                                    view! { <p>Logging in...</p> }.into_view()
                                } else {
                                    view! {}.into_view()
                                }
                            }}

                            {move || {
                                match login_value.get() {
                                    Some(response) => {
                                        match response {
                                            Ok(uname) => {
                                                set_username(Some(uname));
                                                view! {}.into_view()
                                            }
                                            Err(server_err) => {
                                                view! {
                                                    // Displays any errors returned from the server
                                                    <p>{format!("{}", server_err.to_string())}</p>
                                                }
                                                    .into_view()
                                            }
                                        }
                                    }
                                    None => view! {}.into_view(),
                                }
                            }}
                        }
                            .into_view()
                    } else {
                        view! {

                            <h1>Loading...</h1>
                        }
                            .into_view()
                    }
                }}

            </div>
        </div>
    }
}

#[component]
pub fn AdminSignup() -> impl IntoView {
    // Uses the SignUp server function
    let signup = create_server_action::<AdminSignup>();
    // Used to fetch any errors returned from the server
    let signup_value = signup.value();
    // Used for client side password validation
    let (passwords_match, set_passwords_match) = create_signal(true);

    let (user, set_user): (ReadSignal<Option<String>>, WriteSignal<Option<String>>) =
        create_signal(None);

    let pending = signup.pending();

    let qr_code = create_resource(
        || (),
        move |_| async move { generate_2fa(user.get().unwrap()).await },
    );

    let enable_2fa = create_server_action::<AdminEnable2fa>();
    let loading = qr_code.loading();
    let value = enable_2fa.value();

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            // Form for user sign up, does some client side field validation
            <div class="container">
                {move || {
                    if pending() {
                        view! {
                            <h1>Creating account...</h1>
                            <p>"We're excited for you to get started :)"</p>
                        }
                            .into_view()
                    } else {
                        if user.get().is_some(){
                            let (encoded, token) = qr_code.get().unwrap().unwrap();
                            view! {
                                <ActionForm class="login-form" action=enable_2fa>
                                    <img src=format!("data:image/png;base64,{}", encoded) alt="QR Code"/>
                                    <input
                                        class="form-control"
                                        type="hidden"
                                        name="username"
                                        value=user.get()
                                    />
                                    <input
                                        class="form-control"
                                        type="hidden"
                                        name="two_factor_token"
                                        value=token
                                    />
                                    <div class="mb-3">
                                        <label class="form-label">
                                            <input
                                                class="form-control"
                                                type="text"
                                                name="otp"
                                                maxLength=6
                                                placeholder="OTP From Authenticator"
                                            />
                                        </label>
                                    </div>
                                    <input class="btn btn-primary" type="submit" value="Enable Two Factor"/>
                                </ActionForm>
                                {move || {
                                    if signup_value().is_some() {
                                        match signup_value().unwrap(){
                                            Ok(uname) => {
                                                set_user(Some(uname));
                                                view! {}.into_view()
                                            },
                                            Err(err) => {
                                                view! {
                                                    <p>{err.to_string()}</p>
                                                }.into_view()
                                            }
                                        }
                                    }else{
                                        view! {}.into_view()
                                    }
                                }}
                            }
                                .into_view()
                        }else{
                            view! {
                                <h1>"Sign Up"</h1>
                                <ActionForm
                                    class="login-form"
                                    on:submit=move |ev| {
                                        let data = Signup::from_event(&ev);
                                        if data.is_err() {
                                            ev.prevent_default();
                                        } else {
                                            let data_values = data.unwrap();
                                            if data_values.password != data_values.confirm_password {
                                                set_passwords_match(false);
                                                ev.prevent_default();
                                            }
                                        }
                                    }

                                    action=signup
                                >
                                    <div class="mb-3">
                                    <label class="form-label">
                                        <input
                                            class="form-control"
                                            type="password"
                                            name="admin_key"
                                            required=true
                                            placeholder="Admin Key"
                                        />
                                        </label>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">
                                            <input
                                                class="form-control"
                                                type="text"
                                                name="username"
                                                required=true
                                                minLength=5
                                                maxLength=16
                                                placeholder="Username"
                                            />
                                        </label>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">
                                            <input
                                                class="form-control"
                                                type="password"
                                                name="password"
                                                required=true
                                                minLength=8
                                                maxLength=24
                                                pattern=PASSWORD_PATTERN
                                                placeholder="Password"
                                            />
                                        </label>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">
                                            <input
                                                class="form-control"
                                                type="password"
                                                name="confirm_password"
                                                required=true
                                                minLength=8
                                                maxLength=24
                                                pattern=PASSWORD_PATTERN
                                                placeholder="Confirm Password"
                                            />
                                        </label>
                                        {move || {
                                            if !passwords_match.get() {
                                                view! { <p>Passwords do not match</p> }.into_view()
                                            } else {
                                                view! {}.into_view()
                                            }
                                        }}

                                        {move || {
                                            match signup_value.get() {
                                                Some(response) => {
                                                    match response {
                                                        Ok(_) => view! {}.into_view(),
                                                        Err(server_err) => {
                                                            view! {
                                                                // Displays any errors returned from the server
                                                                <p>{format!("{}", server_err.to_string())}</p>
                                                            }
                                                                .into_view()
                                                        }
                                                    }
                                                }
                                                None => view! {}.into_view(),
                                            }
                                        }}

                                    </div>
                                    <input class="btn btn-primary" type="submit" value="Sign Up"/>
                                </ActionForm>
                            }
                                .into_view()
                    }
                    }
                }}

            </div>

        </div>
    }
}
