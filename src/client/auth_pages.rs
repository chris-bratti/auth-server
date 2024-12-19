#![allow(non_snake_case)]
use crate::{
    client::client_helpers::{get_user_from_session, user_server_side_redirect},
    controllers::*,
    OAuthRequest, UserBasicInfo,
};
use leptos::*;
use leptos_router::*;

static PASSWORD_PATTERN: &str =
    "^.*(?=.{8,}).*(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@!:#$^;%&?]).+$";

#[component]
pub fn Login() -> impl IntoView {
    let oauth_query = use_query::<OAuthRequest>();

    let client_id = Signal::derive(move || {
        oauth_query.with(|query: &Result<OAuthRequest, ParamsError>| {
            query
                .as_ref()
                .map(|query: &OAuthRequest| query.client_id.clone())
                .unwrap_or(None)
        })
    });
    let state = Signal::derive(move || {
        oauth_query.with(|query| {
            query
                .as_ref()
                .map(|query| query.state.clone())
                .unwrap_or(None)
        })
    });

    let user_result =
        create_blocking_resource(|| (), |_| async move { get_user_from_session().await });
    let user_is_logged_in =
        move || user_result.get().is_some() && user_result.get().unwrap().is_ok();
    let log_user_in = || view! { <Auth/> };

    view! {
       <Suspense fallback=|| {
           view! { <h1>Loading....</h1> }
       }>
           <Show when=user_is_logged_in fallback=log_user_in>

               {{
                    let _ =
                    create_blocking_resource(|| (), move |_| async move { user_server_side_redirect(user_result.get().unwrap().unwrap().username, client_id(), state()).await });
               }}

           </Show>
       </Suspense>
    }
}

#[component]
pub fn Auth() -> impl IntoView {
    let oauth_query = use_query::<OAuthRequest>();

    let client_id = Signal::derive(move || {
        oauth_query.with(|query: &Result<OAuthRequest, ParamsError>| {
            query
                .as_ref()
                .map(|query: &OAuthRequest| query.client_id.clone())
                .unwrap_or(None)
        })
    });
    let state = Signal::derive(move || {
        oauth_query.with(|query| {
            query
                .as_ref()
                .map(|query| query.state.clone())
                .unwrap_or(None)
        })
    });

    // Uses Login server function
    let login = create_server_action::<Login>();
    // Used to fetch any errors returned from the Login function
    let login_value = login.value();

    let pending = login.pending();

    let verify_otp = create_server_action::<VerifyOtp>();

    let _verify_otp_value = verify_otp.value();

    let (two_factor_enabled, set_two_factor_enabled) = create_signal(false);

    let (username, set_username) = create_signal(None);

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <div class="container">
                {move || {
                    if two_factor_enabled() && username.get().is_some() {
                        view! {
                            <ActionForm class="login-form" action=verify_otp>
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="username"
                                    value=username.get().unwrap()
                                />
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="client_id"
                                    value=client_id()
                                />
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="state"
                                    value=state()
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
                    } else if !two_factor_enabled() && username.get().is_none() {
                        view! {
                            <h1>"Welcome to Leptos!"</h1>
                            <ActionForm class="login-form" action=login>
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="client_id"
                                    value=client_id()
                                />
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="state"
                                    value=state()
                                />
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
                                {move || {
                                    if !client_id().is_none() || !state().is_none(){
                                        view! {
                                            <A href=format!("/signup?client_id={}&state={}", client_id().unwrap(), state().unwrap()) class="forgot-password-btn">
                                            "Don't have an account? Sign up!"
                                            </A>
                                        }
                                    }else{
                                        view! {
                                            <A href="/signup" class="forgot-password-btn">
                                            "Don't have an account? Sign up!"
                                            </A>
                                        }
                                    }
                                }}
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
                                                set_two_factor_enabled(true);
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
pub fn Signup() -> impl IntoView {
    let oauth_query = use_query::<OAuthRequest>();

    let client_id = Signal::derive(move || {
        oauth_query.with(|query: &Result<OAuthRequest, ParamsError>| {
            query
                .as_ref()
                .map(|query: &OAuthRequest| query.client_id.clone())
                .unwrap_or(None)
        })
    });
    let state = Signal::derive(move || {
        oauth_query.with(|query| {
            query
                .as_ref()
                .map(|query| query.state.clone())
                .unwrap_or(None)
        })
    });
    // Uses the SignUp server function
    let signup = create_server_action::<Signup>();
    // Used to fetch any errors returned from the server
    let signup_value = signup.value();
    // Used for client side password validation
    let (passwords_match, set_passwords_match) = create_signal(true);

    let pending = signup.pending();

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
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="client_id"
                                    value=client_id()
                                />
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="state"
                                    value=state()
                                />
                                <div class="mb-3">
                                    <label class="form-label">

                                        <input
                                            class="form-control"
                                            type="text"
                                            name="first_name"
                                            required=true
                                            placeholder="First Name"
                                        />
                                    </label>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">

                                        <input
                                            class="form-control"
                                            type="text"
                                            name="last_name"
                                            required=true
                                            placeholder="Last Name"
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
                                            type="email"
                                            name="email"
                                            required=true
                                            placeholder="Email"
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
                                            maxLength=16
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
                                            maxLength=16
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
                }}

            </div>

        </div>
    }
}

#[component]
pub fn ForgotPassword() -> impl IntoView {
    let forgot_password = create_server_action::<RequestPasswordReset>();
    let pending = forgot_password.pending();

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <div class="container">
                {move || {
                    if pending() {
                        view! { <h1>Emailing reset instructions...</h1> }.into_view()
                    } else {
                        view! {
                            <h1>Forgot Password</h1>
                            <p>
                                "Enter your username. If a valid account exists, you will receive an email with reset instructions"
                            </p>
                            <ActionForm class="login-form" action=forgot_password>
                                <div class="mb-3">
                                    <label class="form-label">
                                        "Username"
                                        <input
                                            class="form-control"
                                            type="text"
                                            name="username"
                                            required=true
                                        />
                                    </label>
                                </div>
                                <input
                                    class="btn btn-primary"
                                    type="submit"
                                    value="Request Password Reset"
                                />
                            </ActionForm>
                        }
                            .into_view()
                    }
                }}

            </div>

        </div>
    }
}

#[component]
pub fn EnableTwoFactor(
    user: ReadSignal<UserBasicInfo>,
    set_user: WriteSignal<UserBasicInfo>,
    set_enable_two_factor: WriteSignal<bool>,
) -> impl IntoView {
    let qr_code = create_resource(
        || (),
        move |_| async move { generate_2fa(user.get().username.to_string()).await },
    );

    let enable_2fa = create_server_action::<Enable2FA>();
    let loading = qr_code.loading();
    let value = enable_2fa.value();
    view! {
        {move || {
            if loading() {
                view! { <h1>loading...</h1> }.into_view()
            } else {
                let (encoded, token) = qr_code.get().unwrap().unwrap();
                view! {
                    <ActionForm class="login-form" action=enable_2fa>
                        <img src=format!("data:image/png;base64,{}", encoded) alt="QR Code"/>
                        <input
                            class="form-control"
                            type="hidden"
                            name="username"
                            value=user.get().username
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
                        if value().is_some() && value().unwrap().unwrap() {
                            set_user(UserBasicInfo{
                                two_factor: true,
                                ..user.get()
                            });
                            set_enable_two_factor(false);
                        }
                    }}
                }
                    .into_view()
            }
        }}
    }
}

#[component]
pub fn ResetPassword() -> impl IntoView {
    let params = use_params_map();
    let generated_id =
        move || params.with(|params| params.get("generated_id").cloned().unwrap_or_default());
    let (passwords_match, set_passwords_match) = create_signal(true);
    // Uses the SignUp server function
    let reset_password = create_server_action::<PasswordReset>();
    // Used to fetch any errors returned from the server
    let reset_password_value = reset_password.value();

    let pending = reset_password.pending();
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <div class="container">
                {move || {
                    if pending() {
                        view! { <h1>Resetting password...</h1> }.into_view()
                    } else {
                        view! {
                            <h1>Reset Password</h1>
                            <ActionForm
                                class="login-form"
                                on:submit=move |ev| {
                                    let data = PasswordReset::from_event(&ev);
                                    if data.is_err() {
                                        ev.prevent_default();
                                    } else {
                                        let data_values = data.unwrap();
                                        if data_values.password != data_values.confirm_password
                                        {
                                            set_passwords_match(false);
                                            ev.prevent_default();
                                        }
                                    }
                                }

                                action=reset_password
                            >
                                <div class="mb-3">
                                    <label class="form-label">
                                        <input
                                            class="form-control"
                                            type="text"
                                            name="username"
                                            required=true
                                            placeholder="Username"
                                        />
                                    </label>
                                </div>
                                <input
                                    class="form-control"
                                    type="hidden"
                                    name="reset_token"
                                    value=move || generated_id()
                                />
                                <div class="mb-3">
                                    <label class="form-label">
                                        <input
                                            class="form-control"
                                            type="password"
                                            name="new_password"
                                            required=true
                                            minLength=8
                                            maxLength=16
                                            pattern=PASSWORD_PATTERN
                                            placeholder="New Password"
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
                                            maxLength=16
                                            pattern=PASSWORD_PATTERN
                                            placeholder="Confirm New Password"
                                        />
                                    </label>
                                </div>
                                <input
                                    class="btn btn-primary"
                                    type="submit"
                                    value="Update Password"
                                />
                            </ActionForm>
                            {move || {
                                if !passwords_match.get() {
                                    view! { <p>Passwords do not match</p> }.into_view()
                                } else {
                                    view! {}.into_view()
                                }
                            }}

                            {move || {
                                match reset_password_value.get() {
                                    Some(response) => {
                                        match response {
                                            Ok(_) => view! {}.into_view(),
                                            Err(server_err) => {
                                                view! { <p>{format!("{}", server_err.to_string())}</p> }
                                                    .into_view()
                                            }
                                        }
                                    }
                                    None => view! {}.into_view(),
                                }
                            }}
                        }
                            .into_view()
                    }
                }}

            </div>
        </div>
    }
}

#[component]
pub fn Verify() -> impl IntoView {
    let params = use_params_map();
    let generated_id =
        move || params.with(|params| params.get("generated_id").cloned().unwrap_or_default());

    let verify_user = create_server_action::<VerifyUser>();
    let validation_result = verify_user.value();
    let pending = verify_user.pending();

    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            {move || {
                if !pending() {
                    if validation_result.get().is_some() {
                        view! {
                            <h1>There was an error verifying your account</h1>
                            <p>Your verification link could have expired. Try resending</p>
                        }
                            .into_view()
                    } else {
                        view! {
                            <div class="container">
                                <ActionForm class="login-form" action=verify_user>
                                    <div class="mb-3">
                                        <label class="form-label">
                                            <input
                                                class="form-control"
                                                type="text"
                                                name="username"
                                                required=true
                                                placeholder="Username"
                                            />
                                        </label>
                                    </div>
                                    <input
                                        class="form-control"
                                        type="hidden"
                                        name="verification_token"
                                        value=generated_id()
                                    />
                                    <input
                                        class="btn btn-primary"
                                        type="submit"
                                        value="Verify Account"
                                    />
                                </ActionForm>
                            </div>
                        }
                            .into_view()
                    }
                } else {
                    view! { <h1>Verifying...</h1> }.into_view()
                }
            }}

        </div>
    }
}

#[component]
pub fn ChangePassword(username: String) -> impl IntoView {
    let update_password = create_server_action::<UpdatePassword>();

    let update_password_value = update_password.value();

    let (passwords_match, set_passwords_match) = create_signal(true);
    let (old_pass_used, set_old_pass_used) = create_signal(false);
    view! {
        <h1>Change Password</h1>
        <div style:font-family="sans-serif" style:text-align="center">
            <ActionForm
                class="login-form"
                on:submit=move |ev| {
                    let data = UpdatePassword::from_event(&ev);
                    if data.is_err() {
                        ev.prevent_default();
                    } else {
                        let data_values = data.unwrap();
                        if data_values.password != data_values.confirm_password {
                            set_passwords_match(false);
                            ev.prevent_default();
                        }
                        if data_values.password == data_values.current_password {
                            set_old_pass_used(true);
                            ev.prevent_default();
                        }
                    }
                }

                action=update_password
            >
                <input class="form-control" type="hidden" name="username" value=username/>
                <div class="mb-3">
                    <label class="form-label">
                        <input
                            class="form-control"
                            type="password"
                            name="current_password"
                            required=true
                            placeholder="Current Password"
                        />
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        <input
                            class="form-control"
                            type="password"
                            name="new_password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                            placeholder="New Password"
                        />
                    </label>
                </div>
                <div class="mb-3">
                    <label class="form-label">
                        <input
                            class="form-control"
                            type="password"
                            name="confirm_new_password"
                            required=true
                            minLength=8
                            maxLength=16
                            pattern=PASSWORD_PATTERN
                            placeholder="Confirm Password"
                        />
                    </label>
                </div>
                <input class="btn btn-primary" type="submit" value="Update Password"/>
                <A class="forgot-password-btn" href="/user">
                    "To user"
                </A>
            </ActionForm>
            {move || {
                if !passwords_match.get() {
                    view! { <p>Passwords do not match</p> }.into_view()
                } else {
                    view! {}.into_view()
                }
            }}

            {move || {
                if old_pass_used.get() {
                    view! { <p>New password cannot match current password</p> }.into_view()
                } else {
                    view! {}.into_view()
                }
            }}

            {move || {
                match update_password_value.get() {
                    Some(response) => {
                        match response {
                            Ok(_) => view! {}.into_view(),
                            Err(server_err) => {
                                view! { <p>{format!("{}", server_err.to_string())}</p> }.into_view()
                            }
                        }
                    }
                    None => view! {}.into_view(),
                }
            }}

        </div>
    }
}
