use crate::{controllers::*, OAuthRequest};
use leptos::*;
use leptos_router::*;

static PASSWORD_PATTERN: &str =
    "^.*(?=.{8,}).*(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@!:#$^;%&?]).+$";

#[component]
pub fn Auth() -> impl IntoView {
    let oauth_query = use_query::<OAuthRequest>();

    let client_id = Signal::derive(move || {
        oauth_query.with(|query: &Result<OAuthRequest, ParamsError>| {
            query
                .as_ref()
                .map(|query: &OAuthRequest| query.client_id.clone())
                .unwrap_or("".to_string())
        })
    });
    let state = Signal::derive(move || {
        oauth_query.with(|query| {
            query
                .as_ref()
                .map(|query| query.state.clone())
                .unwrap_or("".to_string())
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
                                    <div class="buttons">
                                        <A class="forgot-password-btn" href="/forgotpassword">
                                         "Forgot Password?"
                                        </A>
                                        <A href="/signup" class="button">
                                            "Don't have an account? Sign up!"
                                        </A>
                                </div>
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
pub fn SignUp() -> impl IntoView {
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
