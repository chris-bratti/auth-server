#![allow(non_snake_case)]
use crate::client::admin_pages::AdminPage;
use crate::client::auth_pages::*;
use crate::client::client_helpers::get_user_from_session;
use crate::controllers::Logout;
use crate::UserBasicInfo;
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

#[derive(Clone)]
struct UserContext {
    pub user_signal: (ReadSignal<UserBasicInfo>, WriteSignal<UserBasicInfo>),
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/auth_server.css" />
        <Stylesheet
            id="boostrap"
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        />

        // sets the document title
        <Title text="Welcome to Auth Leptos" />

        // content for this welcome page
        <body class="dark-mode">
            <Router>
                <main>
                    <Routes>
                        <Route path="" view=HomePage />
                        <Route
                            path="/user"
                            view=|| {
                                view! {
                                    <UserVerificationWrapper>
                                        <UserProfile />
                                    </UserVerificationWrapper>
                                }
                            }
                        />
                        <Route path="/login" view=Login />
                        <Route path="/signup" view=Signup />
                        <Route path="/admin" view=AdminPage />
                        <Route path="/forgotpassword" view=ForgotPassword />
                        <Route path="/reset/:generated_id" view=ResetPassword />
                        <Route path="/verify/:generated_id" view=Verify />
                        <Route path="/*any" view=NotFound />
                    </Routes>
                </main>
            </Router>
        </body>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    // Basic homepage
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <div class="button-container">
                <div class="heading">"Welcome to Auth Leptos!"</div>
                <div class="buttons">
                    <A href="/login" class="button">
                        Login
                    </A>
                    <A href="/signup" class="button">
                        Sign Up
                    </A>
                    <A class="button" href="/user">
                        "To user"
                    </A>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn LoggedIn(children: ChildrenFn) -> impl IntoView {
    let user_result =
        create_blocking_resource(|| (), |_| async move { get_user_from_session().await });
    let children = store_value(children);
    let user_is_logged_in =
        move || user_result.get().is_some() && user_result.get().unwrap().is_ok();
    let user_is_verified = move || user_result.get().unwrap().unwrap().verified;
    let logged_in_fallback = || view! { <NotLoggedIn /> };
    let verified_fallback = || {
        view! { <NotVerified /> }
    };
    view! {
        <Suspense fallback=|| {
            view! { <h1>Loading....</h1> }
        }>
            <Show when=user_is_logged_in fallback=logged_in_fallback>

                {{
                    provide_context(UserContext {
                        user_signal: create_signal(user_result.get().unwrap().unwrap()),
                    })
                }}

                <Show when=user_is_verified fallback=verified_fallback>
                    {children.with_value(|children| children())}
                </Show>
            </Show>
        </Suspense>
    }
}

#[component]
pub fn UserVerificationWrapper(children: ChildrenFn) -> impl IntoView {
    let children = store_value(children);
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <LoggedIn>{children.with_value(|children| children())}</LoggedIn>
        </div>
    }
}

#[component]
pub fn UserProfile() -> impl IntoView {
    let (user, set_user): (ReadSignal<UserBasicInfo>, WriteSignal<UserBasicInfo>) =
        expect_context::<UserContext>().user_signal;
    let (update_password, set_update_password) = create_signal(false);
    let (enable_two_factor, set_enable_two_factor) = create_signal(false);
    let logout = create_server_action::<Logout>();
    view! {
        {move || {
            if update_password.get() {
                view! {
                    <div class="container">
                        <ChangePassword username=user.get().username />
                        <button class="button" on:click=move |_| { set_update_password(false) }>

                            Cancel
                        </button>
                    </div>
                }
                    .into_view()
            } else if enable_two_factor.get() {
                view! {
                    <div class="container">
                        <EnableTwoFactor
                            user=user
                            set_user=set_user
                            set_enable_two_factor=set_enable_two_factor
                        />
                        <button class="button" on:click=move |_| { set_enable_two_factor(false) }>
                            Cancel
                        </button>
                    </div>
                }
                    .into_view()
            } else {
                view! {
                    <div style:font-family="sans-serif" style:text-align="center">
                        <div class="button-container">
                            <div class="heading">
                                {format!(
                                    "Welcome {} {}!",
                                    user.get().first_name,
                                    user.get().last_name,
                                )}

                            </div>
                            <div class="buttons">
                                <button
                                    class="button"
                                    on:click=move |_| {
                                        if update_password.get() {
                                            set_update_password(false)
                                        } else {
                                            set_enable_two_factor(false);
                                            set_update_password(true);
                                        }
                                    }
                                >

                                    Update Password
                                </button>
                                {move || {
                                    if user.get().two_factor {
                                        view! {}.into_view()
                                    } else {
                                        view! {
                                            <button
                                                class="button"
                                                on:click=move |_| {
                                                    if enable_two_factor.get() {
                                                        set_enable_two_factor(false)
                                                    } else {
                                                        set_update_password(false);
                                                        set_enable_two_factor(true);
                                                    }
                                                }
                                            >

                                                Enable Two Factor Authentication
                                            </button>
                                        }
                                            .into_view()
                                    }
                                }}

                                <A class="button" href="/">
                                    "Home"
                                </A>
                                <button class="button" on:click=move |_| logout.dispatch(Logout {})>
                                    "Logout"
                                </button>
                            </div>
                        </div>
                    </div>
                }
                    .into_view()
            }
        }}
    }
}

#[component]
fn NotLoggedIn() -> impl IntoView {
    view! {
        <div style:font-family="sans-serif" style:text-align="center">
            <div class="button-container">
                <div class="heading">"You need to be logged in to view this page"</div>
                <div class="buttons">
                    <A href="/login" class="button">
                        Login
                    </A>
                    <A href="/signup" class="button">
                        Sign Up
                    </A>
                    <A class="button" href="/">
                        "Home"
                    </A>
                </div>
            </div>
        </div>
    }
}

#[component]
fn NotVerified() -> impl IntoView {
    view! {
        <h1>Your email is not verified</h1>
        <p>Please follow the link we sent to your inbox to verify your email!</p>
        <div>
            <A class="btn btn-primary" href="/">
                "Home"
            </A>
        </div>
    }
}

/// 404 - Not Found
#[component]
fn NotFound() -> impl IntoView {
    // set an HTTP status code 404
    // this is feature gated because it can only be done during
    // initial server-side rendering
    // if you navigate to the 404 page subsequently, the status
    // code will not be set because there is not a new HTTP request
    // to the server
    #[cfg(feature = "ssr")]
    {
        // this can be done inline because it's synchronous
        // if it were async, we'd use a server function
        let resp = expect_context::<leptos_actix::ResponseOptions>();
        resp.set_status(actix_web::http::StatusCode::NOT_FOUND);
    }

    view! { <h1>"Not Found"</h1> }
}
