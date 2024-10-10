use std::{collections::HashMap, env};

use supabase_auth::models::{
    AuthClient, DesktopResendParams, LogoutScope, ResendParams, SSOSignInOptions, SSOSuccess,
    SignInWithOAuthOptions, SignInWithSSO, UpdateUserPayload,
};

fn create_test_client() -> AuthClient {
    AuthClient::new_from_env().unwrap()
}

#[tokio::test]
async fn create_client_test_valid() {
    let auth_client = AuthClient::new_from_env().unwrap();

    assert!(*auth_client.project_url() == env::var("SUPABASE_URL").unwrap())
}

#[tokio::test]
async fn test_login_with_email() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await
        .unwrap();

    assert!(session.user.email == demo_email)
}

#[tokio::test]
async fn test_login_with_email_invalid() {
    let auth_client = create_test_client();

    let demo_email = "invalid@demo.com";
    let demo_password = "invalid";

    let session = auth_client
        .login_with_email(demo_email, demo_password)
        .await;

    assert!(session.is_err())
}

#[tokio::test]
async fn sign_in_with_phone_and_password_test() {
    let auth_client = create_test_client();

    let demo_phone = env::var("DEMO_PHONE").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .sign_in_with_phone_and_password(&demo_phone, &demo_password)
        .await
        .unwrap();

    assert!(session.user.phone == demo_phone)
}

#[tokio::test]
async fn sign_up_with_email_test_valid() {
    let auth_client = create_test_client();

    let uuid = uuid::Uuid::now_v7();

    let demo_email = format!("signup__{}@demo.com", uuid);
    let demo_password = "ciJUAojfZZYKfCxkiUWH";

    let session = auth_client
        .sign_up_with_email_and_password(demo_email.as_ref(), demo_password)
        .await
        .unwrap();

    assert!(session.user.email == demo_email)
}

#[tokio::test]
async fn sign_up_with_phone_test_valid() {
    let auth_client = create_test_client();

    let demo_phone = "13334445555";
    let demo_password = "ciJUAojfZZYKfCxkiUWH";

    let session = auth_client
        .sign_up_with_phone_and_password(demo_phone, demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    assert!(session.is_ok() && session.unwrap().user.phone == "13334445555")
}

#[tokio::test]
async fn send_login_email_with_magic_link() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();

    let _response = auth_client
        .send_login_email_with_magic_link(demo_email)
        .await;

    assert!(_response.is_ok())
}

#[tokio::test]
async fn send_email_with_otp() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();

    let response = auth_client.send_email_with_otp(demo_email, None).await;

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    assert!(response.is_ok())
}

#[tokio::test]
async fn send_sms_with_otp() {
    let auth_client = create_test_client();

    let demo_phone = "1333444555";

    let response = auth_client.send_sms_with_otp(demo_phone).await;

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    assert!(response.is_ok())
}

#[tokio::test]
async fn sign_in_with_oauth_test() {
    let auth_client = create_test_client();

    // Must login to get a user bearer token
    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(demo_email, demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let mut params = HashMap::new();
    params.insert("key".to_string(), "value".to_string());
    params.insert("second_key".to_string(), "second_value".to_string());
    params.insert("third_key".to_string(), "third_value".to_string());

    let options = SignInWithOAuthOptions {
        query_params: Some(params),
        redirect_to: Some("localhost".to_string()),
        scopes: Some("repo gist notifications".to_string()),
        skip_brower_redirect: Some(true),
    };

    let response = auth_client
        .sign_in_with_oauth(supabase_auth::models::Provider::Github, Some(options))
        .await
        .unwrap();

    if response.status() != 200 {
        println!("SIGN IN WITH OAUTH TEST RESPONSE -- \n{:?}", response);
    }
}

#[tokio::test]
async fn sign_in_with_oauth_no_options_test() {
    let auth_client = create_test_client();

    // Must login to get a user bearer token
    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(demo_email, demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let response = auth_client
        .sign_in_with_oauth(supabase_auth::models::Provider::Github, None)
        .await;

    println!(
        "SIGN IN WITH OAUTH \n NO OPTIONS TEST RESPONSE -- \n{:?}",
        response
    );

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    assert!(response.is_ok())
}

#[tokio::test]
async fn get_user_test() {
    let auth_client = create_test_client();

    // Must login to get a user bearer token
    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let user = auth_client
        .get_user(session.unwrap().access_token)
        .await
        .unwrap();

    assert!(user.email == demo_email)
}

#[tokio::test]
async fn update_user_test() {
    let auth_client = create_test_client();

    // Must login to get a user bearer token
    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let updated_user = UpdateUserPayload {
        email: Some(demo_email.clone()),
        password: Some("qqqqwwww".to_string()),
        data: None,
    };

    let first_response = auth_client
        .update_user(updated_user, session.unwrap().access_token)
        .await;

    if first_response.is_err() {
        eprintln!("{:?}", first_response.as_ref().unwrap_err())
    }

    // Login with new password to validate the change
    let test_password = "qqqqwwww";

    let new_session = auth_client
        .login_with_email(demo_email.as_ref(), test_password)
        .await;

    if new_session.is_err() {
        eprintln!("{:?}", new_session.as_ref().unwrap_err())
    }

    // Return the user to original condition
    let original_user = UpdateUserPayload {
        email: Some(demo_email),
        password: Some("qwerqwer".to_string()),
        data: None,
    };

    let second_response = auth_client
        .update_user(original_user, new_session.unwrap().access_token)
        .await;

    assert!(second_response.is_ok())
}

#[tokio::test]
async fn exchange_token_for_session() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let original_session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await
        .unwrap();

    assert!(original_session.user.email == demo_email);

    println!(
        "REFRESH TOKEN BEING TESTED -- {}",
        original_session.refresh_token
    );

    let new_session = auth_client
        .refresh_session(original_session.refresh_token)
        .await
        .unwrap();

    assert!(new_session.user.email == demo_email)
}

#[tokio::test]
async fn reset_password_for_email_test() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();

    let response = auth_client.reset_password_for_email(demo_email).await;

    assert!(response.is_ok())
}

#[tokio::test]
async fn resend_email_test() {
    let auth_client = create_test_client();

    let uuid = uuid::Uuid::now_v7();

    let demo_email = format!("signup__{}@demo.com", uuid);
    let demo_password = "ciJUAojfZZYKfCxkiUWH";

    let session = auth_client
        .sign_up_with_email_and_password(demo_email.clone(), demo_password.to_string())
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let credentials = DesktopResendParams {
        otp_type: supabase_auth::models::EmailOtpType::Email,
        email: demo_email.to_owned(),
        options: None,
    };

    let response = auth_client.resend(ResendParams::Desktop(credentials)).await;

    assert!(response.is_ok() && session.unwrap().user.email == demo_email)
}

#[tokio::test]
async fn logout_test() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(demo_email, demo_password.to_string())
        .await
        .unwrap();

    let logout = auth_client
        .logout(Some(LogoutScope::Global), session.access_token)
        .await
        .unwrap();

    assert!(logout.status().is_success())
}

#[tokio::test]
async fn get_settings_test() {
    let auth_client = create_test_client();

    let settings = auth_client.get_settings().await.unwrap();

    assert!(settings.external.github == true)
}

#[tokio::test]
async fn get_health_test() {
    let auth_client = create_test_client();

    let health = auth_client.get_health().await.unwrap();

    assert!(health.description != "")
}
