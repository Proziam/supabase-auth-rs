use std::env;

use reqwest::header;
use supabase_auth::client::AuthClient;

#[tokio::test]
async fn create_client_test_valid() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    assert!(auth_client.project_url == test_project_url)
}

#[tokio::test]
async fn sign_in_with_password_test_valid() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    let demo_email = "demo@demo.com";
    let demo_password = "qwerqwer";

    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("apikey", auth_client.api_key.parse().unwrap());

    let session = auth_client
        .sign_in_with_email_and_password(demo_email, demo_password)
        .await;

    assert!(session.is_ok() && session.unwrap().user.email == demo_email)
}

#[tokio::test]
async fn sign_in_with_password_test_invalid() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    let demo_email = "invalid@demo.com";
    let demo_password = "invalid";

    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("apikey", auth_client.api_key.parse().unwrap());

    let session = auth_client
        .sign_in_with_email_and_password(demo_email, demo_password)
        .await;

    assert!(session.is_err())
}

#[tokio::test]
async fn sign_up_with_email_test_valid() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    let uuid = uuid::Uuid::now_v7();

    let demo_email = format!("signup__{}@demo.com", uuid);
    let demo_password = "ciJUAojfZZYKfCxkiUWH";

    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("apikey", auth_client.api_key.parse().unwrap());

    let session = auth_client
        .sign_up_with_email_and_password(demo_email.clone(), demo_password.to_string())
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    assert!(session.is_ok() && session.unwrap().user.email == demo_email)
}

#[tokio::test]
async fn sign_up_with_phone_test_valid() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    let demo_phone = "13334445555";
    let demo_password = "ciJUAojfZZYKfCxkiUWH";

    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("apikey", auth_client.api_key.parse().unwrap());

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
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    let demo_email = "demo@demo.com";

    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("apikey", auth_client.api_key.parse().unwrap());

    let response = auth_client
        .send_login_email_with_magic_link(demo_email)
        .await;

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    assert!(response.is_ok())
}

#[tokio::test]
async fn send_sms_with_otp() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    let demo_phone = "1333444555";

    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("apikey", auth_client.api_key.parse().unwrap());

    let response = auth_client.send_sms_with_otp(demo_phone).await;

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    assert!(response.is_ok())
}

#[tokio::test]
async fn sign_in_with_oauth_test() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    // Must login to get a user bearer token
    let demo_email = "demo@demo.com";
    let demo_password = "qwerqwer";

    let session = auth_client
        .sign_in_with_email_and_password(demo_email, demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("apikey", auth_client.api_key.parse().unwrap());
    headers.insert(header::AUTHORIZATION, auth_client.api_key.parse().unwrap());

    let response = auth_client
        .sign_in_with_oauth(supabase_auth::models::Provider::Github)
        .await;

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    assert!(response.is_ok())
}

#[tokio::test]
async fn get_user_test() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    // Must login to get a user bearer token
    let demo_email = "demo@demo.com";
    let demo_password = "qwerqwer";

    let session = auth_client
        .sign_in_with_email_and_password(demo_email, demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let user = auth_client.get_user(session.unwrap().access_token).await;

    if user.is_err() {
        eprintln!("{:?}", user.as_ref().unwrap_err())
    }

    assert!(user.is_ok())
}

#[tokio::test]
async fn update_user_test() {
    let test_project_url = env::var("SUPABASE_URL").unwrap();
    let test_api_key = env::var("SUPABASE_API").unwrap();
    let test_jwt_secret = env::var("SUPABASE_JWT_SECRET").unwrap();

    let auth_client = AuthClient::new(
        Some(&test_project_url),
        Some(&test_api_key),
        Some(&test_jwt_secret),
    );

    // Must login to get a user bearer token
    let demo_email = "demo@demo.com";
    let demo_password = "qwerqwer";

    let session = auth_client
        .sign_in_with_email_and_password(demo_email, demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let user = auth_client.get_user(session.unwrap().access_token).await;

    if user.is_err() {
        eprintln!("{:?}", user.as_ref().unwrap_err())
    }

    assert!(user.is_ok())
}