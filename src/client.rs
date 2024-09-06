use std::env;

use reqwest::{
    header::{self, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client, Response, StatusCode,
};

use crate::{
    error::Error,
    models::{
        Provider, RequestMagicLinkPayload, Session, SignInWithEmailAndPasswordPayload,
        SignInWithPhoneAndPasswordPayload, SignUpWithEmailAndPasswordPayload,
        SignUpWithPhoneAndPasswordPayload, UpdateUserPayload, User,
    },
};

/// Supabase Auth Client
/// You can find your project url and keys at https://supabase.com/dashboard/project/<your project id>/settings/api
pub struct AuthClient {
    pub client: Client,
    /// REST endpoint for querying and managing your database
    /// Example: https://<project id>.supabase.co
    pub project_url: String,
    /// WARN: The `service role` key has the ability to bypass Row Level Security. Never share it publicly.
    pub api_key: String,
    /// Used to decode your JWTs. You can also use this to mint your own JWTs.
    pub jwt_secret: String,
}

impl AuthClient {
    /// Create a new AuthClient
    /// Will use `SUPABASE_URL` `SUPABASE_API_KEY` and `SUPABASE_JWT_SECRET` environment variables if no params are provided
    pub fn new<S: Into<String>>(
        project_url: Option<S>,
        api_key: Option<S>,
        jwt_secret: Option<S>,
    ) -> Self {
        let client = Client::new();

        let project_url = project_url
            .map(Into::into)
            .or_else(|| env::var("SUPABASE_URL").ok())
            .unwrap_or_else(String::new);

        let api_key = api_key
            .map(Into::into)
            .or_else(|| env::var("SUPABASE_API_KEY").ok())
            .unwrap_or_else(String::new);

        let jwt_secret = jwt_secret
            .map(Into::into)
            .or_else(|| env::var("SUPABASE_JWT_SECRET").ok())
            .unwrap_or_else(String::new);

        AuthClient {
            client,
            project_url,
            api_key,
            jwt_secret,
        }
    }

    pub async fn sign_in_with_email_and_password<S: Into<String>>(
        &self,
        email: S,
        password: S,
    ) -> Result<Session, Error> {
        let payload = SignInWithEmailAndPasswordPayload {
            email: email.into(),
            password: password.into(),
        };

        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!(
                "{}/auth/v1/token?grant_type=password",
                self.project_url
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str(&response)?)
    }

    pub async fn sign_in_with_phone_and_password<S: Into<String>>(
        &self,
        phone: S,
        password: S,
    ) -> Result<Session, Error> {
        let payload = SignInWithPhoneAndPasswordPayload {
            phone: phone.into(),
            password: password.into(),
        };

        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!(
                "{}/auth/v1/token?grant_type=password",
                self.project_url
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str(&response)?)
    }

    pub async fn sign_up_with_email_and_password<S: Into<String>>(
        &self,
        email: S,
        password: S,
    ) -> Result<Session, Error> {
        let payload = SignUpWithEmailAndPasswordPayload {
            email: email.into(),
            password: password.into(),
        };

        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}/auth/v1/signup", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str::<Session>(&response)?)
    }

    pub async fn sign_up_with_phone_and_password<S: Into<String>>(
        &self,
        phone: S,
        password: S,
    ) -> Result<Session, Error> {
        let payload = SignUpWithPhoneAndPasswordPayload {
            phone: phone.into(),
            password: password.into(),
        };

        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}/auth/v1/signup", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str::<Session>(&response)?)
    }

    pub async fn send_login_email_with_magic_link<S: Into<String>>(
        &self,
        email: S,
    ) -> Result<Response, Error> {
        let payload = RequestMagicLinkPayload {
            email: email.into(),
        };

        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}/auth/v1/magiclink", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        Ok(response)
    }

    // Login with SMS OTP
    pub async fn send_sms_with_otp<S: Into<String>>(&self, phone: S) -> Result<Response, Error> {
        let payload = phone.into();

        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}/auth/v1/opt", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        Ok(response)
    }

    // TODO: Add scopes and redirects and query params
    pub async fn sign_in_with_oauth(&self, provider: Provider) -> Result<Response, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let response = self
            .client
            .get(format!(
                "{}/auth/v1/authorize?provider={}",
                self.project_url,
                provider.to_string()
            ))
            .headers(headers)
            .send()
            .await?;

        Ok(response)
    }

    /// Get the User struct of the logged in user
    pub async fn get_user<S: Into<String>>(&self, bearer_token: S) -> Result<User, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("apikey", self.api_key.parse().unwrap());
        let token = format!("Bearer {}", &bearer_token.into());
        headers.insert(
            AUTHORIZATION,
            // TODO: Handle this
            HeaderValue::from_str(&token).unwrap(),
        );

        let user = self
            .client
            .get(format!("{}/auth/v1/user", self.project_url))
            .headers(headers)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str(&user).unwrap())
    }

    /// Sends the user a log in link via email. Once logged in you should direct the user to a new password form. And use "Update User" below to save the new password.
    pub async fn forgotten_password_email<S: Into<String>>(&self, email: S) -> Result<(), Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("apikey", self.api_key.parse().unwrap());
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        let body = serde_json::to_string(&email.into())?;

        let user = self
            .client
            .post(format!("{}/auth/v1/recover", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        match user.status() {
            StatusCode::OK => Ok(()),
            _ => Err(Error::InternalError),
        }
    }

    /// Update the user with a new email or password. Each key (email, password, and data) is optional
    pub async fn update_user<S: Into<String>>(
        &self,
        updated_user: UpdateUserPayload,
        bearer_token: S,
    ) -> Result<User, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("apikey", self.api_key.parse().unwrap());
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", &bearer_token.into()))?,
        );

        let payload = UpdateUserPayload {
            email: updated_user.email,
            password: updated_user.password,
            data: updated_user.data,
        };

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .put(format!("{}/auth/v1/user", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await;

        Ok(serde_json::from_str::<User>(&response.unwrap())?)
    }
    // log out current user
    // invite user with email
}
