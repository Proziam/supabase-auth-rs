use std::env;

use reqwest::{
    header::{self, HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client, Response, StatusCode,
};

use crate::{
    error::Error,
    models::{
        Provider, RequestMagicLinkPayload, Session, SignInEmailOtpParams,
        SignInWithEmailAndPasswordPayload, SignInWithEmailOtpPayload, SignInWithIdTokenCredentials,
        SignInWithOAuthOptions, SignInWithPhoneAndPasswordPayload,
        SignUpWithEmailAndPasswordPayload, SignUpWithPhoneAndPasswordPayload, UpdateUserPayload,
        User, VerifyEmailOtpParams, VerifyMobileOtpParams, VerifyOtpParams, VerifyTokenHashParams,
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
    pub fn new(
        project_url: impl Into<String>,
        api_key: impl Into<String>,
        jwt_secret: impl Into<String>,
    ) -> Self {
        let client = Client::new();

        AuthClient {
            client,
            project_url: project_url.into(),
            api_key: api_key.into(),
            jwt_secret: jwt_secret.into(),
        }
    }

    /// Create a new AuthClient from environment variables
    /// Requires `SUPABASE_URL`, `SUPABASE_API_KEY`, and `SUPABASE_JWT_SECRET` environment variables
    pub fn new_from_env() -> Result<AuthClient, Error> {
        let client = Client::new();

        let project_url = env::var("SUPABASE_URL")?;
        let api_key = env::var("SUPABASE_API_KEY")?;
        let jwt_secret = env::var("SUPABASE_JWT_SECRET")?;

        Ok(AuthClient {
            client,
            project_url: project_url.into(),
            api_key: api_key.into(),
            jwt_secret: jwt_secret.into(),
        })
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
            .post(format!("{}/auth/v1/otp", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        Ok(response)
    }

    // Login with Email OTP
    pub async fn send_email_with_otp<S: Into<String>>(
        &self,
        email: S,
        options: Option<SignInEmailOtpParams>,
    ) -> Result<Response, Error> {
        let payload = SignInWithEmailOtpPayload {
            email: email.into(),
            options,
        };

        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}/auth/v1/otp", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        Ok(response)
    }

    /// Sign in a user using an OAuth provider.
    pub async fn sign_in_with_oauth(
        &self,
        provider: Provider,
        options: Option<SignInWithOAuthOptions>,
    ) -> Result<Response, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("apikey", self.api_key.parse().unwrap());

        let body = serde_json::to_string(&options)?;

        let response = self
            .client
            .get(format!(
                "{}/auth/v1/authorize?provider={}",
                self.project_url,
                provider.to_string()
            ))
            .headers(headers)
            .body(body)
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

        let body = serde_json::to_string::<UpdateUserPayload>(&updated_user)?;

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

    /// Allows signing in with an OIDC ID token. The authentication provider used should be enabled and configured.
    pub async fn sign_in_with_id_token(
        &self,
        credentials: SignInWithIdTokenCredentials,
    ) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", self.api_key.parse().unwrap());
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        let body = serde_json::to_string(&credentials)?;

        let response = self
            .client
            .post(format!(
                "{}/auth/v1/token?grant_type=id_token",
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

    /// Sends an invite link to an email address.
    pub async fn invite_user_by_email<S: Into<String>>(&self, email: S) -> Result<User, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", self.api_key.parse().unwrap());
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        let body = serde_json::to_string(&email.into())?;

        let response = self
            .client
            .post(format!("{}/auth/v1/invite", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str(&response)?)
    }

    pub async fn verify_otp(&self, params: VerifyOtpParams) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", self.api_key.parse()?);
        headers.insert(CONTENT_TYPE, "application/json".parse()?);

        let body = match params {
            VerifyOtpParams::Mobile(params) => {
                serde_json::to_string::<VerifyMobileOtpParams>(&params)?
            }
            VerifyOtpParams::Email(params) => {
                serde_json::to_string::<VerifyEmailOtpParams>(&params)?
            }
            VerifyOtpParams::TokenHash(params) => {
                serde_json::to_string::<VerifyTokenHashParams>(&params)?
            }
        };

        let client = Client::new();

        let response = client
            .post(&format!("{}/auth/v1/verify", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str(&response)?)
    }
}
