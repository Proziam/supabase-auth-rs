#![cfg(not(doctest))]

use std::env;

use reqwest::{
    header::{self, HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client, Response,
};

use crate::{
    error::Error,
    models::{
        AuthClient, Provider, RefreshSessionPayload, RequestMagicLinkPayload, ResendParams,
        ResetPasswordForEmailPayload, Session, SignInEmailOtpParams,
        SignInWithEmailAndPasswordPayload, SignInWithEmailOtpPayload, SignInWithIdTokenCredentials,
        SignInWithOAuthOptions, SignInWithPhoneAndPasswordPayload,
        SignUpWithEmailAndPasswordPayload, SignUpWithPhoneAndPasswordPayload, UpdateUserPayload,
        User, VerifyOtpParams,
    },
};

impl AuthClient {
    /// Create a new Auth Client
    /// You can find your project url and keys at https://supabase.com/dashboard/project/<your project id>/settings/api
    pub fn new(
        project_url: impl Into<String>,
        api_key: impl Into<String>,
        jwt_secret: impl Into<String>,
    ) -> Self {
        AuthClient {
            client: Client::new(),
            project_url: project_url.into(),
            api_key: api_key.into(),
            jwt_secret: jwt_secret.into(),
        }
    }

    /// Create a new AuthClient from environment variables
    /// Requires `SUPABASE_URL`, `SUPABASE_API_KEY`, and `SUPABASE_JWT_SECRET` environment variables
    /// ```
    /// let auth_client = AuthClient::new_from_env().unwrap();
    ///
    /// assert!(auth_client.project_url == env::var("SUPABASE_URL").unwrap())
    /// ```
    pub fn new_from_env() -> Result<AuthClient, Error> {
        let project_url = env::var("SUPABASE_URL")?;
        let api_key = env::var("SUPABASE_API_KEY")?;
        let jwt_secret = env::var("SUPABASE_JWT_SECRET")?;

        Ok(AuthClient {
            client: Client::new(),
            project_url,
            api_key,
            jwt_secret,
        })
    }

    /// Sign in a user with an email and password
    /// ```
    /// let session = auth_client
    ///     .sign_in_with_email_and_password(demo_email, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.email == demo_email)
    /// ```
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
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
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

    /// Sign in a user with phone number and password
    /// ```
    /// let session = auth_client
    ///     .sign_in_with_phone_and_password(demo_phone, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.phone == demo_phone)
    /// ```
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
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

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

    /// Sign up a new user with an email and password
    /// ```
    /// let session = auth_client
    ///     .sign_up_with_email_and_password(demo_email, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.email == demo_email)
    ///```
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
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

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

    /// Sign up a new user with an email and password
    /// ```
    /// let session = auth_client
    ///     .sign_up_with_phone_and_password(demo_phone, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.phone == demo_phone)
    ///```
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
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

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

    /// Sends a login email containing a magic link
    /// ```
    /// let _response = auth_client
    ///     .send_login_email_with_magic_link(demo_email)
    ///    .await
    ///    .unwrap();
    ///```
    pub async fn send_login_email_with_magic_link<S: Into<String>>(
        &self,
        email: S,
    ) -> Result<Response, Error> {
        let payload = RequestMagicLinkPayload {
            email: email.into(),
        };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

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

    /// Send a Login OTP via SMS
    /// ```
    /// let response = auth_client.send_sms_with_otp(demo_phone).await;
    /// ```
    pub async fn send_sms_with_otp<S: Into<String>>(&self, phone: S) -> Result<Response, Error> {
        let payload = phone.into();

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

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
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

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
    /// ```
    /// // You can add custom parameters using a HashMap<String, String>
    /// let mut params = HashMap::new();
    /// params.insert("key".to_string(), "value".to_string());
    ///
    /// let options = SignInWithOAuthOptions {
    ///     query_params: Some(params),
    ///     redirect_to: Some("localhost".to_string()),
    ///     scopes: Some("repo gist notifications".to_string()),
    ///     skip_brower_redirect: Some(true),
    /// };
    ///
    /// let response = auth_client
    ///     .sign_in_with_oauth(supabase_auth::models::Provider::Github, Some(options))
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn sign_in_with_oauth(
        &self,
        provider: Provider,
        options: Option<SignInWithOAuthOptions>,
    ) -> Result<Response, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

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

    /// Return the signed in User
    /// ```
    /// let user = auth_client
    ///     .get_user(session.unwrap().access_token)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(user.email == demo_email)
    /// ```
    pub async fn get_user<S: Into<String>>(&self, bearer_token: S) -> Result<User, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        let token = format!("Bearer {}", &bearer_token.into());
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&token)?);

        let user = self
            .client
            .get(format!("{}/auth/v1/user", self.project_url))
            .headers(headers)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str(&user)?)
    }

    /// Update the user, such as changing email or password. Each field (email, password, and data) is optional
    /// ```
    /// let updated_user_data = UpdateUserPayload {
    ///     email: Some("demo@demo.com".to_string()),
    ///     password: Some("demo_password".to_string()),
    ///     data: None, // This field can hold any valid JSON value
    /// };
    ///
    /// let user = auth_client
    ///     .update_user(updated_user_data, access_token)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn update_user<S: Into<String>>(
        &self,
        updated_user: UpdateUserPayload,
        bearer_token: S,
    ) -> Result<User, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
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
            .await?;

        Ok(serde_json::from_str(&response)?)
    }

    /// Allows signing in with an OIDC ID token. The authentication provider used should be enabled and configured.
    pub async fn sign_in_with_id_token(
        &self,
        credentials: SignInWithIdTokenCredentials,
    ) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

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
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

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
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&params)?;

        let response = self
            .client
            .post(&format!("{}/auth/v1/verify", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str(&response)?)
    }

    pub async fn exchange_token_for_session<S: Into<String>>(
        &self,
        refresh_token: S,
    ) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&RefreshSessionPayload {
            refresh_token: refresh_token.into(),
        })?;

        let response = self
            .client
            .post(&format!(
                "{}/auth/v1/token?grant_type=refresh_token",
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

    pub async fn refresh_session(&self, refresh_token: String) -> Result<Session, Error> {
        self.exchange_token_for_session(refresh_token).await
    }

    /// Send a password recovery email. Invalid Email addresses will return Error Code 400.
    /// Valid email addresses that are not registered as users will not return an error.
    pub async fn reset_password_for_email<S: Into<String>>(
        &self,
        email: S,
    ) -> Result<Response, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&ResetPasswordForEmailPayload {
            email: email.into(),
        })?;

        let response = self
            .client
            .post(&format!("{}/auth/v1/recover", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        Ok(response)
    }

    /// Resends emails for existing signup confirmation, email change, SMS OTP, or phone change OTP.
    pub async fn resend(&self, credentials: ResendParams) -> Result<Response, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&credentials)?;

        let response = self
            .client
            .post(&format!("{}/auth/v1/resend", self.project_url))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        Ok(response)
    }
}
