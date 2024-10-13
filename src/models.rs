#![cfg(not(doctest))]

use core::fmt;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display};

/// Supabase Auth Client
pub struct AuthClient {
    pub(crate) client: Client,
    /// REST endpoint for querying and managing your database
    /// Example: https://<project id>.supabase.co
    pub(crate) project_url: String,
    /// WARN: The `service role` key has the ability to bypass Row Level Security. Never share it publicly.
    pub(crate) api_key: String,
    /// Used to decode your JWTs. You can also use this to mint your own JWTs.
    pub(crate) jwt_secret: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub expires_at: u64,
    pub refresh_token: String,
    pub user: User,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub aud: String,
    pub role: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed_at: Option<String>,
    pub phone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_sent_at: Option<String>,
    pub last_sign_in_at: String,
    pub app_metadata: AppMetadata,
    pub user_metadata: UserMetadata,
    pub identities: Vec<Identity>,
    pub created_at: String,
    pub updated_at: String,
    pub is_anonymous: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AppMetadata {
    pub provider: String,
    pub providers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UserMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IdTokenCredentials {
    /// Provider name or OIDC iss value identifying which provider should be used to verify the provided token.
    pub provider: Provider,
    /// OIDC ID token issued by the specified provider. The iss claim in the ID token must match the supplied provider. Some ID tokens contain an at_hash which require that you provide an access_token value to be accepted properly. If the token contains a nonce claim you must supply the nonce used to obtain the ID token.
    pub token: String,
    /// If the ID token contains an at_hash claim, then the hash of this value is compared to the value in the ID token.
    pub access_token: Option<String>,
    /// If the ID token contains a nonce claim, then the hash of this value is compared to the value in the ID token.
    pub nonce: Option<String>,
    /// Optional Object which may contain a captcha token
    pub gotrue_meta_security: Option<GotrueMetaSecurity>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignInWithOAuthOptions {
    pub query_params: Option<HashMap<String, String>>,
    pub redirect_to: Option<String>,
    pub scopes: Option<String>,
    pub skip_brower_redirect: Option<bool>,
}

#[derive(Debug)]
pub struct OAuthResponse {
    pub url: Url,
    pub provider: Provider,
}

#[derive(Debug, Serialize)]
pub struct GotrueMetaSecurity {
    /// Verification token received when the user completes the captcha on the site.
    captcha_token: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub identity_id: String,
    pub id: String,
    pub user_id: String,
    pub identity_data: IdentityData,
    pub provider: String,
    pub last_sign_in_at: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone_verified: bool,
    pub sub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoginOptions {
    Email(String),
    Phone(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInWithEmailAndPasswordPayload {
    pub(crate) email: String,
    pub(crate) password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInWithPhoneAndPasswordPayload {
    pub(crate) phone: String,
    pub(crate) password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignUpWithEmailAndPasswordPayload {
    pub(crate) email: String,
    pub(crate) password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignUpWithPhoneAndPasswordPayload {
    pub(crate) phone: String,
    pub(crate) password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMagicLinkPayload {
    pub(crate) email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserPayload {
    pub email: Option<String>,
    pub password: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendSMSOtpPayload {
    pub phone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTPResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum VerifyOtpParams {
    Mobile(VerifyMobileOtpParams),
    Email(VerifyEmailOtpParams),
    TokenHash(VerifyTokenHashParams),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyMobileOtpParams {
    /// The user's phone number.
    pub phone: String,
    /// The otp sent to the user's phone number.
    pub token: String,
    /// The user's verification type.
    #[serde(rename = "type")]
    pub otp_type: MobileOtpType,
    /// Optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<VerifyOtpOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEmailOtpParams {
    /// The user's phone number.
    pub email: String,
    /// The otp sent to the user's phone number.
    pub token: String,
    /// The user's verification type.
    #[serde(rename = "type")]
    pub otp_type: EmailOtpType,
    /// Optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<VerifyOtpOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyTokenHashParams {
    /// The user's phone number.
    pub token_hash: String,
    /// The user's verification type.
    #[serde(rename = "type")]
    pub otp_type: MobileOtpType,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailOtpType {
    Signup,
    Invite,
    Magiclink,
    Recovery,
    EmailChange,
    Email,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileOtpType {
    Sms,
    PhoneChange,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyOtpOptions {
    /// A URL to send the user to after they are confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SignInWithOtp {
    Mobile(SignInMobileOtpParams),
    Email(SignInEmailOtpParams),
    WhatsApp(SignInMobileOtpParams),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignInWithEmailOtpPayload {
    pub email: String,
    pub options: Option<SignInEmailOtpParams>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignInWithEmailOtp {
    /// The user's phone number.
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<SignInEmailOtpParams>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignInEmailOtpParams {
    /// Verification token received when the user completes the captcha on the site.
    pub captcha_token: Option<String>,
    /// A custom data object to store the user's metadata. This maps to the `auth.users.raw_user_meta_data` column.
    pub data: Option<serde_json::Value>,
    /// The redirect url embedded in the email link
    pub email_redirect_to: Option<String>,
    /// If set to false, this method will not create a new user. Defaults to true.
    pub should_create_user: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignInMobileOtpParams {
    /// Verification token received when the user completes the captcha on the site.
    pub captcha_token: Option<String>,
    /// A custom data object to store the user's metadata. This maps to the `auth.users.raw_user_meta_data` column.
    pub data: Option<serde_json::Value>,
    /// The redirect url embedded in the email link
    pub channel: Option<Channel>,
    /// If set to false, this method will not create a new user. Defaults to true.
    pub should_create_user: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshSessionPayload {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResetPasswordForEmailPayload {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ResendParams {
    Desktop(DesktopResendParams),
    Mobile(MobileResendParams),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DesktopResendParams {
    #[serde(rename = "type")]
    pub otp_type: EmailOtpType,
    pub email: String,
    pub options: Option<DesktopResendOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DesktopResendOptions {
    pub email_redirect_to: Option<String>,
    pub captcha_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MobileResendParams {
    #[serde(rename = "type")]
    pub otp_type: MobileOtpType,
    pub phone: String,
    pub options: Option<MobileResendOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MobileResendOptions {
    captcha_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Sms,
    Whatsapp,
}

impl Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Channel::Sms => write!(f, "sms"),
            Channel::Whatsapp => write!(f, "whatsapp"),
        }
    }
}

/// Health status of the Auth Server
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthServerHealth {
    /// Version of the service
    pub version: String,
    /// Name of the service
    pub name: String,
    /// Description of the service
    pub description: String,
}

/// Settings of the Auth Server
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthServerSettings {
    pub external: External,
    pub disable_signup: bool,
    pub mailer_autoconfirm: bool,
    pub phone_autoconfirm: bool,
    pub sms_provider: String,
    pub saml_enabled: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct External {
    pub anonymous_users: bool,
    pub apple: bool,
    pub azure: bool,
    pub bitbucket: bool,
    pub discord: bool,
    pub facebook: bool,
    pub figma: bool,
    pub fly: bool,
    pub github: bool,
    pub gitlab: bool,
    pub google: bool,
    pub keycloak: bool,
    pub kakao: bool,
    pub linkedin: bool,
    pub linkedin_oidc: bool,
    pub notion: bool,
    pub spotify: bool,
    pub slack: bool,
    pub slack_oidc: bool,
    pub workos: bool,
    pub twitch: bool,
    pub twitter: bool,
    pub email: bool,
    pub phone: bool,
    pub zoom: bool,
}

#[derive(Debug, Serialize, Deserialize)]
/// Currently enabled OAuth providers.
///
/// # Example
/// ```
/// let provider = Provider::Github.to_string();
/// println!("{provider}") // "github"
/// ```
pub enum Provider {
    Apple,
    Azure,
    Bitbucket,
    Discord,
    Facebook,
    Figma,
    Fly,
    Github,
    Gitlab,
    Google,
    Kakao,
    Keycloak,
    Linkedin,
    LinkedinOidc,
    Notion,
    Slack,
    SlackOidc,
    Spotify,
    Twitch,
    Twitter,
    Workos,
    Zoom,
}

impl Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Provider::Apple => write!(f, "apple"),
            Provider::Azure => write!(f, "azure"),
            Provider::Bitbucket => write!(f, "bitbucket"),
            Provider::Discord => write!(f, "discord"),
            Provider::Facebook => write!(f, "facebook"),
            Provider::Figma => write!(f, "figma"),
            Provider::Fly => write!(f, "fly"),
            Provider::Github => write!(f, "github"),
            Provider::Gitlab => write!(f, "gitlab"),
            Provider::Google => write!(f, "google"),
            Provider::Kakao => write!(f, "kakao"),
            Provider::Keycloak => write!(f, "keycloak"),
            Provider::Linkedin => write!(f, "linkedin"),
            Provider::LinkedinOidc => write!(f, "linkedin_oidc"),
            Provider::Notion => write!(f, "notion"),
            Provider::Slack => write!(f, "slack"),
            Provider::SlackOidc => write!(f, "slack_oidc"),
            Provider::Spotify => write!(f, "spotify"),
            Provider::Twitch => write!(f, "twitch"),
            Provider::Twitter => write!(f, "twitter"),
            Provider::Workos => write!(f, "workos"),
            Provider::Zoom => write!(f, "zoom"),
        }
    }
}

/// Represents the scope of the logout operation
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogoutScope {
    Global,
    Local,
    Others,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignInWithSSO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<SSOSignInOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SSOSignInOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    captcha_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SSOSuccess {
    pub url: String,
    pub status: u16,
    pub headers: Headers,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Headers {
    pub date: String,
    #[serde(rename = "content-type")]
    pub content_type: String,
    #[serde(rename = "transfer-encoding")]
    pub transfer_encoding: String,
    pub connection: String,
    pub server: String,
    pub vary: String,
    #[serde(rename = "x-okta-request-id")]
    pub x_okta_request_id: String,
    #[serde(rename = "x-xss-protection")]
    pub x_xss_protection: String,
    pub p3p: String,
    #[serde(rename = "set-cookie")]
    pub set_cookie: Vec<String>,
    #[serde(rename = "content-security-policy-report-only")]
    pub content_security_policy_report_only: String,
    #[serde(rename = "content-security-policy")]
    pub content_security_policy: String,
    #[serde(rename = "x-rate-limit-limit")]
    pub x_rate_limit_limit: String,
    #[serde(rename = "x-rate-limit-remaining")]
    pub x_rate_limit_remaining: String,
    #[serde(rename = "x-rate-limit-reset")]
    pub x_rate_limit_reset: String,
    #[serde(rename = "referrer-policy")]
    pub referrer_policy: String,
    #[serde(rename = "accept-ch")]
    pub accept_ch: String,
    #[serde(rename = "cache-control")]
    pub cache_control: String,
    pub pragma: String,
    pub expires: String,
    #[serde(rename = "x-frame-options")]
    pub x_frame_options: String,
    #[serde(rename = "x-content-type-options")]
    pub x_content_type_options: String,
    #[serde(rename = "x-ua-compatible")]
    pub x_ua_compatible: String,
    #[serde(rename = "content-language")]
    pub content_language: String,
    #[serde(rename = "strict-transport-security")]
    pub strict_transport_security: String,
    #[serde(rename = "x-robots-tag")]
    pub x_robots_tag: String,
}

// Implement custom Debug to avoid exposing sensitive information
impl fmt::Debug for AuthClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthClient")
            .field("project_url", &self.project_url())
            .field("api_key", &"[REDACTED]")
            .field("jwt_secret", &"[REDACTED]")
            .finish()
    }
}
