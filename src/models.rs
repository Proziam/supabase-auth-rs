use core::fmt;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

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
    pub(crate) email: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) data: Option<serde_json::Value>,
}

#[derive(Debug)]
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
