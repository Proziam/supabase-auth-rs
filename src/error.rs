use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("User Already Exists")]
    AlreadySignedUp,
    #[error("Invalid Credentials")]
    WrongCredentials,
    #[error("User Not Found")]
    UserNotFound,
    #[error("Supabase Client not Authenticated")]
    NotAuthenticated,
    #[error("Missing Refresh Token")]
    MissingRefreshToken,
    #[error("JWT Is Invalid")]
    WrongToken,
    #[error("Internal Error")]
    InternalError,
    #[error("Network Error")]
    NetworkError(#[from] reqwest::Error),
    #[error("Failed to Parse")]
    ParseError(#[from] serde_json::Error),
    #[error("Header Value is Invalid")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
}
