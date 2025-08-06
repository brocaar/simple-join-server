use diesel::result::Error as ResultError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("object does not exist `{0}`")]
    NotFound(String),

    #[error("invalid request `{0}`")]
    InvalidRequest(String),

    #[error(transparent)]
    Diesel(#[from] diesel::result::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error(transparent)]
    Lrwn(#[from] lrwn::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

impl Error {
    pub fn from_diesel(e: diesel::result::Error, s: String) -> Self {
        match &e {
            ResultError::NotFound => Error::NotFound(s),
            _ => Error::Diesel(e),
        }
    }
}
