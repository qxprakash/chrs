//! Predecessors to [ChrisClient] for getting _ChRIS_ authorization
//! tokens or creating _ChRIS_ accounts.

use crate::types::{CubeUrl, ItemUrl, UserId, Username};
use serde::{Deserialize, Serialize};
use reqwest::StatusCode;
use thiserror::Error;


#[derive(Deserialize)]
struct AuthTokenResponse {
    // clippy doesn't know how serde works
    #[allow(dead_code)]
    token: String,
}

#[derive(Deserialize)]
pub struct UserCreatedResponse {
    pub url: ItemUrl,
    pub id: UserId,
    pub username: Username,
    pub email: String,
    // feed: Vec  // idk what this is
}

#[derive(Serialize)]
struct Credentials<'a> {
    username: &'a Username,
    password: &'a str,
}

#[derive(Serialize)]
struct CreateUserData<'a> {
    username: &'a Username,
    password: &'a str,
    email: &'a str,
}


#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Status {0}: Invalid username or password")]
    InvalidCredentials(StatusCode),

    #[error("Status {1}: Server error - {0}")]
    ServerError(String, StatusCode),

    #[error("Status {0}: Unexpected response - The specified URL might not be a valid CUBE URL")]
    UnexpectedResponse(StatusCode),

    #[error("Status {1:?}: Network error - {0}")]
    NetworkError(reqwest::Error, Option<StatusCode>),

    #[error("Status {1}: Failed to parse response - {0}")]
    ParseError(String, StatusCode),

    #[error("Status {0}: Resource not found - The specified URL might be incorrect")]
    NotFound(StatusCode),
}

/// CUBE username and password struct.
/// [Account] is a builder for [ChrisClient].
pub struct Account<'a> {
    pub client: reqwest::Client,
    pub url: &'a CubeUrl,
    pub username: &'a Username,
    pub password: &'a str,
}

impl<'a> Account<'a> {
    pub fn new(url: &'a CubeUrl, username: &'a Username, password: &'a str) -> Self {
        Self {
            client: Default::default(),
            url,
            username,
            password,
        }
    }

    pub async fn get_token(&self) -> Result<String, AuthError> {
        let auth_url = format!("{}auth-token/", &self.url);
        let req = self
            .client
            .post(auth_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&Credentials {
                username: self.username,
                password: self.password,
            });

        let res = req.send().await.map_err(|e| AuthError::NetworkError(e, None))?;
        let status = res.status();

        match status {
            StatusCode::OK => {
                let text = res.text().await.map_err(|e| AuthError::NetworkError(e, Some(status)))?;
                serde_json::from_str::<AuthTokenResponse>(&text)
                    .map(|token_object| token_object.token)
                    .map_err(|e| AuthError::ParseError(e.to_string(), status))
            }
            StatusCode::UNAUTHORIZED => Err(AuthError::InvalidCredentials(status)),
            StatusCode::NOT_FOUND => Err(AuthError::NotFound(status)),
            status if status.is_server_error() => {
                Err(AuthError::ServerError(status.to_string(), status))
            }
            _ => Err(AuthError::UnexpectedResponse(status)),
        }
    }

    pub async fn create_account(&self, email: &str) -> Result<UserCreatedResponse, reqwest::Error> {
        let users_url = format!("{}users/", &self.url);
        let req = self
            .client
            .post(users_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&CreateUserData {
                username: self.username,
                password: self.password,
                email,
            });
        let res = req.send().await?;
        res.error_for_status_ref()?;
        let created_user: UserCreatedResponse = res.json().await?;
        Ok(created_user)
    }
}

