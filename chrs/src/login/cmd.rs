use super::prompt::{prompt_if_missing, prompt_if_missing_password};
use super::state::ChrsSessions;
use super::store;
use crate::credentials::Credentials;
use chris::{
    types::{CubeUrl, Username},
    Account, AnonChrisClient, ChrisClient
};
use chris::AuthError;
use color_eyre::eyre::{bail, Context, Result, eyre};
use color_eyre::owo_colors::OwoColorize;
use color_eyre::Help; // Import the Help trait

pub async fn login(
    Credentials {
        cube_url,
        username,
        password,
        token,
        ui,
        config_path,
        ..
    }: Credentials,
    backend: store::Backend,
    password_from_stdin: bool,
) -> Result<()> {
    if password.is_some() && password_from_stdin {
        bail!(
            "Options {} and {} may not be used together.",
            "--password".bold(),
            "--password-stdin".bold()
        );
    }

    let mut config = ChrsSessions::load(config_path.as_deref())?;
    let cube = prompt_if_missing(cube_url, "ChRIS API address")?;
    let username = prompt_if_missing(username, "username")?;

    let token = if username.as_str().is_empty() {
        login_anonymous(&cube).await
    } else if let Some(token) = token {
        login_with_token(&cube, &username, &token).await
    } else {
        let password = prompt_if_missing_password(password, "password", password_from_stdin)?;
        login_with_password(&cube, &username, &password).await
    }?;

    let login = store::CubeState {
        cube,
        token,
        username,
        current_plugin_instance_id: None,
        ui,
    };

    config.add(login, backend)?;
    config.save(config_path.as_deref())
}

/// Contact CUBE just to make sure CUBE is reachable.
async fn login_anonymous(cube_url: &CubeUrl) -> Result<Option<String>> {
    AnonChrisClient::build(cube_url.clone())?.connect().await?;
    Ok(None)
}

/// Login to CUBE by getting a token using a password.
async fn login_with_password(
    cube_url: &CubeUrl,
    username: &Username,
    password: &str,
) -> Result<Option<String>> {
    let account = Account {
        client: Default::default(),
        url: cube_url,
        username,
        password,
    };

    match account.get_token().await {
        Ok(token) => Ok(Some(token)),
        Err(err) => {
            let error_details = match &err {
                AuthError::InvalidCredentials(status) =>
                    format!("Invalid username or password | {} : {}", "Error Msg".yellow().bold(), status),
                AuthError::ServerError(msg, status) =>
                    format!("Server error: {} | {} : {} ",  msg, "Error Msg".yellow().bold(), status),
                AuthError::UnexpectedResponse(status) =>
                    format!("Status: {} | Unexpected response: The specified URL might not be a valid CUBE URL", status),
                AuthError::NetworkError(e, status) =>
                    format!("Network error | {} : {} | {}", "Error Msg".yellow().bold(), status.map_or("N/A".to_string(), |s| s.to_string()),e),
                AuthError::ParseError(e, status) =>
                    format!("Parse error | {}: {} -- Unexpected response, maybe the specified URL isn’t a CUBE URL? | {}: {}", "Error Msg".yellow().bold(), e, "Status Code".yellow().bold(), status),
                AuthError::NotFound(status) =>
                    format!("Not Found | {}: The specified URL might be incorrect , it might not be a CUBE URL | {} : {}", "Error Msg".yellow().bold(), "Status Code".yellow().bold(), status),
            };

            let suggestion = match &err {
                AuthError::InvalidCredentials(_) => "Please check your username and password and try again.",
                AuthError::ServerError(_, _) => "Please try again later or contact support if the issue persists.",
                AuthError::UnexpectedResponse(_) => "Please verify the URL and ensure it points to a valid CUBE instance.",
                AuthError::NetworkError(_, _) => "Please check your network connection and try again.",
                AuthError::ParseError(_, _) => "Please verify the URL and ensure it points to a valid CUBE instance.",
                AuthError::NotFound(_) => "Please verify the URL and ensure it points to a valid CUBE instance.",
            };

            Err(eyre!("Login failed\n{}: {}", "Error".red().bold(), error_details))
                .with_suggestion(|| suggestion.to_string())
        }
    }
}

/// Verify token works for the CUBE.
async fn login_with_token(
    cube_url: &CubeUrl,
    username: &Username,
    token: &str,
) -> Result<Option<String>> {
    ChrisClient::build(cube_url.clone(), username.clone(), token)?
        .connect()
        .await
        .wrap_err_with(|| format!("Invalid token for {cube_url}"))?;
    Ok(Some(token.to_string()))
}

pub fn logout(
    Credentials {
        cube_url,
        username,
        config_path,
        ..
    }: Credentials,
) -> Result<()> {
    let mut config = ChrsSessions::load(config_path.as_deref())?;
    if let Some(url) = cube_url {
        let removed = match username {
            Some(u) => config.remove(&url, Some(&u)),
            None => config.remove(&url, None),
        };
        if !removed {
            bail!("Not logged in.");
        }
    } else if !config.clear() {
        bail!("Not logged in.");
    }
    config.save(config_path.as_deref())
}