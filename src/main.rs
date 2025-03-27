use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    Router,
};
use color_eyre::eyre::{eyre, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    signal,
    sync::mpsc::{self, Receiver, Sender},
};
use url::Url;

/// Client credentials flow configuration
#[derive(Clone, Debug)]
struct ConfigCC {
    client_id: String,
    client_secret: String,
    scope: Option<String>,
    token_endpoint: String,
}

/// Device code flow configuration
#[derive(Clone, Debug)]
struct ConfigDC {
    client_id: String,
    client_secret: String,
    scope: Option<String>,
    token_endpoint: String,
    device_authorization_endpoint: String,
}

/// Authorization code flow configuration
#[derive(Clone, Debug)]
struct ConfigAC {
    client_id: String,
    client_secret: String,
    scope: String,
    token_endpoint: String,
    authorization_endpoint: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    verification_uri_complete: String,
    expires_in: u32,
    interval: u64,
}

#[derive(Debug)]
struct AppState {
    tx: Sender<i32>,
    redirect_uri: String,
    config: ConfigAC,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQueryParams {
    code: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let filename = env::var("OIDC_ENVFILE").unwrap_or_default();
    if !filename.is_empty() {
        dotenvy::from_filename(&filename)
            .wrap_err_with(|| format!("Failed to read settings from file {}", filename))?;
    } else {
        // Load configuration from .env file
        let _ = dotenvy::dotenv();
    }

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(
            "Usage: {} [client_credentials|device_authorization|authorization_code|version]",
            args[0]
        );
        return Ok(());
    }

    let grant_type = &args[1];

    match grant_type.as_str() {
        "c" | "client_credentials" => {
            let config = load_config_cc()?;
            let access_token = get_client_credentials_token(&config).await?;
            println!("{}", access_token);
        }
        "d" | "device_authorization" => {
            let config = load_config_dc()?;
            let access_token = get_device_authorization_token(&config).await?;
            println!("{}", access_token);
        }
        "a" | "authorization_code" => {
            let config = load_config_ac()?;
            println!("Starting callback handler");
            start_http_server(&config).await?;
        }
        "v" | "version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
        _ => println!("Invalid grant type specified"),
    }

    Ok(())
}

/// Load configuration from `.env` file for client credentials flow
fn load_config_cc() -> Result<ConfigCC> {
    Ok(ConfigCC {
        client_id: env::var("CLIENT_ID").context("CLIENT_ID must be set")?,
        client_secret: env::var("CLIENT_SECRET").context("CLIENT_SECRET must be set")?,
        scope: env::var("SCOPE").ok(),
        token_endpoint: env::var("TOKEN_ENDPOINT").context("TOKEN_ENDPOINT must be set")?,
    })
}

/// Load configuration from `.env` file for device code flow
fn load_config_dc() -> Result<ConfigDC> {
    Ok(ConfigDC {
        client_id: env::var("CLIENT_ID").context("CLIENT_ID must be set")?,
        client_secret: env::var("CLIENT_SECRET").context("CLIENT_SECRET must be set")?,
        device_authorization_endpoint: env::var("DEVICE_AUTHORIZATION_ENDPOINT")
            .context("DEVICE_AUTHORIZATION_ENDPOINT must be set")?,
        scope: env::var("SCOPE").ok(),
        token_endpoint: env::var("TOKEN_ENDPOINT").context("TOKEN_ENDPOINT must be set")?,
    })
}

/// Load configuration from `.env` file for authorization code flow
fn load_config_ac() -> Result<ConfigAC> {
    let mut scope = env::var("SCOPE").unwrap_or_default();
    if scope.is_empty() {
        scope = "openid profile email".to_string();
    };
    Ok(ConfigAC {
        client_id: env::var("CLIENT_ID").context("CLIENT_ID must be set")?,
        client_secret: env::var("CLIENT_SECRET").context("CLIENT_SECRET must be set")?,
        scope,
        token_endpoint: env::var("TOKEN_ENDPOINT").context("TOKEN_ENDPOINT must be set")?,
        authorization_endpoint: env::var("AUTHORIZATION_ENDPOINT")
            .context("AUTHORIZATION_ENDPOINT must be set")?,
        port: env::var("PORT")
            .map_or_else(|_| "37080".to_string(), |p| p.to_string())
            .parse::<u16>()
            .context("Cannot parse PORT")?,
    })
}

/// Get access token through client credentials flow
async fn get_client_credentials_token(config: &ConfigCC) -> Result<String> {
    let client = Client::new();
    let mut params = HashMap::new();
    params.insert("grant_type", "client_credentials");

    // Add scope if provided
    if let Some(ref scope) = config.scope {
        params.insert("scope", scope);
    }

    let response = client
        .post(&config.token_endpoint)
        .form(&params)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .send()
        .await?;

    if response.status().is_client_error() || response.status().is_server_error() {
        return Err(eyre!(
            "Request failed: {}. Is client `{}` configured for client credentials grant?",
            response.status(),
            config.client_id
        ));
    }

    let token_response: serde_json::Value = response.json().await?;
    Ok(token_response["access_token"]
        .as_str()
        .ok_or_else(|| {
            eyre!(
                "No access token provided. Is client `{}` configured for client credentials grant?",
                config.client_id
            )
        })?
        .to_string())
}

/// Get access token through device code flow
async fn get_device_authorization_token(config: &ConfigDC) -> Result<String> {
    let client = Client::new();
    let mut params = HashMap::new();
    params.insert("client_id", &config.client_id);
    params.insert("client_secret", &config.client_secret);

    // Add scope if provided
    if let Some(ref scope) = config.scope {
        params.insert("scope", scope);
    }

    let response = client
        .post(&config.device_authorization_endpoint)
        .form(&params)
        .send()
        .await?;

    if response.status().is_client_error() || response.status().is_server_error() {
        return Err(eyre!(
            "Request failed: {}. Is client `{}` configured for device authorization grant?",
            response.status(),
            config.client_id
        ));
    }

    let device_code_response: DeviceAuthorizationResponse = response
        .json()
        .await
        .context("Reading device authorization response")?;

    let grant_type = "urn:ietf:params:oauth:grant-type:device_code".to_string();
    params.insert("device_code", &device_code_response.device_code);
    params.insert("grant_type", &grant_type);

    println!("Opening browser for authentication...");
    println!("{}", device_code_response.verification_uri_complete);
    open::that(device_code_response.verification_uri_complete)?;

    let polling_timeout = Duration::from_secs(device_code_response.expires_in as u64);
    let polling_start = Instant::now();
    let mut token_response = None;
    // Poll for device code authorization
    loop {
        if token_response.is_some() {
            break;
        }

        // if polling_timeout is up, break the loop
        if Instant::now().duration_since(polling_start) >= polling_timeout {
            return Err(eyre!("Device authorization timed out"));
        }

        let response = client
            .post(&config.token_endpoint)
            .form(&params)
            .send()
            .await?;

        let response_status = response.status();
        if response_status.is_client_error() || response_status.is_server_error() {
            if response.status() == 400 {
                let j = response
                    .json::<serde_json::Value>()
                    .await
                    .context("Reading polling response")?;
                let error_description = j.get("error").and_then(|e| e.as_str()).unwrap_or_default();
                if error_description == "authorization_pending" {
                    tokio::time::sleep(Duration::from_secs(device_code_response.interval)).await;
                    continue;
                }
            }

            return Err(eyre!(
                "Request failed: {}. Is client `{}` configured for device authorization grant?",
                response_status,
                config.client_id
            ));
        }

        let token_response2: serde_json::Value = response.json().await?;
        token_response = Some(token_response2["access_token"]
            .as_str()
            .ok_or_else(|| {
                eyre!(
                "No access token provided. Is client `{}` configured for device authorization grant?",
                config.client_id
            )
            })?
            .to_string())
    }

    // return the access token or an error if none is received
    token_response.ok_or_else(|| eyre!("No access token received after polling"))
}

/// Handle Ctrl+C and SIGTERM signals
async fn shutdown_signal(mut rx: Receiver<i32>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = rx.recv() => {},
    }
}

/// Prepare authorization URL
fn build_authorization_url(config: &ConfigAC, callback_url: &str) -> String {
    let mut url = Url::parse(&config.authorization_endpoint).unwrap();
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", callback_url)
        .append_pair("scope", &config.scope)
        .append_pair("response_type", "code");

    url.into()
}

/// Start HTTP server for authorization code flow
async fn start_http_server(config: &ConfigAC) -> Result<()> {
    let addr = SocketAddr::new(IpAddr::from_str("::")?, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .wrap_err_with(|| format!("Cannot start server at http://{addr}"))?;
    let (tx, rx) = mpsc::channel(1);
    let redirect_uri = format!("http://localhost:{}/callback", addr.port());
    let app_state = Arc::new(AppState {
        tx,
        redirect_uri: redirect_uri.clone(),
        config: config.clone(),
    });
    let app = Router::new()
        .route("/callback", axum::routing::get(handle_request))
        .with_state(app_state);

    let server_task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(shutdown_signal(rx))
            .await
            .unwrap();
    });
    let auth_url = build_authorization_url(config, &redirect_uri);
    println!("Opening browser for authentication...");
    println!("{}", auth_url);
    open::that(auth_url)?;

    println!("Waiting for authorization code callback...");
    let _ = server_task.await;
    Ok(())
}

/// Handle authorization code callback
async fn handle_request(
    callback_query_params: Query<CallbackQueryParams>,
    State(app_state): State<Arc<AppState>>,
) -> Result<Html<String>, axum::response::Response> {
    let access_token = get_authorization_code_token(
        &app_state.config,
        &callback_query_params.code,
        &app_state.redirect_uri,
    )
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response());

    let _ = app_state
        .tx
        .send(if access_token.is_err() { 1 } else { 0 })
        .await;
    println!("{}", access_token?);
    Ok(Html("<html>You can close this window now. Or <a href=\"https://login.qwirl.de/realms/BRB/protocol/openid-connect/logout\">logout</a>.</html>".to_string()))
}

/// Get access token through authorization code flow
async fn get_authorization_code_token(
    config: &ConfigAC,
    code: &str,
    redirect_uri: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];

    let response = client
        .post(&config.token_endpoint)
        .form(&params)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .send()
        .await?;

    let token_response: serde_json::Value = response.json().await?;
    Ok(token_response["access_token"].as_str().unwrap().to_string())
}
