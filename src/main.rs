use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    Router,
};
use reqwest::Client;
use serde::Deserialize;
use std::{
    env,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::{
    signal,
    sync::mpsc::{self, Receiver, Sender},
};
use url::Url;

#[derive(Clone, Debug, Deserialize)]
struct ConfigCC {
    client_id: String,
    client_secret: String,
    token_endpoint: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ConfigAC {
    client_id: String,
    client_secret: String,
    token_endpoint: String,
    authorization_endpoint: String,
    port: u16,
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from .env file
    dotenvy::dotenv().ok();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(
            "Usage: {} [client_credentials|authorization_code|version]",
            args[0]
        );
        return Ok(());
    }

    let grant_type = &args[1];

    match grant_type.as_str() {
        "client_credentials" => {
            let config = load_config_cc();
            let access_token = get_client_credentials_token(&config).await?;
            println!("{}", access_token);
        }
        "authorization_code" => {
            let config = load_config_ac();
            println!("Starting callback handler");
            start_http_server(&config).await?;
        }
        "version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
        _ => println!("Invalid grant type specified"),
    }

    Ok(())
}

/// Load configuration from `.env` file for client credentials flow
fn load_config_cc() -> ConfigCC {
    ConfigCC {
        client_id: env::var("CLIENT_ID").expect("CLIENT_ID must be set"),
        client_secret: env::var("CLIENT_SECRET").expect("CLIENT_SECRET must be set"),
        token_endpoint: env::var("TOKEN_ENDPOINT").expect("TOKEN_ENDPOINT must be set"),
    }
}

/// Load configuration from `.env` file for authorization code flow
fn load_config_ac() -> ConfigAC {
    ConfigAC {
        client_id: env::var("CLIENT_ID").expect("CLIENT_ID must be set"),
        client_secret: env::var("CLIENT_SECRET").expect("CLIENT_SECRET must be set"),
        token_endpoint: env::var("TOKEN_ENDPOINT").expect("TOKEN_ENDPOINT must be set"),
        authorization_endpoint: env::var("AUTHORIZATION_ENDPOINT")
            .expect("AUTHORIZATION_ENDPOINT must be set"),
        port: env::var("PORT")
            .map_or_else(|_| "37080".to_string(), |p| p.to_string())
            .parse::<u16>()
            .expect("Cannot parse PORT"),
    }
}

/// Get access token through client credentials flow
async fn get_client_credentials_token(
    config: &ConfigCC,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let params = [("grant_type", "client_credentials")];

    let response = client
        .post(&config.token_endpoint)
        .form(&params)
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .send()
        .await?;

    let token_response: serde_json::Value = response.json().await?;
    Ok(token_response["access_token"].as_str().unwrap().to_string())
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
        .append_pair("response_type", "code");

    url.into()
}

/// Start HTTP server for authorization code flow
async fn start_http_server(config: &ConfigAC) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::new(IpAddr::from_str("::")?, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Cannot start server");
    let (tx, rx) = mpsc::channel(1);
    let redirect_uri = format!("http://127.0.0.1:{}/callback", addr.port());
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
