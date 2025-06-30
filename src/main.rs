use axum::{
    routing::post,
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use solana_sdk::signature::{Keypair, Signer};
use std::net::SocketAddr;
use bs58;
use axum::Server;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret_bytes = keypair.to_bytes();
    let secret = bs58::encode(secret_bytes).into_string(); // ✅ Base58 encode 64-byte secret key

    let response = SuccessResponse {
        success: true,
        data: KeypairResponse { pubkey, secret },
    };

    (StatusCode::OK, Json(response))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/keypair", post(generate_keypair));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on http://{}", addr);

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
