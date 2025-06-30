// main.rs
use axum::{
    routing::{get, post},
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use bs58;
use base64;
use hyper::Server;
use solana_sdk::{
    signature::{Keypair, Signer, Signature},
};
use solana_program::{instruction::AccountMeta, pubkey::Pubkey};
use spl_token::{instruction::{initialize_mint, mint_to}, ID as TOKEN_PROGRAM_ID};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running at http://{}", addr);

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> &'static str {
    "server is running go to /keypair , /token/create , /token/mint , /message/sign , and /message/verify "
}

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

fn error(msg: &str) -> ErrorResponse {
    ErrorResponse {
        success: false,
        error: msg.to_string(),
    }
}

fn decode_pubkey(s: &str) -> Result<Pubkey, String> {
    bs58::decode(s)
        .into_vec()
        .map_err(|_| "Invalid base58".to_string())
        .and_then(|bytes| Pubkey::try_from(bytes.as_slice()).map_err(|_| "Invalid pubkey bytes".to_string()))
}


#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = SuccessResponse {
        success: true,
        data: KeypairResponse { pubkey, secret },
    };

    (StatusCode::OK, Json(response)).into_response()
}


#[derive(Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaInfo>,
    instruction_data: String,
}

async fn create_token(Json(body): Json<CreateTokenRequest>) -> impl IntoResponse {
    let mint_authority = match decode_pubkey(&body.mintAuthority) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&e))).into_response(),
    };
    let mint = match decode_pubkey(&body.mint) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&e))).into_response(),
    };

    let instruction = match initialize_mint(&TOKEN_PROGRAM_ID, &mint, &mint_authority, None, body.decimals) {
        Ok(instr) => instr,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&format!("Init mint failed: {e}")))).into_response(),
    };

    let accounts = instruction.accounts.into_iter().map(|a| AccountMetaInfo {
        pubkey: a.pubkey.to_string(),
        is_signer: a.is_signer,
        is_writable: a.is_writable,
    }).collect();

    let response = SuccessResponse {
        success: true,
        data: InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(instruction.data),
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}


#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(Json(body): Json<MintTokenRequest>) -> impl IntoResponse {
    let mint = match decode_pubkey(&body.mint) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&e))).into_response(),
    };
    let dest = match decode_pubkey(&body.destination) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&e))).into_response(),
    };
    let authority = match decode_pubkey(&body.authority) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&e))).into_response(),
    };

    let instruction = match mint_to(&TOKEN_PROGRAM_ID, &mint, &dest, &authority, &[], body.amount) {
        Ok(instr) => instr,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&format!("Mint failed: {e}")))).into_response(),
    };

    let accounts = instruction.accounts.into_iter().map(|a| AccountMetaInfo {
        pubkey: a.pubkey.to_string(),
        is_signer: a.is_signer,
        is_writable: a.is_writable,
    }).collect();

    let response = SuccessResponse {
        success: true,
        data: InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(instruction.data),
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}


#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(Json(body): Json<SignMessageRequest>) -> impl IntoResponse {
    let secret_bytes = match bs58::decode(&body.secret).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(_) => return (StatusCode::BAD_REQUEST, Json(error("Secret must be 64 bytes"))).into_response(),
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Invalid base58 in secret"))).into_response(),
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Failed to parse keypair"))).into_response(),
    };

    let signature = keypair.sign_message(body.message.as_bytes());

    let response = SuccessResponse {
        success: true,
        data: SignMessageResponse {
            signature: base64::encode(signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: body.message,
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}


#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(Json(body): Json<VerifyMessageRequest>) -> impl IntoResponse {
    let sig_bytes = match base64::decode(&body.signature) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(_) => return (StatusCode::BAD_REQUEST, Json(error("Signature must be 64 bytes in base64"))).into_response(),
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Invalid base64 in signature"))).into_response(),
    };

    let pubkey_bytes = match bs58::decode(&body.pubkey).into_vec() {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(_) => return (StatusCode::BAD_REQUEST, Json(error("Pubkey must be 32 bytes in base58"))).into_response(),
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Invalid base58 in pubkey"))).into_response(),
    };

    let pubkey = match Pubkey::try_from(pubkey_bytes.as_slice()) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Invalid pubkey bytes"))).into_response(),
    };

    let signature = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Invalid signature format"))).into_response(),
    };

    let is_valid = signature.verify(pubkey.as_ref(), body.message.as_bytes());

    let response = SuccessResponse {
        success: true,
        data: VerifyMessageResponse {
            valid: is_valid,
            message: body.message,
            pubkey: pubkey.to_string(),
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}
