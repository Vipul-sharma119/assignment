use axum::{
    routing::{get, post},
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    signature::{Keypair, Signer},
};
use solana_program::pubkey::Pubkey;
use solana_program::instruction::AccountMeta;

use spl_token::instruction::initialize_mint;
use std::net::SocketAddr;
use std::env;
use bs58;
use base64;
use axum::Server;

#[tokio::main]
async fn main() {
   let app = Router::new()
    .route("/", get(root))
    .route("/keypair", post(generate_keypair))
    .route("/token/create", post(create_token))
    .route("/token/mint", post(mint_token))
    .route("/message/sign", post(sign_message));
    




    
    let port = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Server running at http://{}", addr);

    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}


async fn root() -> &'static str {
    "\nUse POST /keypair or POST /token/create."
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
    let secret = bs58::encode(secret_bytes).into_string();

    let response = SuccessResponse {
        success: true,
        data: KeypairResponse { pubkey, secret },
    };

    (StatusCode::OK, Json(response))
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
struct CreateTokenResponse {
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

    let instruction = match initialize_mint(
        &spl_token::ID,
        &mint,
        &mint_authority,
        None,
        body.decimals,
    ) {
        Ok(instr) => instr,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(error(&format!("Instruction creation failed: {e}")))
        ).into_response(),
    };

    let accounts: Vec<AccountMetaInfo> = instruction.accounts.into_iter().map(|acct| AccountMetaInfo {
        pubkey: acct.pubkey.to_string(),
        is_signer: acct.is_signer,
        is_writable: acct.is_writable,
    }).collect();

    let encoded_data = base64::encode(instruction.data);

    let response = SuccessResponse {
        success: true,
        data: CreateTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: encoded_data,
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

    let destination = match decode_pubkey(&body.destination) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&e))).into_response(),
    };

    let authority = match decode_pubkey(&body.authority) {
        Ok(pk) => pk,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(error(&e))).into_response(),
    };

    let instruction = match spl_token::instruction::mint_to(
        &spl_token::ID,
        &mint,
        &destination,
        &authority,
        &[], 
        body.amount,
    ) {
        Ok(instr) => instr,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(error(&format!("Instruction creation failed: {e}")))
        ).into_response(),
    };

    let accounts: Vec<AccountMetaInfo> = instruction.accounts.into_iter().map(|acct| AccountMetaInfo {
        pubkey: acct.pubkey.to_string(),
        is_signer: acct.is_signer,
        is_writable: acct.is_writable,
    }).collect();

    let encoded_data = base64::encode(instruction.data);

    let response = SuccessResponse {
        success: true,
        data: CreateTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: encoded_data,
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
    // Decode secret key
    let secret_bytes = match bs58::decode(&body.secret).into_vec() {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(_) => return (StatusCode::BAD_REQUEST, Json(error("Secret must be 64 bytes in base58"))).into_response(),
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Invalid base58 in secret"))).into_response(),
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(error("Failed to parse keypair from secret"))).into_response(),
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



fn decode_pubkey(s: &str) -> Result<Pubkey, String> {
    bs58::decode(s)
        .into_vec()
        .map_err(|_| "Invalid base58".to_string())
        .and_then(|bytes| {
            Pubkey::try_from(bytes.as_slice())
                .map_err(|_| "Invalid pubkey bytes".to_string())
        })
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
