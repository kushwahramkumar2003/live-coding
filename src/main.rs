use std::convert::Infallible;
use warp::{Filter, Reply, Rejection};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use base58::{ToBase58, FromBase58};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use anyhow::{Result, anyhow};

#[derive(Serialize)]
struct R<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> R<T> {
    fn ok(d: T) -> Self {
        Self {
            success: true,
            data: Some(d),
            error: None,
        }
    }

    fn err(m: String) -> R<()> {
        R {
            success: false,
            data: None,
            error: Some(m),
        }
    }
}

#[derive(Deserialize)]
struct Ct {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct Mt {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct Sm {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct Vm {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct Ss {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct St {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct Kp {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct Ai {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct Ir {
    program_id: String,
    accounts: Vec<Ai>,
    instruction_data: String,
}

#[derive(Serialize)]
struct Sr {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct Vr {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct Ssr {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct Tai {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct Str {
    program_id: String,
    accounts: Vec<Tai>,
    instruction_data: String,
}

fn pk(s: &str) -> Result<Pubkey> {
    s.parse::<Pubkey>()
        .map_err(|_| anyhow!("Invalid public key format"))
}

fn kp(s: &str) -> Result<Keypair> {
    let b = s.from_base58()
        .map_err(|_| anyhow!("Invalid base58 secret key"))?;
    
    if b.len() != 64 {
        return Err(anyhow!("Invalid secret key length"));
    }
    
    Keypair::from_bytes(&b)
        .map_err(|_| anyhow!("Invalid keypair"))
}

fn ata(w: &Pubkey, m: &Pubkey) -> Pubkey {
    spl_associated_token_account::get_associated_token_address(w, m)
}

async fn gen() -> Result<impl Reply, Rejection> {
    let k = Keypair::new();
    let r = Kp {
        pubkey: k.pubkey().to_string(),
        secret: k.to_bytes().to_base58(),
    };
    
    Ok(warp::reply::json(&R::ok(r)))
}

async fn ct(req: Ct) -> Result<impl Reply, Rejection> {
    let ma = match pk(&req.mint_authority) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid mint authority".to_string()))),
    };
    
    let m = match pk(&req.mint) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid mint address".to_string()))),
    };
    
    let i = initialize_mint(
        &spl_token::id(),
        &m,
        &ma,
        Some(&ma),
        req.decimals,
    ).unwrap();
    
    let a: Vec<Ai> = i.accounts.iter().map(|acc| Ai {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();
    
    let r = Ir {
        program_id: i.program_id.to_string(),
        accounts: a,
        instruction_data: B64.encode(&i.data),
    };
    
    Ok(warp::reply::json(&R::ok(r)))
}

async fn mt(req: Mt) -> Result<impl Reply, Rejection> {
    let m = match pk(&req.mint) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid mint address".to_string()))),
    };
    
    let d = match pk(&req.destination) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid destination address".to_string()))),
    };
    
    let a = match pk(&req.authority) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid authority address".to_string()))),
    };
    
    let dt = ata(&d, &m);
    
    let i = mint_to(
        &spl_token::id(),
        &m,
        &dt,
        &a,
        &[],
        req.amount,
    ).unwrap();
    
    let ac: Vec<Ai> = i.accounts.iter().map(|acc| Ai {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();
    
    let r = Ir {
        program_id: i.program_id.to_string(),
        accounts: ac,
        instruction_data: B64.encode(&i.data),
    };
    
    Ok(warp::reply::json(&R::ok(r)))
}

async fn sm(req: Sm) -> Result<impl Reply, Rejection> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(warp::reply::json(&R::<()>::err("Missing required fields".to_string())));
    }
    
    let k = match kp(&req.secret) {
        Ok(kp) => kp,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid secret key".to_string()))),
    };
    
    let mb = req.message.as_bytes();
    let sig = k.sign_message(mb);
    
    let r = Sr {
        signature: B64.encode(sig.as_ref()),
        public_key: k.pubkey().to_string(),
        message: req.message,
    };
    
    Ok(warp::reply::json(&R::ok(r)))
}

async fn vm(req: Vm) -> Result<impl Reply, Rejection> {
    let p = match pk(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid public key".to_string()))),
    };
    
    let sb = match B64.decode(&req.signature) {
        Ok(b) => b,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid signature format".to_string()))),
    };
    
    let sig = match Signature::try_from(sb.as_slice()) {
        Ok(s) => s,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid signature".to_string()))),
    };
    
    let mb = req.message.as_bytes();
    let v = sig.verify(p.as_ref(), mb);
    
    let r = Vr {
        valid: v,
        message: req.message,
        pubkey: req.pubkey,
    };
    
    Ok(warp::reply::json(&R::ok(r)))
}

async fn ss(req: Ss) -> Result<impl Reply, Rejection> {
    let f = match pk(&req.from) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid from address".to_string()))),
    };
    
    let t = match pk(&req.to) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid to address".to_string()))),
    };
    
    if req.lamports == 0 {
        return Ok(warp::reply::json(&R::<()>::err("Amount must be greater than 0".to_string())));
    }
    
    let i = system_instruction::transfer(&f, &t, req.lamports);
    
    let r = Ssr {
        program_id: i.program_id.to_string(),
        accounts: i.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: B64.encode(&i.data),
    };
    
    Ok(warp::reply::json(&R::ok(r)))
}

async fn st(req: St) -> Result<impl Reply, Rejection> {
    let d = match pk(&req.destination) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid destination address".to_string()))),
    };
    
    let m = match pk(&req.mint) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid mint address".to_string()))),
    };
    
    let o = match pk(&req.owner) {
        Ok(p) => p,
        Err(_) => return Ok(warp::reply::json(&R::<()>::err("Invalid owner address".to_string()))),
    };
    
    if req.amount == 0 {
        return Ok(warp::reply::json(&R::<()>::err("Amount must be greater than 0".to_string())));
    }
    
    let st = ata(&o, &m);
    let dt = ata(&d, &m);
    
    let i = transfer(
        &spl_token::id(),
        &st,
        &dt,
        &o,
        &[],
        req.amount,
    ).unwrap();
    
    let a: Vec<Tai> = i.accounts.iter().map(|acc| Tai {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();
    
    let r = Str {
        program_id: i.program_id.to_string(),
        accounts: a,
        instruction_data: B64.encode(&i.data),
    };
    
    Ok(warp::reply::json(&R::ok(r)))
}

async fn hrej(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let msg;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        msg = "NOT_FOUND";
    } else if let Some(_) = err.find::<warp::filters::body::BodyDeserializeError>() {
        code = warp::http::StatusCode::BAD_REQUEST;
        msg = "BAD_REQUEST";
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        code = warp::http::StatusCode::METHOD_NOT_ALLOWED;
        msg = "METHOD_NOT_ALLOWED";
    } else {
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        msg = "INTERNAL_SERVER_ERROR";
    }

    let j = warp::reply::json(&R::<()>::err(msg.to_string()));
    Ok(warp::reply::with_status(j, code))
}

#[tokio::main]
async fn main() {
    env_logger::init();
    
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type"])
        .allow_methods(vec!["GET", "POST", "DELETE"]);
    
    let k = warp::path("keypair")
        .and(warp::post())
        .and_then(gen);
    
    let ct_r = warp::path!("token" / "create")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(ct);
    
    let mt_r = warp::path!("token" / "mint")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(mt);
    
    let sm_r = warp::path!("message" / "sign")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(sm);
    
    let vm_r = warp::path!("message" / "verify")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(vm);
    
    let ss_r = warp::path!("send" / "sol")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(ss);
    
    let st_r = warp::path!("send" / "token")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(st);
    
    let routes = k
        .or(ct_r)
        .or(mt_r)
        .or(sm_r)
        .or(vm_r)
        .or(ss_r)
        .or(st_r)
        .with(cors)
        .recover(hrej);
    
    println!("Solana HTTP Server starting on port 3030...");
    warp::serve(routes)
        .run(([0, 0, 0, 0], 3030))
        .await;
}