//! Operator / federation relay: submit `shield(...)` via `eth_sendRawTransaction` and watch
//! Bitcoin Core for deposits (V1 single-sig address, optional intent matching).
//!
//! **Multisig / policy**: deploy a Gnosis Safe (or similar) as `PrivacyBTC.federation` so the
//! relay EOA is replaced by multisig execution; this binary stays single-key for local signing.

use anyhow::{anyhow, Context, Result};
use axum::{extract::{Query, State}, http::StatusCode, routing::get, routing::post, Json, Router};
use clap::{Parser, Subcommand};
use k256::ecdsa::{RecoveryId, SigningKey};
use privacy_core::intent::{build_shield_intent_v1, bundle_content_sha256, BtcDepositConfigV1, ShieldIntentV1};
use privacy_core::types::OrchardStoredBundle;
use privacy_core::ethereum::{
    encode_bundle_calldata, encode_erc_shield_calldata, encode_finalize_withdraw_calldata,
    bundle_value_balance_be, evm_address_to_recipient_meta, parse_evm_address_hex,
    BundleActionArgs, BundleCalldataArgs, ErcShieldCalldataArgs,
    FinalizeWithdrawCalldataArgs,
};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use url::Url;

#[derive(Parser)]
#[command(name = "privacybtc-relayer", version, about = "Federation shield relay + BTC watch (V1)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build `shield(...)` calldata, sign an EIP-155 legacy tx, and broadcast via `eth_sendRawTransaction`.
    ///
    /// The signing key **must** be the on-chain `PrivacyBTC.federation` account (or an EOA that is
    /// not the federation key will revert with `NotFederation`).
    ShieldSubmit {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        chain_id: u64,
        /// Hex-encoded secp256k1 private key (32 bytes), with or without `0x`.
        #[arg(long)]
        private_key: String,
        /// `PrivacyBTC` contract address (20-byte hex).
        #[arg(long)]
        contract: String,
        /// JSON file: `OrchardStoredBundle` (same as `privacybtc shield-prepare` output).
        #[arg(long)]
        bundle_json: PathBuf,
        /// Amount locked on Bitcoin for this shield (satoshis). Default: read from `--intent-json` if set.
        #[arg(long)]
        amount_sats: Option<u64>,
        /// Optional `ShieldIntentV1` JSON — used for default `amount_sats` and cross-check when both are set.
        #[arg(long)]
        intent_json: Option<PathBuf>,
        #[arg(long, default_value_t = 1.0)]
        gas_price_gwei: f64,
        /// Headroom for `shield()` + Groth16 verify per action (~300–500k each).
        #[arg(long, default_value_t = 3_000_000)]
        gas_limit: u64,
    },
    /// Submit `finalizeWithdraw(nf,amount,recipientMeta)` via `eth_sendRawTransaction`.
    UnshieldFinalize {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        chain_id: u64,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        contract: String,
        /// Nullifier of the spent note (bytes32 hex).
        #[arg(long)]
        nf_hex: String,
        /// Unshield amount in sats/zats.
        #[arg(long)]
        amount_sats: u64,
        /// Opaque BTC recipient metadata (bytes32 hex).
        #[arg(long)]
        recipient_meta_hex: String,
        #[arg(long, default_value_t = 1.0)]
        gas_price_gwei: f64,
        #[arg(long, default_value_t = 150_000)]
        gas_limit: u64,
    },
    /// Poll Bitcoin Core `listunspent` for the federation deposit address and match against
    /// `ShieldIntentV1` JSON files (with sibling `*.bundle.json` for content-hash checks).
    WatchBtc {
        #[arg(long)]
        btc_rpc_url: String,
        /// Watch-only deposit address imported in `bitcoind`.
        #[arg(long)]
        deposit_address: String,
        /// Directory containing intent JSON files (`ShieldIntentV1`).
        #[arg(long)]
        intent_dir: PathBuf,
        #[arg(long, default_value_t = 60)]
        poll_secs: u64,
        #[arg(long, default_value_t = 1)]
        min_conf: u32,
        /// Exit after one successful poll (for cron); default runs until interrupted.
        #[arg(long, default_value_t = false)]
        once: bool,
    },
    /// Start HTTP API for frontend/operator integration.
    Serve {
        #[arg(long, env = "PRIVACYBTC_RELAYER_BIND", default_value = "127.0.0.1:8790")]
        bind: String,
        #[arg(long, env = "PRIVACYBTC_ETH_RPC_URL")]
        rpc_url: String,
        #[arg(long, env = "PRIVACYBTC_CHAIN_ID")]
        chain_id: u64,
        #[arg(long, env = "PRIVACYBTC_RELAYER_PRIVATE_KEY")]
        private_key: String,
        /// pERC20 issuer key (onlyIssuer). Used ONLY by /erc/mint/submit to sign+broadcast
        /// the issuer-submitted `mint(...)`. Distinct from the relayer key above.
        #[arg(long, env = "PERC20_ISSUER_PRIVATE_KEY")]
        issuer_private_key: Option<String>,
        #[arg(long, env = "PRIVACYBTC_CONTRACT_ADDRESS")]
        contract: String,
        #[arg(long, env = "PRIVACYBTC_GAS_PRICE_GWEI", default_value_t = 1.0)]
        gas_price_gwei: f64,
        /// Groth16 verify per action; tune after profiling on target RPC.
        #[arg(long, env = "PRIVACYBTC_GAS_LIMIT_SHIELD", default_value_t = 3_000_000)]
        gas_limit_shield: u64,
        #[arg(long, env = "PRIVACYBTC_GAS_LIMIT_UNSHIELD", default_value_t = 3_000_000)]
        gas_limit_unshield: u64,
        #[arg(long, env = "PRIVACYBTC_GAS_LIMIT_TRANSFER", default_value_t = 5_000_000)]
        gas_limit_transfer: u64,
        /// Optional: enable automatic shield submit from Bitcoin deposits.
        #[arg(long, env = "PRIVACYBTC_BTC_RPC_URL")]
        btc_rpc_url: Option<String>,
        #[arg(long, env = "PRIVACYBTC_BTC_DEPOSIT_ADDRESS")]
        deposit_address: Option<String>,
        #[arg(long, env = "PRIVACYBTC_INTENT_DIR")]
        intent_dir: Option<PathBuf>,
        /// Optional: enable transfer auto-submit from prepared bundle files.
        #[arg(long, env = "PRIVACYBTC_TRANSFER_DIR")]
        transfer_dir: Option<PathBuf>,
        #[arg(long, env = "PRIVACYBTC_BTC_MIN_CONF", default_value_t = 1)]
        min_conf: u32,
        /// WIF-encoded private key for federation payout wallet (optional).
        /// When set, unshield auto-payout signs locally and broadcasts via Esplora.
        #[arg(long, env = "PRIVACYBTC_BTC_PAYOUT_WIF")]
        btc_payout_wif: Option<String>,
        /// Payout fee rate in sat/vB (default 5).
        #[arg(long, env = "PRIVACYBTC_BTC_PAYOUT_FEE_SAT_VB", default_value_t = 5)]
        btc_payout_fee_sat_vb: u64,
        /// Base URL of the privacybtc-indexer to notify of broadcast transactions.
        /// e.g. http://127.0.0.1:8787
        #[arg(long, env = "PRIVACYBTC_INDEXER_URL")]
        indexer_url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    match cli.command {
        Command::ShieldSubmit {
            rpc_url,
            chain_id,
            private_key,
            contract,
            bundle_json,
            amount_sats,
            intent_json,
            gas_price_gwei,
            gas_limit,
        } => {
            shield_submit(
                &rpc_url,
                chain_id,
                &private_key,
                &contract,
                &bundle_json,
                amount_sats,
                intent_json.as_deref(),
                gas_price_gwei,
                gas_limit,
            )
            .await?;
        }
        Command::UnshieldFinalize {
            rpc_url,
            chain_id,
            private_key,
            contract,
            nf_hex,
            amount_sats,
            recipient_meta_hex,
            gas_price_gwei,
            gas_limit,
        } => {
            let cli_nonce_cache = Arc::new(Mutex::new(None::<u64>));
            let tx_hash = unshield_finalize_submit(
                &rpc_url,
                chain_id,
                &private_key,
                &contract,
                &nf_hex,
                amount_sats,
                &recipient_meta_hex,
                gas_price_gwei,
                gas_limit,
                &cli_nonce_cache,
            )
            .await?;
            println!("finalizeWithdraw eth_sendRawTransaction ok: {tx_hash}");
        }
        Command::WatchBtc {
            btc_rpc_url,
            deposit_address,
            intent_dir,
            poll_secs,
            min_conf,
            once,
        } => {
            watch_btc_loop(
                &btc_rpc_url,
                &deposit_address,
                &intent_dir,
                poll_secs,
                min_conf,
                once,
            )
            .await?;
        }
        Command::Serve {
            bind,
            rpc_url,
            chain_id,
            private_key,
            issuer_private_key,
            contract,
            gas_price_gwei,
            gas_limit_shield,
            gas_limit_unshield,
            gas_limit_transfer,
            btc_rpc_url,
            deposit_address,
            intent_dir,
            transfer_dir,
            min_conf,
            btc_payout_wif,
            btc_payout_fee_sat_vb,
            indexer_url,
        } => {
            run_http_server(
                &bind,
                &rpc_url,
                chain_id,
                &private_key,
                issuer_private_key.as_deref(),
                &contract,
                gas_price_gwei,
                gas_limit_shield,
                gas_limit_unshield,
                gas_limit_transfer,
                btc_rpc_url.as_deref(),
                deposit_address.as_deref(),
                intent_dir.as_deref(),
                transfer_dir.as_deref(),
                min_conf,
                btc_payout_wif.as_deref(),
                btc_payout_fee_sat_vb,
                indexer_url,
            )
            .await?;
        }
    }
    Ok(())
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn parse_fixed_hex_32(hex: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(strip_0x(hex)).context("invalid hex")?;
    if decoded.len() != 32 {
        return Err(anyhow!("expected 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn parse_hex_key(s: &str) -> Result<SigningKey> {
    let bytes = hex::decode(strip_0x(s)).context("private key hex")?;
    SigningKey::from_slice(&bytes).map_err(|e| anyhow!("invalid signing key: {e}"))
}

fn eth_address_from_signing_key(signing_key: &SigningKey) -> [u8; 20] {
    let vk = signing_key.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let pubkey_bytes = &encoded.as_bytes()[1..];
    let hash: [u8; 32] = Keccak256::digest(pubkey_bytes).into();
    hash[12..].try_into().expect("20 bytes")
}

#[derive(Clone)]
struct RelayerHttpConfig {
    rpc_url: String,
    chain_id: u64,
    private_key: String,
    /// pERC20 issuer key (onlyIssuer), used only by /erc/mint/submit. None if unset.
    issuer_private_key: Option<String>,
    contract: String,
    gas_price_gwei: f64,
    gas_limit_shield: u64,
    gas_limit_unshield: u64,
    gas_limit_transfer: u64,
    auto_shield: Option<AutoShieldConfig>,
    auto_transfer: Option<AutoTransferConfig>,
    /// WIF-encoded secp256k1 private key for the federation payout wallet.
    /// When set, unshield auto-payout signs locally and broadcasts via Esplora.
    btc_payout_wif: Option<String>,
    /// Fee rate in sat/vB for payout transactions (default 5).
    btc_payout_fee_sat_vb: u64,
    /// Base URL of the privacybtc-indexer (e.g. "http://127.0.0.1:8787").
    /// When set, the relayer notifies the indexer of every broadcast tx hash.
    indexer_url: Option<String>,
    /// In-process nonce counter. Initialized from chain on first use, then incremented
    /// locally so concurrent / back-to-back requests never reuse the same nonce.
    nonce_cache: Arc<Mutex<Option<u64>>>,
}

#[derive(Clone)]
struct AutoShieldConfig {
    btc_rpc_url: String,
    deposit_address: String,
    intent_dir: PathBuf,
    min_conf: u32,
}

#[derive(Clone)]
struct AutoTransferConfig {
    transfer_dir: PathBuf,
    seen_bundle_paths: Arc<Mutex<std::collections::HashSet<String>>>,
}

#[derive(Debug, Deserialize)]
struct HttpShieldSubmitRequest {
    bundle: OrchardStoredBundle,
    amount_sats: u64,
}

#[derive(Debug, Deserialize)]
struct HttpUnshieldFinalizeRequest {
    nf_hex: String,
    amount_sats: u64,
    recipient_meta_hex: String,
}

#[derive(Debug, Deserialize, Default)]
struct HttpShieldAutoRequest {
    #[serde(default)]
    intent_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HttpShieldPrepareRequest {
    proved_bundle: OrchardStoredBundle,
    amount_sats: u64,
    /// BTC txid from the user's wallet send.  Stored in the intent so UTXO matching
    /// uses the exact txid instead of amount, preventing cross-session collisions.
    #[serde(default)]
    btc_txid: Option<String>,
}

#[derive(serde::Serialize)]
struct HttpShieldPrepareResponse {
    btc_deposit_address: String,
    amount_sats: u64,
    intent_path: String,
}

#[derive(Debug, Deserialize, Default)]
struct HttpTransferAutoRequest {
    #[serde(default)]
    bundle_path: Option<String>,
}

#[derive(serde::Serialize)]
struct HttpTxResponse {
    tx_hash: String,
}

#[derive(serde::Serialize)]
struct HttpAutoShieldResponse {
    tx_hash: String,
    btc_txid: String,
    intent_path: String,
    amount_sats: u64,
}

#[derive(serde::Serialize)]
struct HttpAutoTransferResponse {
    tx_hash: String,
    bundle_path: String,
}

#[derive(serde::Serialize)]
struct HttpErrorResponse {
    error: String,
}

/// Notify the indexer of a broadcast tx hash so it can recover events
/// if the WebSocket drops while the tx is in-flight.
async fn notify_pending_tx(indexer_url: Option<String>, tx_hash: String, contract_address: String) {
    let Some(base_url) = indexer_url else { return };
    let url = format!(
        "{}/notify_tx?pool={}",
        base_url.trim_end_matches('/'),
        contract_address
    );
    let body = serde_json::json!({ "tx_hash": tx_hash });
    // Use no_proxy for localhost to bypass any system/Clash proxy (HTTPS_PROXY etc.)
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap_or_default();
    match client.post(&url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("[relayer] notified indexer of tx {tx_hash}");
        }
        Ok(resp) => {
            eprintln!("[relayer] notify_tx returned status {}: {tx_hash}", resp.status());
        }
        Err(e) => {
            eprintln!("[relayer] notify_tx failed for {tx_hash}: {e}");
        }
    }
}

#[derive(Deserialize)]
struct FrozenRootResp {
    /// `rt_frozen` as 0x-prefixed little-endian 32-byte hex (indexer convention).
    root_hex: String,
}

/// `GET {indexer}/frozen_root?pool={contract}` → `rt_frozen` as **big-endian** 32 bytes.
///
/// The indexer publishes the root little-endian (its on-the-wire convention, matching
/// `/merkle_path` siblings); `pubFields` are big-endian `uint256` words, so we flip it
/// here to compare in the same order.
async fn fetch_frozen_root_be(indexer_base: &str, contract: &str) -> Result<[u8; 32]> {
    let url = format!("{}/frozen_root?pool={}", indexer_base.trim_end_matches('/'), contract);
    let client = reqwest::Client::builder().no_proxy().build().unwrap_or_default();
    let resp: FrozenRootResp = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut bytes = parse_hex32(&resp.root_hex)?; // little-endian
    bytes.reverse(); // → big-endian, matching pubFields[7]
    Ok(bytes)
}

/// Pre-broadcast compliance gate. Every action's `pubFields[7]` (rt_frozen) must equal
/// the indexer's current `/frozen_root`; otherwise the proof was built against a stale
/// blacklist and the on-chain `_verifyAction` would revert with `BadFrozenRoot`. Catching
/// it here turns a wasted, reverting broadcast into a clear, actionable error.
///
/// Best-effort on availability: if no `indexer_url` is configured, or the indexer is
/// unreachable, this logs and proceeds (the on-chain check stays the ultimate gate). A
/// *reachable* indexer reporting a mismatch is a hard error.
async fn enforce_frozen_compliance(
    indexer_url: Option<&str>,
    contract: &str,
    bundle: &OrchardStoredBundle,
) -> Result<()> {
    let Some(base) = indexer_url else { return Ok(()) };
    let expected_be = match fetch_frozen_root_be(base, contract).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[relayer] frozen-root preflight skipped (indexer unreachable: {e:#}); \
                 relying on the on-chain BadFrozenRoot guard"
            );
            return Ok(());
        }
    };
    for (i, a) in bundle.actions.iter().enumerate() {
        let pf = a
            .pub_fields_bn254
            .as_ref()
            .ok_or_else(|| anyhow!("action {i} missing pub_fields_bn254"))?;
        let got = pf
            .get(7)
            .ok_or_else(|| anyhow!("action {i} pub_fields_bn254 has fewer than 8 entries"))?;
        if got.as_slice() != expected_be {
            return Err(anyhow!(
                "action {i} pubFields[7] (rt_frozen) does not match the indexer's /frozen_root: \
                 the proof was built against a stale compliance root. Re-prove against the current \
                 frozen set (GET /frozen_witness). expected 0x{} got 0x{}",
                hex::encode(expected_be),
                hex::encode(got)
            ));
        }
    }
    Ok(())
}

async fn run_http_server(
    bind: &str,
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
    issuer_private_key: Option<&str>,
    contract: &str,
    gas_price_gwei: f64,
    gas_limit_shield: u64,
    gas_limit_unshield: u64,
    gas_limit_transfer: u64,
    btc_rpc_url: Option<&str>,
    deposit_address: Option<&str>,
    intent_dir: Option<&Path>,
    transfer_dir: Option<&Path>,
    min_conf: u32,
    btc_payout_wif: Option<&str>,
    btc_payout_fee_sat_vb: u64,
    indexer_url: Option<String>,
) -> Result<()> {
    let auto_shield = match (btc_rpc_url, deposit_address, intent_dir) {
        (Some(btc_rpc_url), Some(deposit_address), Some(intent_dir)) => Some(AutoShieldConfig {
            btc_rpc_url: btc_rpc_url.to_string(),
            deposit_address: deposit_address.to_string(),
            intent_dir: intent_dir.to_path_buf(),
            min_conf,
        }),
        _ => None,
    };
    let auto_transfer = transfer_dir.map(|transfer_dir| AutoTransferConfig {
        transfer_dir: transfer_dir.to_path_buf(),
        seen_bundle_paths: Arc::new(Mutex::new(std::collections::HashSet::new())),
    });
    let state = Arc::new(RelayerHttpConfig {
        rpc_url: rpc_url.to_string(),
        chain_id,
        private_key: private_key.to_string(),
        issuer_private_key: issuer_private_key.map(|s| s.to_string()),
        contract: contract.to_string(),
        gas_price_gwei,
        gas_limit_shield,
        gas_limit_unshield,
        gas_limit_transfer,
        auto_shield,
        auto_transfer,
        btc_payout_wif: btc_payout_wif.map(|s| s.to_string()),
        btc_payout_fee_sat_vb,
        indexer_url,
        nonce_cache: Arc::new(Mutex::new(None)),
    });
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/tx/status", get(http_tx_status))
        .route("/shield/address", get(http_shield_address))
        .route("/shield/check", get(http_shield_check))
        .route("/shield/submit", post(http_shield_submit))
        .route("/shield/prepare", post(http_shield_prepare))
        .route("/shield/auto", post(http_shield_auto))
        .route("/transfer/auto", post(http_transfer_auto))
        .route("/transfer/submit", post(http_transfer_submit))
        .route("/unshield/submit", post(http_unshield_submit))
        .route("/unshield/finalize", post(http_unshield_finalize))  // legacy, kept for compat
        .route("/erc/shield/submit", post(http_erc_shield_submit))
        .route("/submit_raw", post(http_submit_raw))
        .route("/erc/mint/submit", post(http_erc_mint_submit))
        .layer(build_cors_layer())
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    println!("relayer http listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Return the configured BTC deposit address so the frontend can send BTC before proving.
async fn http_shield_address(
    State(cfg): State<Arc<RelayerHttpConfig>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<HttpErrorResponse>)> {
    let auto = cfg.auto_shield.as_ref()
        .ok_or_else(|| http_error(anyhow!("shield not configured on this relayer")))?;
    Ok(Json(serde_json::json!({
        "btc_deposit_address": auto.deposit_address,
        "min_confirmations": auto.min_conf,
    })))
}

/// Lightweight BTC UTXO check — returns whether a confirmed UTXO exists.
/// Query params:
///   amount_sats  (required) – expected value in satoshis
///   txid         (required) – BTC txid of the user's deposit transaction;
///                             UTXO must match both amount and txid
async fn http_shield_check(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<HttpErrorResponse>)> {
    async {
        let auto = cfg.auto_shield.as_ref()
            .ok_or_else(|| anyhow!("shield not configured on this relayer"))?;
        let amount_sats: u64 = params.get("amount_sats")
            .ok_or_else(|| anyhow!("missing query param amount_sats"))?
            .parse()
            .context("amount_sats must be a positive integer")?;
        let txid_filter = params.get("txid").map(|t| t.to_lowercase());
        let btc_backend = BtcBackend::from_url(&auto.btc_rpc_url)?;
        let utxos = btc_backend.list_utxos(&auto.deposit_address, auto.min_conf).await?;
        let target_btc = amount_sats as f64 / 100_000_000.0;
        let matched = utxos.iter().find(|u| {
            let amount_ok = (u.amount - target_btc).abs() < 1e-9;
            let txid_ok = txid_filter.as_ref()
                .map(|t| u.txid.to_lowercase() == *t)
                .unwrap_or(true);
            amount_ok && txid_ok
        });
        Ok(Json(serde_json::json!({
            "confirmed": matched.is_some(),
            "amount_sats": amount_sats,
            "txid": matched.map(|u| u.txid.clone()),
        })))
    }
    .await
    .map_err(http_error)
}

async fn http_shield_prepare(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpShieldPrepareRequest>,
) -> Result<Json<HttpShieldPrepareResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    async {
        let auto = cfg.auto_shield.as_ref()
            .ok_or_else(|| anyhow!("auto shield is not configured on this relayer"))?;

        // Validate the bundle has the Groth16 proof attached at action level (local prover).
        req.proved_bundle.actions.first()
            .ok_or_else(|| anyhow!("proved_bundle has no actions"))?
            .proof_bn254.as_ref()
            .ok_or_else(|| anyhow!("proved_bundle.proof_bn254 is missing — call prover /shield/prove first"))?;
        req.proved_bundle.actions.first()
            .and_then(|a| a.pub_fields_bn254.as_ref())
            .ok_or_else(|| anyhow!("proved_bundle.pub_fields_bn254 is missing"))?;

        let intent = build_shield_intent_v1(
            &req.proved_bundle,
            &BtcDepositConfigV1 { btc_deposit_address: auto.deposit_address.clone() },
            req.amount_sats,
            None,
            req.btc_txid.clone(),
        ).context("build_shield_intent_v1 failed")?;

        std::fs::create_dir_all(&auto.intent_dir)
            .with_context(|| format!("create intent_dir {}", auto.intent_dir.display()))?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let intent_name = format!("intent-{}-{}.json", req.amount_sats, ts);
        let intent_path = auto.intent_dir.join(&intent_name);
        let bundle_path = bundle_path_for_intent(&intent_path);

        std::fs::write(&bundle_path, serde_json::to_string_pretty(&req.proved_bundle)?)
            .with_context(|| format!("write bundle {}", bundle_path.display()))?;
        std::fs::write(&intent_path, serde_json::to_string_pretty(&intent)?)
            .with_context(|| format!("write intent {}", intent_path.display()))?;

        Ok(Json(HttpShieldPrepareResponse {
            btc_deposit_address: auto.deposit_address.clone(),
            amount_sats: req.amount_sats,
            intent_path: intent_path.to_string_lossy().into_owned(),
        }))
    }
    .await
    .map_err(http_error)
}

async fn http_shield_auto(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpShieldAutoRequest>,
) -> Result<Json<HttpAutoShieldResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    async {
        let auto = cfg
            .auto_shield
            .as_ref()
            .ok_or_else(|| anyhow!("auto shield is not configured on relayer serve"))?;
        let btc_backend = BtcBackend::from_url(&auto.btc_rpc_url)?;
        let matches = poll_deposits_backend(&btc_backend, &auto.deposit_address, &auto.intent_dir, auto.min_conf).await?;
        let selected = if let Some(intent_path) = req.intent_path.as_deref() {
            matches
                .into_iter()
                .find(|m| m.intent_path == intent_path)
                .ok_or_else(|| anyhow!("requested intent_path has no confirmed matching UTXO"))?
        } else {
            matches
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no confirmed BTC deposits matched available intents"))?
        };
        let intent_raw = std::fs::read_to_string(&selected.intent_path)
            .with_context(|| format!("read {}", selected.intent_path))?;
        let intent: ShieldIntentV1 = serde_json::from_str(&intent_raw).context("intent JSON")?;
        let bundle_path = bundle_path_for_intent(Path::new(&selected.intent_path));
        let bundle_raw =
            std::fs::read_to_string(&bundle_path).with_context(|| format!("read {}", bundle_path.display()))?;
        let bundle: OrchardStoredBundle = serde_json::from_str(&bundle_raw).context("bundle JSON")?;
        let tx_hash = submit_shield_bundle(
            &cfg.rpc_url,
            cfg.chain_id,
            &cfg.private_key,
            &cfg.contract,
            &bundle,
            intent.amount_sats,
            cfg.gas_price_gwei,
            cfg.gas_limit_shield,
            &cfg.nonce_cache,
            cfg.indexer_url.as_deref(),
        )
        .await?;
        tokio::spawn(notify_pending_tx(
            cfg.indexer_url.clone(),
            tx_hash.clone(),
            cfg.contract.clone(),
        ));
        // Spawn a background task that polls for the EVM receipt and deletes the
        // intent + bundle files only after the tx is confirmed on-chain (status=0x1).
        // Keeping them until confirmed means a reverted tx can be retried; deleting
        // them after success prevents the same proof/UTXO from being re-submitted.
        {
            let rpc_url  = cfg.rpc_url.clone();
            let tx_hash2 = tx_hash.clone();
            let intent_path2 = selected.intent_path.clone();
            tokio::spawn(async move {
                if cleanup_intent_after_receipt(&rpc_url, &tx_hash2, &intent_path2).await {
                    println!("[shield] intent cleaned up after confirmed tx {tx_hash2}");
                } else {
                    eprintln!("[shield] intent NOT cleaned up (tx reverted or timed out): {tx_hash2}");
                }
            });
        }
        Ok(Json(HttpAutoShieldResponse {
            tx_hash,
            btc_txid: selected.matched_utxo.txid.clone(),
            intent_path: selected.intent_path,
            amount_sats: intent.amount_sats,
        }))
    }
    .await
    .map_err(http_error)
}

async fn http_shield_submit(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpShieldSubmitRequest>,
) -> Result<Json<HttpTxResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    let tx_hash = submit_shield_bundle(
        &cfg.rpc_url,
        cfg.chain_id,
        &cfg.private_key,
        &cfg.contract,
        &req.bundle,
        req.amount_sats,
        cfg.gas_price_gwei,
        cfg.gas_limit_shield,
        &cfg.nonce_cache,
        cfg.indexer_url.as_deref(),
    )
    .await
    .map_err(http_error)?;
    tokio::spawn(notify_pending_tx(cfg.indexer_url.clone(), tx_hash.clone(), cfg.contract.clone()));
    Ok(Json(HttpTxResponse { tx_hash }))
}

async fn http_transfer_auto(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpTransferAutoRequest>,
) -> Result<Json<HttpAutoTransferResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    async {
        let auto = cfg
            .auto_transfer
            .as_ref()
            .ok_or_else(|| anyhow!("auto transfer is not configured on relayer serve"))?;
        let selected_path = if let Some(path) = req.bundle_path.as_deref() {
            PathBuf::from(path)
        } else {
            next_transfer_bundle_path(&auto.transfer_dir, &auto.seen_bundle_paths).await?
        };
        let raw = std::fs::read_to_string(&selected_path)
            .with_context(|| format!("read {}", selected_path.display()))?;
        let bundle: OrchardStoredBundle = serde_json::from_str(&raw).context("bundle JSON")?;
        let tx_hash = submit_transfer_bundle(
            &cfg.rpc_url,
            cfg.chain_id,
            &cfg.private_key,
            &cfg.contract,
            &bundle,
            cfg.gas_price_gwei,
            cfg.gas_limit_transfer,
            &cfg.nonce_cache,
            cfg.indexer_url.as_deref(),
        )
        .await?;
        {
            let mut seen = auto.seen_bundle_paths.lock().await;
            seen.insert(selected_path.to_string_lossy().into_owned());
        }
        Ok(Json(HttpAutoTransferResponse {
            tx_hash,
            bundle_path: selected_path.to_string_lossy().into_owned(),
        }))
    }
    .await
    .map_err(http_error)
}

/// Inline transfer — accepts a pre-built `OrchardStoredBundle` in the request body.
/// Unlike `/transfer/auto` (which picks from a disk directory), this endpoint is
/// suitable for direct frontend → relayer calls once the local prover has produced a bundle.
#[derive(Debug, serde::Deserialize)]
struct HttpTransferSubmitRequest {
    bundle: OrchardStoredBundle,
    /// Pool contract address (0x-prefixed 20 bytes). Required — works for both BTC and ERC pools.
    contract: String,
}

/// GET /tx/status?hash=0x...
/// 返回 {"status": "pending"|"success"|"failed"}
#[derive(serde::Deserialize)]
struct TxStatusQuery {
    hash: String,
}
#[derive(serde::Serialize)]
struct TxStatusResponse {
    status: &'static str,
}

async fn http_tx_status(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Query(q): Query<TxStatusQuery>,
) -> Result<Json<TxStatusResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    let client = EthRpcClient::new(cfg.rpc_url.clone());
    match client.get_transaction_receipt_status(&q.hash).await {
        Ok(None)        => Ok(Json(TxStatusResponse { status: "pending" })),
        Ok(Some(true))  => Ok(Json(TxStatusResponse { status: "success" })),
        Ok(Some(false)) => Ok(Json(TxStatusResponse { status: "failed"  })),
        Err(e)          => Err(http_error(e)),
    }
}

async fn http_transfer_submit(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpTransferSubmitRequest>,
) -> Result<Json<HttpTxResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    let tx_hash = submit_transfer_bundle(
        &cfg.rpc_url,
        cfg.chain_id,
        &cfg.private_key,
        &req.contract,
        &req.bundle,
        cfg.gas_price_gwei,
        cfg.gas_limit_transfer,
        &cfg.nonce_cache,
        cfg.indexer_url.as_deref(),
    )
    .await
    .map_err(http_error)?;
    tokio::spawn(notify_pending_tx(cfg.indexer_url.clone(), tx_hash.clone(), req.contract.clone()));
    Ok(Json(HttpTxResponse { tx_hash }))
}

/// Generic raw-calldata relay: sign + broadcast a pre-built call from the relayer
/// EOA, paying gas and hiding the user's EOA. Asset-agnostic — the caller supplies
/// the target contract and the fully-encoded, already-signed calldata, so this
/// works for any pool/standard (e.g. PERC20 mint/transfer/burn) without the relayer
/// needing to know the contract's ABI.
#[derive(Debug, serde::Deserialize)]
struct HttpSubmitRawRequest {
    /// Target contract address (0x-prefixed 20 bytes).
    to: String,
    /// Fully-encoded calldata (0x-prefixed hex), including the 4-byte selector.
    data: String,
    /// Optional gas limit override (defaults to the transfer gas limit).
    #[serde(default)]
    gas_limit: Option<u64>,
    /// Optional wei value to attach (defaults to 0).
    #[serde(default)]
    value: Option<u64>,
}

async fn http_submit_raw(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpSubmitRawRequest>,
) -> Result<Json<HttpTxResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    let calldata = hex::decode(req.data.trim_start_matches("0x"))
        .map_err(|e| http_error(anyhow!("data is not valid hex: {e}")))?;
    let tx_hash = send_raw_calldata(
        &cfg.rpc_url,
        cfg.chain_id,
        &cfg.private_key,
        &req.to,
        calldata,
        req.value.unwrap_or(0),
        cfg.gas_price_gwei,
        req.gas_limit.unwrap_or(cfg.gas_limit_transfer),
        &cfg.nonce_cache,
    )
    .await
    .map_err(http_error)?;
    tokio::spawn(notify_pending_tx(cfg.indexer_url.clone(), tx_hash.clone(), req.to.clone()));
    Ok(Json(HttpTxResponse { tx_hash }))
}

/// Inline unshield — accepts a pre-built `OrchardStoredBundle` and the claimed amount.
///
/// Works for both BTC and ERC pools — both call `PrivacyPool.bundle()`.
///
/// Recipient encoding:
///   - BTC pool: supply `recipient_meta_hex` (0x-prefixed bytes32, sha256 of the BTC address).
///     Optionally also supply `recipient_btc_address` for automatic BTC payout.
///   - ERC pool: supply `recipient_evm` (0x-prefixed 20-byte EVM address). It is
///     right-padded to 32 bytes for the `recipientMeta` field.
///   Exactly one of `recipient_meta_hex` or `recipient_evm` must be provided.
#[derive(Debug, serde::Deserialize)]
struct HttpUnshieldSubmitRequest {
    /// Pool contract address (0x-prefixed 20 bytes). Required.
    contract: String,
    bundle: OrchardStoredBundle,
    amount_sats: u64,
    /// BTC pool: 0x-prefixed bytes32 sha256(btc_address). Mutually exclusive with `recipient_evm`.
    #[serde(default)]
    recipient_meta_hex: Option<String>,
    /// ERC pool: 0x-prefixed 20-byte EVM address. Mutually exclusive with `recipient_meta_hex`.
    #[serde(default)]
    recipient_evm: Option<String>,
    /// Actual BTC address (e.g. `bc1p…`) for automatic payout after L2 confirm.
    /// Only used when `recipient_meta_hex` is set. Must satisfy sha256(addr) == recipient_meta_hex.
    #[serde(default)]
    recipient_btc_address: Option<String>,
}

async fn http_unshield_submit(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpUnshieldSubmitRequest>,
) -> Result<Json<HttpTxResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    // Resolve recipient_meta_hex from whichever field the caller supplied.
    let recipient_meta_hex: String = match (&req.recipient_meta_hex, &req.recipient_evm) {
        (Some(meta), None) => meta.clone(),
        (None, Some(evm)) => {
            let addr = parse_evm_address_hex(evm)
                .map_err(|e| (StatusCode::BAD_REQUEST, Json(HttpErrorResponse {
                    error: format!("bad recipient_evm: {e}"),
                })))?;
            format!("0x{}", hex::encode(evm_address_to_recipient_meta(&addr)))
        }
        (Some(_), Some(_)) => return Err((StatusCode::BAD_REQUEST, Json(HttpErrorResponse {
            error: "supply exactly one of recipient_meta_hex or recipient_evm".into(),
        }))),
        (None, None) => return Err((StatusCode::BAD_REQUEST, Json(HttpErrorResponse {
            error: "recipient_meta_hex or recipient_evm is required".into(),
        }))),
    };

    // Validate BTC address↔meta binding when both are present.
    if let Some(addr) = &req.recipient_btc_address {
        let computed = sha256_hex(addr.as_bytes());
        let expected = recipient_meta_hex.trim_start_matches("0x");
        if computed != expected {
            return Err((StatusCode::BAD_REQUEST, Json(HttpErrorResponse {
                error: format!("recipient_btc_address sha256 mismatch: computed {computed}, expected {expected}"),
            })));
        }
    }


    let tx_hash = submit_unshield_bundle(
        &cfg.rpc_url,
        cfg.chain_id,
        &cfg.private_key,
        &req.contract,
        &req.bundle,
        req.amount_sats,
        &recipient_meta_hex,
        cfg.gas_price_gwei,
        cfg.gas_limit_unshield,
        &cfg.nonce_cache,
        cfg.indexer_url.as_deref(),
    )
    .await
    .map_err(http_error)?;

    tokio::spawn(notify_pending_tx(cfg.indexer_url.clone(), tx_hash.clone(), req.contract.clone()));

    // Spawn background BTC payout (only when btc payout is configured and address provided).
    if let (Some(btc_addr), Some(wif)) =
        (req.recipient_btc_address, cfg.btc_payout_wif.clone())
    {
        let eth_rpc     = cfg.rpc_url.clone();
        let tx          = tx_hash.clone();
        let amount_sats = req.amount_sats;
        let fee_sat_vb  = cfg.btc_payout_fee_sat_vb;
        let esplora_url = cfg.auto_shield.as_ref()
            .map(|s| esplora_base_url(&s.btc_rpc_url))
            .unwrap_or_else(|| "https://blockstream.info/api".to_string());
        tokio::spawn(async move {
            match wait_and_payout_btc(&eth_rpc, &tx, &esplora_url, &wif, &btc_addr, amount_sats, fee_sat_vb).await {
                Ok(btc_txid) => println!(
                    "[unshield] BTC payout sent: txid={btc_txid} amount={amount_sats}sat → {btc_addr}"
                ),
                Err(e) => eprintln!("[unshield] BTC payout FAILED for L2 tx {tx}: {e}"),
            }
        });
    }

    Ok(Json(HttpTxResponse { tx_hash }))
}

// ── ERC shield / unshield handlers ───────────────────────────────────────────

/// Request body for `POST /erc/shield/submit`.
///
/// The relayer calls `PrivacyERC.shield()` with EIP-2612 permit params.
/// For native-ETH pools, pass `permit_*` as zero/null — the contract ignores them.
#[derive(Debug, Deserialize)]
struct HttpErcShieldSubmitRequest {
    /// PrivacyERC contract address (0x-prefixed 20 bytes).
    contract: String,
    /// ZK-proved bundle (must contain proof_bn254 + pub_fields_bn254 + binding_sig_bn254).
    bundle: OrchardStoredBundle,
    /// Token amount in smallest unit (wei for ETH, 6-decimal for USDC …).
    amount: u64,
    /// EIP-2612 permit: token owner EVM address (0x-prefixed).
    #[serde(default)]
    owner: Option<String>,
    /// EIP-2612 permit: expiry unix timestamp.
    #[serde(default)]
    deadline: Option<u64>,
    /// EIP-2612 permit signature v (1–28).
    #[serde(default)]
    permit_v: Option<u8>,
    /// EIP-2612 permit signature r (0x-prefixed 32 bytes).
    #[serde(default)]
    permit_r: Option<String>,
    /// EIP-2612 permit signature s (0x-prefixed 32 bytes).
    #[serde(default)]
    permit_s: Option<String>,
}

// /erc/unshield/submit removed — use /unshield/submit with recipient_evm instead.

#[derive(Deserialize)]
struct HttpMintSubmitRequest {
    /// pERC20 pool (asset) address, 0x + 40 hex.
    contract: String,
    /// Full `mint(uint256,(bytes,uint256[3]))` calldata as 0x hex, built off-chain (forge).
    calldata: String,
}

/// Submit an issuer-signed pERC20 `mint(...)`: broadcast pre-built calldata to the pool, signed
/// with the configured issuer key (`PERC20_ISSUER_PRIVATE_KEY`). `mint` is `onlyIssuer`, so the
/// relayer's normal key cannot be used. The compliance `frozenRoot` is a separate one-time
/// issuer setup (handled outside the relayer), not part of this call.
async fn http_erc_mint_submit(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpMintSubmitRequest>,
) -> Result<Json<HttpTxResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    let issuer_key = cfg.issuer_private_key.as_deref().ok_or_else(|| {
        http_error(anyhow!(
            "mint submit disabled: set PERC20_ISSUER_PRIVATE_KEY on the relayer (mint is onlyIssuer)"
        ))
    })?;
    let cd_hex = req.calldata.strip_prefix("0x").unwrap_or(&req.calldata);
    let calldata =
        hex::decode(cd_hex).map_err(|e| http_error(anyhow!("bad calldata hex: {e}")))?;

    // mint() is the heaviest op (Groth16 pairing + Poseidon depth-32 Merkle insert + Baby JubJub
    // Schnorr verify), so the shield/transfer budgets out-of-gas. But a fixed large limit gets
    // rejected by some providers (e.g. Sepolia/Infura: "gas limit too high"). So estimate gas
    // from the actual calldata and add a 30% margin. An explicit PERC20_MINT_GAS_LIMIT overrides
    // estimation; if estimation fails (e.g. the pool's frozenRoot isn't set yet) fall back to 8M.
    let mint_gas_limit: u64 = match std::env::var("PERC20_MINT_GAS_LIMIT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(g) => g,
        None => {
            let issuer_addr = match parse_hex_key(issuer_key) {
                Ok(sk) => format!("0x{}", hex::encode(eth_address_from_signing_key(&sk))),
                Err(e) => return Err(http_error(anyhow!("bad issuer key: {e}"))),
            };
            let est_client = EthRpcClient::new(cfg.rpc_url.clone());
            let estimated = match est_client.estimate_gas(&issuer_addr, &req.contract, &calldata).await {
                Ok(est) => est.saturating_mul(13) / 10, // +30% margin
                Err(e) => {
                    eprintln!("[mint] eth_estimateGas failed ({e}); using floor");
                    0
                }
            };
            // Clamp: a pERC20 mint needs ~5M gas. Floor at 8M so a low/flaky estimate — e.g. an
            // RPC fallback to a chain where the pool has no code returns ~intrinsic — can't yield
            // an "intrinsic gas too low" tx; cap at 15M to stay under provider per-tx limits
            // ("gas limit too high"). Set PERC20_MINT_GAS_LIMIT to override entirely.
            estimated.clamp(8_000_000, 15_000_000)
        }
    };
    eprintln!("[mint] gas limit = {mint_gas_limit}");
    // Fresh nonce cache: the issuer sender differs from the relayer's normal key, so it must
    // sync its own nonce from chain rather than reuse the relayer's in-process counter.
    let nonce_cache = Arc::new(Mutex::new(None));
    let tx_hash = send_raw_calldata(
        &cfg.rpc_url,
        cfg.chain_id,
        issuer_key,
        &req.contract,
        calldata,
        0,
        cfg.gas_price_gwei,
        mint_gas_limit,
        &nonce_cache,
    )
    .await
    .map_err(http_error)?;

    if let Some(indexer) = cfg.indexer_url.clone() {
        tokio::spawn(notify_pending_tx(Some(indexer), tx_hash.clone(), req.contract.clone()));
    }
    println!("erc mint eth_sendRawTransaction ok: {tx_hash}");
    Ok(Json(HttpTxResponse { tx_hash }))
}

async fn http_erc_shield_submit(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpErcShieldSubmitRequest>,
) -> Result<Json<HttpTxResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    // Parse permit fields (default to zero if not provided — native ETH pools ignore them)
    let owner_bytes: [u8; 20] = if let Some(ref addr) = req.owner {
        parse_evm_address_hex(addr).map_err(|e| http_error(anyhow!("bad owner address: {e}")))?
    } else {
        [0u8; 20]
    };
    let deadline = req.deadline.unwrap_or(0);
    let permit_v = req.permit_v.unwrap_or(0);
    let permit_r = if let Some(ref r) = req.permit_r {
        parse_hex32(r).map_err(|e| http_error(anyhow!("bad permit_r: {e}")))?
    } else {
        [0u8; 32]
    };
    let permit_s = if let Some(ref s) = req.permit_s {
        parse_hex32(s).map_err(|e| http_error(anyhow!("bad permit_s: {e}")))?
    } else {
        [0u8; 32]
    };


    enforce_frozen_compliance(cfg.indexer_url.as_deref(), &cfg.contract, &req.bundle)
        .await
        .map_err(http_error)?;

    let actions     = bundle_to_action_args(&req.bundle).map_err(|e| http_error(anyhow!("bundle decode: {e}")))?;
    let binding_sig = bundle_binding_sig(&req.bundle).map_err(|e| http_error(anyhow!("binding_sig: {e}")))?;

    let erc_args = ErcShieldCalldataArgs {
        actions,
        amount: req.amount as u128,
        owner: owner_bytes,
        deadline,
        permit_v,
        permit_r,
        permit_s,
        binding_sig,
    };
    let calldata = encode_erc_shield_calldata(&erc_args)
        .map_err(|e| http_error(anyhow!("calldata encode: {e}")))?;

    let tx_hash = send_raw_calldata(
        &cfg.rpc_url,
        cfg.chain_id,
        &cfg.private_key,
        &req.contract,
        calldata,
        0,               // value = 0 for ERC-20 (ETH pools: frontend sends msg.value separately)
        cfg.gas_price_gwei,
        cfg.gas_limit_shield,
        &cfg.nonce_cache,
    )
    .await
    .map_err(http_error)?;

    tokio::spawn(notify_pending_tx(cfg.indexer_url.clone(), tx_hash.clone(), req.contract.clone()));
    println!("[erc/shield] submitted: tx={tx_hash} amount={}", req.amount);
    Ok(Json(HttpTxResponse { tx_hash }))
}

// ── ERC calldata helpers ──────────────────────────────────────────────────────

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean).context("invalid hex")?;
    bytes.try_into().map_err(|_| anyhow!("expected 32 bytes, got {}", s.len() / 2))
}

/// Extract `Vec<BundleActionArgs>` from a proved `OrchardStoredBundle`.
fn bundle_to_action_args(bundle: &OrchardStoredBundle) -> Result<Vec<BundleActionArgs>> {
    let mut out = Vec::with_capacity(bundle.actions.len());
    for a in &bundle.actions {
        let proof = a.proof_bn254.clone()
            .ok_or_else(|| anyhow!("action missing proof_bn254 — call prover first"))?;
        let raw_pi: [[u8; 32]; 8] = a.pub_fields_bn254.as_ref()
            .and_then(|v| v.clone().try_into().ok())
            .ok_or_else(|| anyhow!("action missing pub_fields_bn254 (expected 8 elements)"))?;
        let spend_auth: [[u8; 32]; 3] = if a.spend_auth_sig.len() == 96 {
            [
                a.spend_auth_sig[0..32].try_into().unwrap(),
                a.spend_auth_sig[32..64].try_into().unwrap(),
                a.spend_auth_sig[64..96].try_into().unwrap(),
            ]
        } else {
            [[0u8; 32]; 3]
        };
        out.push(BundleActionArgs {
            cmx:            a.cmx,
            enc_ciphertext: a.enc_ciphertext.clone(),
            out_ciphertext: a.out_ciphertext.clone(),
            epk:            a.ephemeral_key,
            nf_old:         a.nullifier,
            anchor:         bundle.anchor_orchard,
            proof,
            pub_fields:     raw_pi,
            spend_auth_sig: spend_auth,
        });
    }
    Ok(out)
}

/// Extract the binding signature `[[u8;32];3]` from a proved `OrchardStoredBundle`.
fn bundle_binding_sig(bundle: &OrchardStoredBundle) -> Result<[[u8; 32]; 3]> {
    bundle.binding_sig_bn254
        .ok_or_else(|| anyhow!("bundle.binding_sig_bn254 is missing"))
}

/// Acquire the next sequential nonce.
///
/// Uses an in-process counter for back-to-back relayer submits, but **re-syncs with
/// `eth_getTransactionCount(pending)` every call** so nonces consumed outside this
/// process (forge deploy, `cast send`, another relayer instance, same EOA) cannot
/// leave the cache permanently behind chain state.
async fn next_nonce(
    client: &EthRpcClient,
    sender_hex: &str,
    cache: &Arc<Mutex<Option<u64>>>,
) -> Result<u64> {
    let chain = client.get_transaction_count(sender_hex).await?;
    let mut g = cache.lock().await;
    let n = match *g {
        None => chain,
        Some(cached) => cached.max(chain),
    };
    *g = Some(n + 1);
    Ok(n)
}

/// Reset the nonce cache on tx error so the next call re-syncs from chain.
async fn invalidate_nonce(cache: &Arc<Mutex<Option<u64>>>) {
    *cache.lock().await = None;
}

fn err_is_nonce_too_low(err: &anyhow::Error) -> bool {
    let s = format!("{err:#}").to_ascii_lowercase();
    s.contains("nonce too low")
}

/// Sign → `eth_sendRawTransaction`, retry once after re-sync if RPC reports nonce too low.
async fn send_raw_with_nonce_retry(
    client: &EthRpcClient,
    sender_hex: &str,
    nonce_cache: &Arc<Mutex<Option<u64>>>,
    mut build: impl FnMut(u64) -> Result<Vec<u8>>,
) -> Result<String> {
    for attempt in 0..2 {
        let nonce = next_nonce(client, sender_hex, nonce_cache).await?;
        let raw_tx = build(nonce)?;
        match client.send_raw_transaction(&raw_tx).await {
            Ok(hash) => return Ok(hash),
            Err(e) => {
                invalidate_nonce(nonce_cache).await;
                if attempt == 0 && err_is_nonce_too_low(&e) {
                    continue;
                }
                return Err(e);
            }
        }
    }
    unreachable!("at most two send attempts")
}

/// Sign and broadcast arbitrary calldata to an EVM contract.
///
/// `nonce_cache` is the in-process nonce counter shared across all handlers.
/// On first call it fetches the current nonce from the chain; subsequently it
/// increments in memory so back-to-back requests never collide on the same nonce.
/// On submission error the cache is reset so the next call re-syncs from chain.
async fn send_raw_calldata(
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
    contract: &str,
    calldata: Vec<u8>,
    value: u64,
    gas_price_gwei: f64,
    gas_limit: u64,
    nonce_cache: &Arc<Mutex<Option<u64>>>,
) -> Result<String> {
    let signing_key = parse_hex_key(private_key)?;
    let addr = eth_address_from_signing_key(&signing_key);
    let client = EthRpcClient::new(rpc_url.to_string());
    // Dynamic EIP-1559 (type-2) fees: pay ~baseFee+tip, cap maxFee at baseFee*2+tip.
    let (max_priority_fee, max_fee) = client.suggest_eip1559_fees(gas_price_gwei).await;

    let sender_hex = format!("0x{}", hex::encode(addr));
    let contract = contract.to_string();
    send_raw_with_nonce_retry(&client, &sender_hex, nonce_cache, |nonce| {
        build_and_sign_eip1559_tx(
            nonce,
            max_priority_fee,
            max_fee,
            gas_limit,
            &contract,
            value,
            &calldata,
            chain_id,
            &signing_key,
        )
    })
    .await
}

/// Poll for L2 tx confirmation (up to 5 min), then sign and broadcast BTC payout via Esplora.
async fn wait_and_payout_btc(
    eth_rpc: &str,
    tx_hash: &str,
    esplora_url: &str,
    wif: &str,
    btc_addr: &str,
    amount_sats: u64,
    fee_sat_vb: u64,
) -> Result<String> {
    let client = Client::new();
    for attempt in 0..60 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let resp: serde_json::Value = client
            .post(eth_rpc)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash]
            }))
            .send().await?.json().await?;
        if let Some(receipt) = resp["result"].as_object() {
            match receipt.get("status").and_then(|s| s.as_str()) {
                Some("0x1") => {
                    println!("[unshield] L2 confirmed (attempt {}), signing BTC payout…", attempt + 1);
                    return btc_payout_local(&client, esplora_url, wif, btc_addr, amount_sats, fee_sat_vb).await;
                }
                Some("0x0") => return Err(anyhow!("L2 unshield tx reverted — BTC payout skipped")),
                _ => {}
            }
        }
    }
    Err(anyhow!("L2 tx not confirmed within 5 minutes"))
}

// ─── BTC local signing (P2TR key-path) via Esplora ───────────────────────────

use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
    Txid as BtcTxid,
    address::Address as BtcAddress,
    consensus::encode::serialize_hex as btc_serialize_hex,
    hashes::Hash as BtcHashTrait,
    key::{Keypair, TapTweak},
    locktime::absolute::LockTime as BtcLockTime,
    secp256k1::{Message as BtcMessage, Secp256k1 as BtcSecp256k1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version as BtcVersion,
    Witness,
};

/// Strip `esplora:` prefix from btc_rpc_url to get a bare HTTPS base URL.
fn esplora_base_url(btc_rpc_url: &str) -> String {
    btc_rpc_url.strip_prefix("esplora:").unwrap_or(btc_rpc_url).to_string()
}

/// Estimate P2TR transaction virtual size in vBytes.
/// Taproot key-path input: ~41 non-witness + 66/4 witness ≈ 57.75 vB
/// P2TR output: 43 bytes  |  tx overhead: 10.5 vB
fn estimate_p2tr_vsize(n_inputs: usize, n_outputs: usize) -> u64 {
    let overhead   = 10u64;
    let input_base = 41u64 * n_inputs as u64;
    let input_wit  = (66u64 * n_inputs as u64 + 3) / 4;
    let outputs    = 43u64 * n_outputs as u64;
    overhead + input_base + input_wit + outputs
}

async fn esplora_get_utxos(client: &Client, base_url: &str, address: &str) -> Result<Vec<EsploraUtxo>> {
    let url = format!("{}/address/{}/utxo", base_url.trim_end_matches('/'), address);
    let utxos: Vec<EsploraUtxo> = client.get(&url).send().await?.json().await?;
    Ok(utxos.into_iter().filter(|u| u.status.confirmed).collect())
}
async fn esplora_broadcast(client: &Client, base_url: &str, tx_hex: &str) -> Result<String> {
    let url  = format!("{}/tx", base_url.trim_end_matches('/'));
    let resp = client.post(&url)
        .header("Content-Type", "text/plain")
        .body(tx_hex.to_string())
        .send().await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Esplora broadcast error: {body}"));
    }
    Ok(resp.text().await?.trim().to_string())
}

/// Build, sign (Taproot key-path), and broadcast a payout transaction.
async fn btc_payout_local(
    client: &Client,
    esplora_url: &str,
    wif: &str,
    recipient_addr_str: &str,
    amount_sats: u64,
    fee_sat_vb: u64,
) -> Result<String> {
    let secp    = BtcSecp256k1::new();
    let network = Network::Bitcoin;

    let privkey    = bitcoin::PrivateKey::from_wif(wif).context("invalid WIF")?;
    let keypair    = Keypair::from_secret_key(&secp, &privkey.inner);
    let (xonly, _) = keypair.x_only_public_key();
    let payout_addr = BtcAddress::p2tr(&secp, xonly, None, network);

    println!("[unshield] payout wallet: {payout_addr}");

    // Fetch confirmed UTXOs, sort largest-first
    let mut utxos = esplora_get_utxos(client, esplora_url, &payout_addr.to_string()).await?;
    if utxos.is_empty() {
        return Err(anyhow!("No confirmed UTXOs at payout address {payout_addr}"));
    }
    utxos.sort_by(|a, b| b.value.cmp(&a.value));

    // Greedy selection
    let mut selected: Vec<&EsploraUtxo> = vec![];
    let mut total_in = 0u64;
    for utxo in &utxos {
        selected.push(utxo);
        total_in += utxo.value;
        let fee = estimate_p2tr_vsize(selected.len(), 2) * fee_sat_vb;
        if total_in >= amount_sats + fee { break; }
    }
    let fee = estimate_p2tr_vsize(selected.len(), 2) * fee_sat_vb;
    if total_in < amount_sats + fee {
        return Err(anyhow!(
            "Insufficient funds: {total_in} sat available, need {} + {fee} fee",
            amount_sats
        ));
    }
    let change = total_in - amount_sats - fee;

    let recipient = BtcAddress::from_str(recipient_addr_str)
        .context("invalid recipient BTC address")?
        .require_network(network)
        .context("wrong network (expected Bitcoin mainnet)")?;

    let inputs: Vec<TxIn> = selected.iter().map(|u| TxIn {
        previous_output: OutPoint {
            txid: BtcTxid::from_str(&u.txid).expect("txid"),
            vout: u.vout,
        },
        script_sig: ScriptBuf::default(),
        sequence:   bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness:    Witness::default(),
    }).collect();

    let mut outputs = vec![TxOut {
        value:         Amount::from_sat(amount_sats),
        script_pubkey: recipient.script_pubkey(),
    }];
    if change > 546 {
        outputs.push(TxOut {
            value:         Amount::from_sat(change),
            script_pubkey: payout_addr.script_pubkey(),
        });
    }

    let mut tx = Transaction {
        version:   BtcVersion::TWO,
        lock_time: BtcLockTime::ZERO,
        input:     inputs,
        output:    outputs,
    };

    let prevouts: Vec<TxOut> = selected.iter().map(|u| TxOut {
        value:         Amount::from_sat(u.value),
        script_pubkey: payout_addr.script_pubkey(),
    }).collect();

    // Compute all sighashes first (immutable borrow), then sign (mutable)
    let tweaked_kp = keypair.tap_tweak(&secp, None);
    let sighashes: Vec<_> = {
        let mut cache = SighashCache::new(&tx);
        (0..tx.input.len()).map(|i| {
            cache.taproot_key_spend_signature_hash(
                i,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            ).expect("sighash")
        }).collect()
    };
    for (i, sh) in sighashes.into_iter().enumerate() {
        let sig = secp.sign_schnorr(&BtcMessage::from_digest(sh.to_byte_array()), &tweaked_kp.to_inner());
        tx.input[i].witness = Witness::from_slice(&[&sig.serialize()]);
    }

    let tx_hex = btc_serialize_hex(&tx);
    println!("[unshield] broadcasting {} vB P2TR tx…", estimate_p2tr_vsize(selected.len(), tx.output.len()));
    esplora_broadcast(client, esplora_url, &tx_hex).await
}

/// sha256(data) → lowercase hex (no 0x prefix)
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(Sha256::digest(data))
}

async fn http_unshield_finalize(
    State(cfg): State<Arc<RelayerHttpConfig>>,
    Json(req): Json<HttpUnshieldFinalizeRequest>,
) -> Result<Json<HttpTxResponse>, (StatusCode, Json<HttpErrorResponse>)> {
    unshield_finalize_submit(
        &cfg.rpc_url,
        cfg.chain_id,
        &cfg.private_key,
        &cfg.contract,
        &req.nf_hex,
        req.amount_sats,
        &req.recipient_meta_hex,
        cfg.gas_price_gwei,
        cfg.gas_limit_unshield,
        &cfg.nonce_cache,
    )
    .await
    .map(|tx_hash| Json(HttpTxResponse { tx_hash }))
    .map_err(http_error)
}

/// Build a CORS layer that restricts allowed origins to the list in
/// `PRIVACYBTC_CORS_ORIGINS` (comma-separated, e.g. `https://app.example.com`).
/// Falls back to localhost-only if the variable is unset.
fn build_cors_layer() -> CorsLayer {
    use tower_http::cors::AllowOrigin;
    let origins_str = std::env::var("PRIVACYBTC_CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:5173,http://127.0.0.1:5173".to_string());
    let origins: Vec<axum::http::HeaderValue> = origins_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any)
}

fn http_error(err: anyhow::Error) -> (StatusCode, Json<HttpErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(HttpErrorResponse {
            error: format!("{err:#}"),
        }),
    )
}

async fn shield_submit(
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
    contract: &str,
    bundle_path: &Path,
    amount_sats_arg: Option<u64>,
    intent_path: Option<&Path>,
    gas_price_gwei: f64,
    gas_limit: u64,
) -> Result<()> {
    // ShieldSubmit CLI subcommand does not have a prover_url arg.
    // The bundle must already contain proof_bn254 + pub_fields_bn254 (call prover before this).
    let raw = std::fs::read_to_string(bundle_path)
        .with_context(|| format!("read {}", bundle_path.display()))?;
    let bundle: OrchardStoredBundle = serde_json::from_str(&raw).context("bundle JSON")?;

    let first = bundle
        .actions
        .first()
        .ok_or_else(|| anyhow!("bundle has no actions"))?;

    let amount_from_intent = if let Some(p) = intent_path {
        let intent_raw = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let intent: ShieldIntentV1 = serde_json::from_str(&intent_raw).context("intent JSON")?;
        let expected_cmx = hex::decode(strip_0x(&intent.orchard_cmx_hex)).context("intent cmx hex")?;
        anyhow::ensure!(
            expected_cmx.len() == 32 && *expected_cmx.as_slice() == first.cmx,
            "intent orchard_cmx_hex does not match bundle first action cmx"
        );
        anyhow::ensure!(
            intent.bundle_sha256_hex == hex::encode(bundle_content_sha256(&bundle)),
            "intent bundle_sha256_hex does not match canonical bundle hash"
        );
        Some(intent.amount_sats)
    } else {
        None
    };

    let amount_sats = match (amount_sats_arg, amount_from_intent) {
        (Some(a), Some(b)) if a != b => {
            return Err(anyhow!(
                "--amount-sats ({a}) disagrees with intent amount_sats ({b})"
            ));
        }
        (Some(a), _) => a,
        (None, Some(b)) => b,
        (None, None) => {
            return Err(anyhow!("pass --amount-sats or --intent-json for amount"));
        }
    };

    let cli_nonce_cache = Arc::new(Mutex::new(None::<u64>));
    let tx_hash = submit_shield_bundle(
        rpc_url,
        chain_id,
        private_key,
        contract,
        &bundle,
        amount_sats,
        gas_price_gwei,
        gas_limit,
        &cli_nonce_cache,
        None,
    )
    .await?;
    println!("eth_sendRawTransaction ok: {tx_hash}");

    Ok(())
}

/// Submit a shield bundle on-chain via bundle().
/// valueBalance must match the signer/prover convention used in this bundle.
/// The bundle must already contain proof_bn254 + pub_fields_bn254 per action.
async fn submit_shield_bundle(
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
    contract: &str,
    bundle: &OrchardStoredBundle,
    amount_sats: u64,
    gas_price_gwei: f64,
    gas_limit: u64,
    nonce_cache: &Arc<Mutex<Option<u64>>>,
    indexer_url: Option<&str>,
) -> Result<String> {
    enforce_frozen_compliance(indexer_url, contract, bundle).await?;

    let binding_sig = bundle
        .binding_sig_bn254
        .ok_or_else(|| anyhow!("bundle.binding_sig_bn254 is missing"))?;

    let mut bundle_actions: Vec<BundleActionArgs> = Vec::with_capacity(bundle.actions.len());
    for a in &bundle.actions {
        let proof = a.proof_bn254.clone()
            .ok_or_else(|| anyhow!("action missing proof_bn254 — call prover first"))?;
        let raw_pi: [[u8; 32]; 8] = a.pub_fields_bn254.as_ref()
            .and_then(|v| <Vec<[u8;32]> as Clone>::clone(v).try_into().ok())
            .ok_or_else(|| anyhow!("action missing pub_fields_bn254 (expected 8 elements)"))?;
        let spend_auth: [[u8; 32]; 3] = if a.spend_auth_sig.len() == 96 {
            [
                a.spend_auth_sig[0..32].try_into().unwrap(),
                a.spend_auth_sig[32..64].try_into().unwrap(),
                a.spend_auth_sig[64..96].try_into().unwrap(),
            ]
        } else {
            [[0u8; 32]; 3]
        };
        bundle_actions.push(BundleActionArgs {
            cmx:             a.cmx,
            enc_ciphertext:  a.enc_ciphertext.clone(),
            out_ciphertext:  a.out_ciphertext.clone(),
            epk:             a.ephemeral_key,
            nf_old:          a.nullifier,
            anchor:          bundle.anchor_orchard,
            proof,
            pub_fields:      raw_pi,
            spend_auth_sig:  spend_auth,
        });
    }

    // Shield: valueBalance = -amount (bit255=1 sign flag, readable satoshis).
    let value_balance = bundle_value_balance_be(amount_sats, true);
    let calldata = encode_bundle_calldata(&BundleCalldataArgs {
        actions: bundle_actions,
        value_balance,
        amount: amount_sats,
        recipient_meta: [0u8; 32],
        binding_sig,
    })
    .map_err(|e| anyhow!("{e}"))?;

    let signing_key = parse_hex_key(private_key)?;
    let addr = eth_address_from_signing_key(&signing_key);
    let client = EthRpcClient::new(rpc_url.to_string());
    let (max_priority_fee, max_fee) = client.suggest_eip1559_fees(gas_price_gwei).await;
    let sender_hex = format!("0x{}", hex::encode(addr));
    let contract = contract.to_string();
    send_raw_with_nonce_retry(&client, &sender_hex, nonce_cache, |nonce| {
        build_and_sign_eip1559_tx(
            nonce, max_priority_fee, max_fee, gas_limit, &contract, 0, &calldata, chain_id, &signing_key,
        )
    })
    .await
}

async fn submit_transfer_bundle(
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
    contract: &str,
    bundle: &OrchardStoredBundle,
    gas_price_gwei: f64,
    gas_limit: u64,
    nonce_cache: &Arc<Mutex<Option<u64>>>,
    indexer_url: Option<&str>,
) -> Result<String> {
    enforce_frozen_compliance(indexer_url, contract, bundle).await?;

    let binding_sig = bundle
        .binding_sig_bn254
        .ok_or_else(|| anyhow!("bundle.binding_sig_bn254 is missing"))?;

    // All actions (single or multi) go through bundle().
    let mut bundle_actions: Vec<BundleActionArgs> = Vec::with_capacity(bundle.actions.len());
    for a in &bundle.actions {
        let proof = a.proof_bn254.clone()
            .ok_or_else(|| anyhow!("action missing proof_bn254 — call prover first"))?;
        let raw_pi: [[u8; 32]; 8] = a.pub_fields_bn254.as_ref()
            .and_then(|v| <Vec<[u8;32]> as Clone>::clone(v).try_into().ok())
            .ok_or_else(|| anyhow!("action missing pub_fields_bn254 (expected 8 elements)"))?;
        let spend_auth: [[u8; 32]; 3] = if a.spend_auth_sig.len() == 96 {
            [
                a.spend_auth_sig[0..32].try_into().unwrap(),
                a.spend_auth_sig[32..64].try_into().unwrap(),
                a.spend_auth_sig[64..96].try_into().unwrap(),
            ]
        } else {
            [[0u8; 32]; 3]
        };
        bundle_actions.push(BundleActionArgs {
            cmx:             a.cmx,
            enc_ciphertext:  a.enc_ciphertext.clone(),
            out_ciphertext:  a.out_ciphertext.clone(),
            epk:             a.ephemeral_key,
            nf_old:          a.nullifier,
            anchor:          bundle.anchor_orchard,
            proof,
            pub_fields:      raw_pi,
            spend_auth_sig:  spend_auth,
        });
    }
    let calldata = encode_bundle_calldata(&BundleCalldataArgs {
        actions:        bundle_actions,
        value_balance:  [0u8; 32], // pure transfer → valueBalance=0
        amount:         0,
        recipient_meta: [0u8; 32],
        binding_sig,
    })
    .map_err(|e| anyhow!("{e}"))?;

    let signing_key = parse_hex_key(private_key)?;
    let addr = eth_address_from_signing_key(&signing_key);
    let client = EthRpcClient::new(rpc_url.to_string());
    let (max_priority_fee, max_fee) = client.suggest_eip1559_fees(gas_price_gwei).await;
    let sender_hex = format!("0x{}", hex::encode(addr));
    let contract = contract.to_string();
    send_raw_with_nonce_retry(&client, &sender_hex, nonce_cache, |nonce| {
        build_and_sign_eip1559_tx(
            nonce, max_priority_fee, max_fee, gas_limit, &contract, 0, &calldata, chain_id, &signing_key,
        )
    })
    .await
}

/// Submit `unshield()` on-chain using a pre-proven `OrchardStoredBundle`.
///
/// The bundle must contain `proof_bn254`, `pub_fields_bn254`, and `binding_sig_bn254`.
/// This calls the trustless `unshield(nfOld, anchor, proof, pubInputs, amount, recipientMeta, bindingSig)`
/// function — no federation trust required on the EVM side.
async fn submit_unshield_bundle(
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
    contract: &str,
    bundle: &OrchardStoredBundle,
    amount_sats: u64,
    recipient_meta_hex: &str,
    gas_price_gwei: f64,
    gas_limit: u64,
    nonce_cache: &Arc<Mutex<Option<u64>>>,
    indexer_url: Option<&str>,
) -> Result<String> {
    enforce_frozen_compliance(indexer_url, contract, bundle).await?;

    let binding_sig = bundle
        .binding_sig_bn254
        .ok_or_else(|| anyhow!(
            "bundle.binding_sig_bn254 is missing — generate binding signature via prover /prove endpoint before submitting"
        ))?;

    let recipient_meta = parse_fixed_hex_32(recipient_meta_hex)
        .with_context(|| format!("invalid recipient_meta_hex: {recipient_meta_hex}"))?;

    // Build bundle actions — unshield and transfer share the same bundle() call.
    let mut bundle_actions: Vec<BundleActionArgs> = Vec::with_capacity(bundle.actions.len());
    for a in &bundle.actions {
        let proof = a.proof_bn254.clone()
            .ok_or_else(|| anyhow!("action missing proof_bn254 (run local Groth16 prover first)"))?;
        let raw_pi: [[u8; 32]; 8] = a.pub_fields_bn254.as_ref()
            .and_then(|v| <Vec<[u8;32]> as Clone>::clone(v).try_into().ok())
            .ok_or_else(|| anyhow!("action missing pub_fields_bn254 (expected 8 elements)"))?;
        let spend_auth: [[u8; 32]; 3] = if a.spend_auth_sig.len() == 96 {
            [
                a.spend_auth_sig[0..32].try_into().unwrap(),
                a.spend_auth_sig[32..64].try_into().unwrap(),
                a.spend_auth_sig[64..96].try_into().unwrap(),
            ]
        } else {
            [[0u8; 32]; 3]
        };
        bundle_actions.push(BundleActionArgs {
            cmx:             a.cmx,
            enc_ciphertext:  a.enc_ciphertext.clone(),
            out_ciphertext:  a.out_ciphertext.clone(),
            epk:             a.ephemeral_key,
            nf_old:          a.nullifier,
            anchor:          bundle.anchor_orchard,
            proof,
            pub_fields:      raw_pi,
            spend_auth_sig:  spend_auth,
        });
    }

    // Unshield: valueBalance = +amount (bit255=0, readable positive satoshis).
    let value_balance = bundle_value_balance_be(amount_sats, false);
    let calldata = encode_bundle_calldata(&BundleCalldataArgs {
        actions: bundle_actions,
        value_balance,
        amount: amount_sats,
        recipient_meta,
        binding_sig,
    })
    .map_err(|e| anyhow!("{e}"))?;

    let signing_key = parse_hex_key(private_key)?;
    let addr = eth_address_from_signing_key(&signing_key);
    let client = EthRpcClient::new(rpc_url.to_string());
    let (max_priority_fee, max_fee) = client.suggest_eip1559_fees(gas_price_gwei).await;
    let sender_hex = format!("0x{}", hex::encode(addr));
    let contract = contract.to_string();
    send_raw_with_nonce_retry(&client, &sender_hex, nonce_cache, |nonce| {
        build_and_sign_eip1559_tx(
            nonce, max_priority_fee, max_fee, gas_limit, &contract, 0, &calldata, chain_id, &signing_key,
        )
    })
    .await
}

async fn unshield_finalize_submit(
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
    contract: &str,
    nf_hex: &str,
    amount_sats: u64,
    recipient_meta_hex: &str,
    gas_price_gwei: f64,
    gas_limit: u64,
    nonce_cache: &Arc<Mutex<Option<u64>>>,
) -> Result<String> {
    let nf = parse_fixed_hex_32(nf_hex)?;
    let recipient_meta = parse_fixed_hex_32(recipient_meta_hex)?;
    let calldata = encode_finalize_withdraw_calldata(&FinalizeWithdrawCalldataArgs {
        nf,
        amount_sats,
        recipient_meta,
    });

    let signing_key = parse_hex_key(private_key)?;
    let addr = eth_address_from_signing_key(&signing_key);
    let client = EthRpcClient::new(rpc_url.to_string());
    let (max_priority_fee, max_fee) = client.suggest_eip1559_fees(gas_price_gwei).await;
    let sender_hex = format!("0x{}", hex::encode(addr));
    let contract = contract.to_string();
    send_raw_with_nonce_retry(&client, &sender_hex, nonce_cache, |nonce| {
        build_and_sign_eip1559_tx(
            nonce, max_priority_fee, max_fee, gas_limit, &contract, 0, &calldata, chain_id, &signing_key,
        )
    })
    .await
}

/// Poll for EVM receipt (up to 5 min). On success (status=0x1) delete the intent
/// and its bundle file so the same proof cannot be re-submitted.
/// Returns true if the intent was cleaned up, false if tx reverted or timed out.
async fn cleanup_intent_after_receipt(rpc_url: &str, tx_hash: &str, intent_path: &str) -> bool {
    let client = Client::new();
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let resp: serde_json::Value = match client
            .post(rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash]
            }))
            .send().await
        {
            Ok(r) => match r.json().await {
                Ok(v) => v,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        if let Some(receipt) = resp["result"].as_object() {
            match receipt.get("status").and_then(|s| s.as_str()) {
                Some("0x1") => {
                    let _ = std::fs::remove_file(intent_path);
                    let _ = std::fs::remove_file(bundle_path_for_intent(Path::new(intent_path)));
                    return true;
                }
                Some("0x0") => return false, // reverted — keep intent for retry
                _ => {}
            }
        }
    }
    false
}

fn bundle_path_for_intent(intent_path: &Path) -> PathBuf {
    let name = intent_path.file_name().and_then(|s| s.to_str()).unwrap_or("intent.json");
    let stem = name.strip_suffix(".json").unwrap_or(name);
    let bundle_name = format!("{stem}.bundle.json");
    intent_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(bundle_name)
}

async fn next_transfer_bundle_path(
    transfer_dir: &Path,
    seen_bundle_paths: &Arc<Mutex<std::collections::HashSet<String>>>,
) -> Result<PathBuf> {
    let pattern = transfer_dir.join("*.transfer.bundle.json");
    let pattern_s = pattern.to_string_lossy();
    let mut candidates: Vec<PathBuf> = vec![];
    for entry in glob::glob(&pattern_s).context("glob transfer bundles")? {
        let path = entry.context("glob entry")?;
        candidates.push(path);
    }
    candidates.sort();
    let seen = seen_bundle_paths.lock().await;
    let selected = candidates
        .into_iter()
        .find(|p| !seen.contains(&p.to_string_lossy().into_owned()))
        .ok_or_else(|| anyhow!("no unsubmitted transfer bundles in {}", transfer_dir.display()))?;
    Ok(selected)
}

#[derive(Deserialize)]
struct ListUnspentEntry {
    txid: String,
    vout: u32,
    amount: f64,
    #[serde(default)]
    confirmations: Option<u32>,
}

// ─── BTC backend abstraction (Bitcoin Core RPC vs Esplora API) ────────────────

/// Detect backend from URL:
/// - `esplora:https://…` → Esplora  (e.g. `esplora:https://blockstream.info/api`)
/// - anything else       → Bitcoin Core JSON-RPC
enum BtcBackend {
    Rpc(BtcRpcClient),
    Esplora(EsploraClient),
}

impl BtcBackend {
    fn from_url(btc_rpc_url: &str) -> Result<Self> {
        if let Some(esplora_base) = btc_rpc_url.strip_prefix("esplora:") {
            Ok(BtcBackend::Esplora(EsploraClient::new(esplora_base.to_string())))
        } else {
            let (base, user, pass) = parse_rpc_url(btc_rpc_url)?;
            Ok(BtcBackend::Rpc(BtcRpcClient::new(base, user, pass)))
        }
    }

    async fn list_utxos(&self, address: &str, min_conf: u32) -> Result<Vec<ListUnspentEntry>> {
        match self {
            BtcBackend::Rpc(c) => c.listunspent(min_conf, 999_999, &[address.to_string()]).await,
            BtcBackend::Esplora(c) => c.listunspent(address, min_conf).await,
        }
    }
}

/// Blockstream/Esplora REST API client.
/// Endpoint: `GET {base}/address/{addr}/utxo`
/// Docs: <https://github.com/Blockstream/esplora/blob/master/API.md>
struct EsploraClient {
    http: Client,
    base: String,
}

#[derive(Deserialize)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    status: EsploraStatus,
    value: u64, // satoshis
}

#[derive(Deserialize)]
struct EsploraStatus {
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u64>,
}

impl EsploraClient {
    fn new(base: String) -> Self {
        Self { http: Client::new(), base: base.trim_end_matches('/').to_string() }
    }

    async fn tip_height(&self) -> Result<u64> {
        let url = format!("{}/blocks/tip/height", self.base);
        let text = self.http.get(&url).send().await?.text().await?;
        text.trim().parse::<u64>().context("parse tip height")
    }

    async fn listunspent(&self, address: &str, min_conf: u32) -> Result<Vec<ListUnspentEntry>> {
        let url = format!("{}/address/{}/utxo", self.base, address);
        let utxos: Vec<EsploraUtxo> = self.http.get(&url).send().await?.json().await?;
        if utxos.is_empty() {
            return Ok(vec![]);
        }
        // Fetch tip height only if we need confirmation counts.
        let tip = if min_conf > 1 {
            Some(self.tip_height().await.unwrap_or(0))
        } else {
            None
        };
        let result = utxos
            .into_iter()
            .filter_map(|u| {
                if !u.status.confirmed {
                    if min_conf == 0 { } else { return None; }
                }
                let confs = match (tip, u.status.block_height) {
                    (Some(t), Some(bh)) if t >= bh => (t - bh + 1) as u32,
                    _ => if u.status.confirmed { 1 } else { 0 },
                };
                if confs < min_conf {
                    return None;
                }
                Some(ListUnspentEntry {
                    txid: u.txid,
                    vout: u.vout,
                    // Esplora returns satoshis; convert to BTC for ListUnspentEntry.
                    amount: u.value as f64 / 100_000_000.0,
                    confirmations: Some(confs),
                })
            })
            .collect();
        Ok(result)
    }
}

async fn watch_btc_loop(
    btc_rpc_url: &str,
    deposit_address: &str,
    intent_dir: &Path,
    poll_secs: u64,
    min_conf: u32,
    once: bool,
) -> Result<()> {
    let backend = BtcBackend::from_url(btc_rpc_url)?;
    loop {
        match poll_deposits_backend(&backend, deposit_address, intent_dir, min_conf).await {
            Ok(matches) => {
                if !matches.is_empty() {
                    println!("{}", serde_json::to_string_pretty(&matches)?);
                }
            }
            Err(e) => eprintln!("watch-btc poll error: {e:#}"),
        }
        if once {
            break;
        }
        tokio::time::sleep(Duration::from_secs(poll_secs)).await;
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct BtcIntentMatch {
    intent_path: String,
    amount_sats: u64,
    orchard_cmx_hex: String,
    matched_utxo: MatchedUtxo,
}

#[derive(serde::Serialize)]
struct MatchedUtxo {
    txid: String,
    vout: u32,
    amount_sats: u64,
    confirmations: u32,
}

/// Poll all shield intents in `intent_dir` against confirmed UTXOs at the deposit address.
/// When an intent has `btc_txid` set, the UTXO is matched by txid (exact); otherwise
/// falls back to amount-only matching (legacy behaviour for intents without txid).
async fn poll_deposits_backend(
    backend: &BtcBackend,
    deposit_address: &str,
    intent_dir: &Path,
    min_conf: u32,
) -> Result<Vec<BtcIntentMatch>> {
    let utxos = backend.list_utxos(deposit_address, min_conf).await?;
    poll_deposits_utxos(&utxos, deposit_address, intent_dir, min_conf)
}

fn poll_deposits_utxos(
    utxos: &[ListUnspentEntry],
    _deposit_address: &str,
    intent_dir: &Path,
    min_conf: u32,
) -> Result<Vec<BtcIntentMatch>> {
    let pattern = intent_dir.join("*.json");
    let pattern_s = pattern.to_string_lossy();
    let mut intents: Vec<(PathBuf, ShieldIntentV1)> = vec![];
    for entry in glob::glob(&pattern_s).context("glob intents")? {
        let path = entry.context("glob entry")?;
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if fname.starts_with('.') || fname.ends_with(".bundle.json") {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Ok(intent) = serde_json::from_str::<ShieldIntentV1>(&raw) {
            intents.push((path, intent));
        }
    }

    let mut out = vec![];
    for (intent_path, intent) in intents {
        let bundle_path = bundle_path_for_intent(&intent_path);
        let bundle_raw = match std::fs::read_to_string(&bundle_path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let bundle: OrchardStoredBundle = match serde_json::from_str(&bundle_raw) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if intent.bundle_sha256_hex != hex::encode(bundle_content_sha256(&bundle)) {
            eprintln!(
                "skip {} (bundle hash mismatch at {})",
                intent_path.display(),
                bundle_path.display()
            );
            continue;
        }
        let Some(first) = bundle.actions.first() else { continue };
        let Ok(cmx_hex) = hex::decode(strip_0x(&intent.orchard_cmx_hex)) else { continue };
        if cmx_hex.len() != 32 || *cmx_hex.as_slice() != first.cmx {
            continue;
        }

        let intent_txid = match &intent.btc_txid {
            Some(t) => t.to_lowercase(),
            // No txid → intent is legacy/broken, skip it.
            None => {
                eprintln!("[shield] skip {} (no btc_txid — delete and re-shield)", intent_path.display());
                continue;
            }
        };
        for u in utxos {
            let sats = btc_to_sats(u.amount)?;
            if u.confirmations.unwrap_or(0) < min_conf { continue; }
            if sats == intent.amount_sats && u.txid.to_lowercase() == intent_txid {
                out.push(BtcIntentMatch {
                    intent_path: intent_path.to_string_lossy().into_owned(),
                    amount_sats: intent.amount_sats,
                    orchard_cmx_hex: intent.orchard_cmx_hex.clone(),
                    matched_utxo: MatchedUtxo {
                        txid: u.txid.clone(),
                        vout: u.vout,
                        amount_sats: sats,
                        confirmations: u.confirmations.unwrap_or(0),
                    },
                });
                break;
            }
        }
    }
    Ok(out)
}

fn btc_to_sats(amount_btc: f64) -> Result<u64> {
    let sats = (amount_btc * 100_000_000.0).round();
    if sats < 0.0 || sats > u64::MAX as f64 {
        return Err(anyhow!("invalid BTC amount"));
    }
    Ok(sats as u64)
}

fn parse_rpc_url(raw: &str) -> Result<(String, Option<String>, Option<String>)> {
    let u = Url::parse(raw).context("rpc url")?;
    let user = if u.username().is_empty() {
        None
    } else {
        Some(u.username().to_string())
    };
    let pass = u.password().map(|s| s.to_string());
    let mut base = u.clone();
    let _ = base.set_username("");
    let _ = base.set_password(None);
    let base_s = base.as_str().trim_end_matches('/').to_string();
    Ok((base_s, user, pass))
}

struct BtcRpcClient {
    http: Client,
    url: String,
    auth_user: Option<String>,
    auth_pass: Option<String>,
}

impl BtcRpcClient {
    fn new(url: String, auth_user: Option<String>, auth_pass: Option<String>) -> Self {
        Self {
            http: Client::new(),
            url: url,
            auth_user,
            auth_pass,
        }
    }

    async fn listunspent(&self, min: u32, max: u32, addresses: &[String]) -> Result<Vec<ListUnspentEntry>> {
        let params = serde_json::json!([min, max, addresses, true]);
        self.rpc_call("listunspent", params).await
    }

    async fn rpc_call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let req = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "privacybtc-relayer",
            "method": method,
            "params": params,
        });
        let mut request = self.http.post(&self.url).json(&req);
        if let (Some(u), Some(p)) = (&self.auth_user, &self.auth_pass) {
            request = request.basic_auth(u, Some(p));
        }
        let resp: JsonRpcResponse<T> = request.send().await?.json().await?;
        match (resp.result, resp.error) {
            (Some(r), None) => Ok(r),
            (None, Some(e)) => Err(anyhow!("btc rpc {}: {} ({})", method, e.message, e.code)),
            _ => Err(anyhow!("btc rpc {}: malformed response", method)),
        }
    }
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

struct EthRpcClient {
    http: Client,
    urls: Vec<String>,
}

impl EthRpcClient {
    fn new(url: String) -> Self {
        // Optional fallback RPCs, comma-separated in PRIVACYBTC_ETH_RPC_FALLBACK_URLS. Default:
        // NONE (use only the configured primary). These MUST be on the SAME chain as `url`.
        //
        // This previously hardcoded Arbitrum-mainnet URLs, which silently returned WRONG-CHAIN
        // results whenever the primary RPC hiccuped: e.g. on a Sepolia deployment, eth_estimateGas
        // would fall back to Arbitrum (where the pool has no code) and return ~intrinsic gas,
        // producing an unsendable "intrinsic gas too low" mint tx. Cross-chain fallbacks are
        // never safe, so they are no longer baked in.
        let mut urls = vec![url.clone()];
        if let Ok(extra) = std::env::var("PRIVACYBTC_ETH_RPC_FALLBACK_URLS") {
            for f in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let f = f.to_string();
                if f != url && !urls.contains(&f) {
                    urls.push(f);
                }
            }
        }
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .expect("reqwest client");
        Self { http, urls }
    }

    async fn block_number(&self) -> Result<u64> {
        let hex_num: String = self
            .rpc_call("eth_blockNumber", serde_json::json!([]))
            .await?;
        parse_hex_u64(&hex_num)
    }

    async fn get_transaction_count(&self, address: &str) -> Result<u64> {
        let hex_num: String = self
            .rpc_call(
                "eth_getTransactionCount",
                serde_json::json!([address, "pending"]),
            )
            .await?;
        parse_hex_u64(&hex_num)
    }

    async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        let hex_tx = format!("0x{}", hex::encode(raw_tx));
        self.rpc_call("eth_sendRawTransaction", serde_json::json!([hex_tx]))
            .await
    }

    /// `eth_estimateGas` for a call `{from, to, data}` against the latest state. Returns the
    /// estimated gas units. Used to size mint() (heavy: pairing + Poseidon Merkle + Schnorr)
    /// without hardcoding a limit that may exceed a provider's per-tx cap.
    async fn estimate_gas(&self, from: &str, to: &str, data: &[u8]) -> Result<u64> {
        let hex_data = format!("0x{}", hex::encode(data));
        let hex_gas: String = self
            .rpc_call(
                "eth_estimateGas",
                serde_json::json!([{ "from": from, "to": to, "data": hex_data }]),
            )
            .await?;
        parse_hex_u64(&hex_gas)
    }

    /// Current `baseFeePerGas` (wei) from the latest block (EIP-1559 chains).
    async fn base_fee_per_gas(&self) -> Result<u64> {
        let block: Value = self
            .rpc_call("eth_getBlockByNumber", serde_json::json!(["latest", false]))
            .await?;
        let bf = block
            .get("baseFeePerGas")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("baseFeePerGas missing from latest block (non-EIP-1559 chain?)"))?;
        parse_hex_u64(bf)
    }

    /// Suggest dynamic EIP-1559 fees `(maxPriorityFeePerGas, maxFeePerGas)` in wei.
    ///
    /// Pays ~`baseFee + tip` (cheap when the network is quiet) while capping `maxFee`
    /// at `baseFee*2 + tip` so the tx still lands if the base fee rises a bit before
    /// inclusion. If the base fee can't be read, falls back to a flat `fallback_gwei`.
    async fn suggest_eip1559_fees(&self, fallback_gwei: f64) -> (u128, u128) {
        const TIP_WEI: u128 = 1_000_000_000; // 1 gwei priority fee
        match self.base_fee_per_gas().await {
            Ok(base) => {
                let base = base as u128;
                (TIP_WEI, base * 2 + TIP_WEI)
            }
            Err(e) => {
                let flat = (fallback_gwei * 1_000_000_000.0) as u128;
                eprintln!("[relayer] base fee unavailable ({e}); EIP-1559 fallback maxFee={fallback_gwei} gwei");
                (TIP_WEI.min(flat.max(1)), flat.max(TIP_WEI))
            }
        }
    }

    /// 查询 tx receipt。返回 None 表示还在 pending；Some(true) 成功；Some(false) revert。
    async fn get_transaction_receipt_status(&self, tx_hash: &str) -> Result<Option<bool>> {
        #[derive(serde::Deserialize)]
        struct Receipt {
            status: String,
        }
        let result: Option<Receipt> = self
            .rpc_call("eth_getTransactionReceipt", serde_json::json!([tx_hash]))
            .await?;
        Ok(result.map(|r| r.status == "0x1"))
    }

    /// 依次尝试每个 RPC URL，任意一个成功即返回；全部失败才报错。
    async fn rpc_call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        });
        let mut last_err = anyhow::anyhow!("no rpc urls configured");
        for url in &self.urls {
            match self.http.post(url).json(&req).send().await {
                Ok(resp) => match resp.json::<JsonRpcResponse<T>>().await {
                    Ok(r) => match (r.result, r.error) {
                        (Some(v), None) => return Ok(v),
                        (None, Some(e)) => {
                            last_err = anyhow!("rpc error {}: {}", e.code, e.message);
                            // JSON-RPC 应用层错误不换节点，直接返回
                            return Err(last_err);
                        }
                        _ => { last_err = anyhow!("malformed rpc response from {url}"); }
                    },
                    Err(e) => { last_err = anyhow!("decode error from {url}: {e}"); }
                },
                Err(e) => {
                    eprintln!("[relayer] rpc {url} failed ({e}), trying next…");
                    last_err = anyhow!("connection error from {url}: {e}");
                }
            }
        }
        Err(last_err)
    }
}

fn parse_hex_u64(hex: &str) -> Result<u64> {
    let s = strip_0x(hex);
    u64::from_str_radix(s, 16).context("hex u64")
}

// ─── EIP-155 legacy RLP (same shape as privacybtc-indexer) ─────────────────

/// Build and sign an **EIP-1559 (type-2)** transaction.
///
/// Envelope: `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
/// gasLimit, to, value, data, accessList])`; the signed tx appends
/// `[yParity, r, s]`. Access list is empty (`0xc0`).
#[allow(clippy::too_many_arguments)]
fn build_and_sign_eip1559_tx(
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: &str,
    value: u64,
    data: &[u8],
    chain_id: u64,
    signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    let to_bytes = hex::decode(strip_0x(to)).context("contract address")?;
    if to_bytes.len() != 20 {
        return Err(anyhow!("contract address must be 20 bytes"));
    }
    let access_list = rlp_list(vec![]); // empty access list → 0xc0

    // Unsigned payload (9 fields).
    let payload = rlp_list(vec![
        rlp_uint(chain_id as u128),
        rlp_uint(nonce as u128),
        rlp_uint(max_priority_fee_per_gas),
        rlp_uint(max_fee_per_gas),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value as u128),
        rlp_bytes(data),
        access_list.clone(),
    ]);
    // sighash = keccak256(0x02 || payload)
    let mut sig_input = Vec::with_capacity(1 + payload.len());
    sig_input.push(0x02);
    sig_input.extend_from_slice(&payload);
    let tx_hash: [u8; 32] = Keccak256::digest(&sig_input).into();

    let (sig, recid): (k256::ecdsa::Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&tx_hash)
        .map_err(|e| anyhow!("signing failed: {e}"))?;
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let y_parity = recid.to_byte() as u128; // type-2 uses yParity (0/1), not the EIP-155 v

    // Signed tx (12 fields) = 0x02 || rlp([...payload..., yParity, r, s])
    let signed = rlp_list(vec![
        rlp_uint(chain_id as u128),
        rlp_uint(nonce as u128),
        rlp_uint(max_priority_fee_per_gas),
        rlp_uint(max_fee_per_gas),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value as u128),
        rlp_bytes(data),
        access_list,
        rlp_uint(y_parity),
        rlp_uint256(&r), // big integer, no leading zeros
        rlp_uint256(&s),
    ]);
    let mut out = Vec::with_capacity(1 + signed.len());
    out.push(0x02);
    out.extend_from_slice(&signed);
    Ok(out)
}

fn rlp_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    let bytes = n.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    rlp_bytes(&bytes[start..])
}

/// Encode a 256-bit big integer (32 bytes) as an RLP integer — strips leading zeros.
/// Required for LegacyTx R and S fields; `rlp_bytes` would preserve leading zeros
/// and produce a non-canonical encoding rejected by go-ethereum.
fn rlp_uint256(bytes: &[u8; 32]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    if start == 32 {
        return vec![0x80]; // zero
    }
    rlp_bytes(&bytes[start..])
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0x80];
    }
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    if bytes.len() <= 55 {
        let mut out = vec![0x80u8 + bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    } else {
        let len = bytes.len();
        let be = len.to_be_bytes();
        let ltrim = be.iter().position(|&b| b != 0).unwrap_or(7);
        let len_enc = &be[ltrim..];
        let mut out = vec![0xb7u8 + len_enc.len() as u8];
        out.extend_from_slice(len_enc);
        out.extend_from_slice(bytes);
        out
    }
}

fn rlp_list(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body: Vec<u8> = items.into_iter().flatten().collect();
    if body.len() <= 55 {
        let mut out = vec![0xc0u8 + body.len() as u8];
        out.append(&mut body);
        out
    } else {
        let len = body.len();
        let be = len.to_be_bytes();
        let ltrim = be.iter().position(|&b| b != 0).unwrap_or(7);
        let len_enc = &be[ltrim..];
        let mut out = vec![0xf7u8 + len_enc.len() as u8];
        out.extend_from_slice(len_enc);
        out.append(&mut body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_path_sibling() {
        let p = PathBuf::from("/a/deposit-1.json");
        assert_eq!(bundle_path_for_intent(&p), PathBuf::from("/a/deposit-1.bundle.json"));
    }
}
