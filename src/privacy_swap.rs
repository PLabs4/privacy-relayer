use anyhow::{anyhow, Context, Result};
use ethabi::{encode, Address, Token, Uint};
use privacy_core::ethereum::{privacy_call_commit, PrivacyCallArgs};
use serde::Deserialize;
use sha3::{Digest, Keccak256};

use crate::fee_calldata::privacy_call_token;

pub const PONS_V1_ROUTE_DATA_LEN: usize = 10 * 32;
pub const PONS_V2_ROUTE_DATA_LEN: usize = 15 * 32;
pub const PROTOCOL_VERSION: u64 = 3;
pub const APPLICATION_VERSION: u64 = 2;
pub const ROBINHOOD_CHAIN_ID: u64 = 4_663;
pub const PONS_V1_MARKET: &str = "pons-v1-v3";
pub const PONS_V2_MARKET: &str = "pons-v2-graduated-v4";
pub const PONS_V1_MARKET_PROFILE_HASH: [u8; 32] = [
    0xd1, 0x12, 0xf8, 0xb0, 0x45, 0x2a, 0x7f, 0x16, 0xed, 0x89, 0xf4, 0xc4, 0x9e, 0xeb, 0x0e, 0x5b,
    0x90, 0x07, 0xea, 0xbf, 0x04, 0xfe, 0xe3, 0xd2, 0xa8, 0xe4, 0xda, 0xb0, 0x3f, 0xe3, 0x29, 0x37,
];
pub const PONS_V2_MARKET_PROFILE_HASH: [u8; 32] = [
    0x78, 0x5a, 0xf6, 0x4c, 0x29, 0xa9, 0x1e, 0x87, 0x17, 0x7c, 0xba, 0x03, 0x1b, 0x96, 0x36, 0x0f,
    0x44, 0xd5, 0x03, 0xa5, 0xec, 0x1b, 0x01, 0x44, 0xbf, 0x42, 0x6a, 0x0d, 0xc5, 0xe3, 0xd4, 0x21,
];
pub const ROBINHOOD_V3_QUOTER: &str = "0x33e885ed0ec9bf04ecfb19341582aadcb4c8a9e7";
pub const ROBINHOOD_V4_POOL_MANAGER: &str = "0x8366a39cc670b4001a1121b8f6a443a643e40951";
pub const ROBINHOOD_V4_QUOTER: &str = "0x8dc178efb8111bb0973dd9d722ebeff267c98f94";
const BPS_DENOMINATOR: u64 = 10_000;
const U48_MAX: u64 = (1u64 << 48) - 1;

const SWAP_SIG: &[u8] = b"swap((uint64,uint48,uint256,uint64,uint48,uint64,uint256,uint256,uint256,uint256,uint16,uint64,bytes32,bytes32),bytes,(bytes,uint256[8]),(bytes,uint256[8]))";
const SWAP_CONTEXT_SIG: &[u8] = b"swapContext((uint64,uint48,uint256,uint64,uint48,uint64,uint256,uint256,uint256,uint256,uint16,uint64,bytes32,bytes32),(bytes,uint256[8]))";
const V4_QUOTE_SIG: &[u8] =
    b"quoteExactOutputSingle(((address,address,uint24,int24,address),bool,uint128,bytes))";
const V3_QUOTE_SIG: &[u8] = b"quoteExactOutput(bytes,uint256)";
const GET_LAUNCHED_TOKEN_SIG: &[u8] = b"getLaunchedToken(address)";
const GRADUATION_STATUS_SIG: &[u8] = b"graduationStatus(address)";
const GET_POOL_SIG: &[u8] = b"getPool(address,address,uint24)";
const HOOK_LAUNCH_SIG: &[u8] = b"launches(bytes32)";

#[derive(Clone, Debug)]
pub struct PrivacySwapConfig {
    pub accepting: bool,
    pub market: String,
    pub route_id: [u8; 32],
    pub direction: String,
    pub asset_symbol: String,
    pub asset_name: String,
    pub coordinator: String,
    pub registry: String,
    pub input_pool: String,
    pub output_pool: String,
    pub input_verifier_set_id: [u8; 32],
    pub output_verifier_set_id: [u8; 32],
    pub input_token: String,
    pub output_token: String,
    pub input_scale: Uint,
    pub output_scale: Uint,
    pub input_unshield_fee_units: u64,
    pub output_shield_fee_units: u64,
    pub adapter: String,
    pub adapter_runtime_codehash: [u8; 32],
    pub market_profile: [u8; 32],
    pub fee_collector: String,
    pub swap_fee_units: u64,
    pub max_ttl_seconds: u64,
    pub max_market_slippage_bps_cap: u16,
    pub route_data: Vec<u8>,
    pub route_hash: [u8; 32],
    pub quoter: String,
    pub quoter_runtime_codehash: [u8; 32],
    pub factory: String,
    pub factory_runtime_codehash: [u8; 32],
    pub pool_manager: String,
    pub hook: String,
    pub weth: String,
    pub v3_factory: String,
    pub v3_factory_runtime_codehash: [u8; 32],
    pub pool: String,
    pub pool_runtime_codehash: [u8; 32],
    pub meme_token: String,
    pub pair_token: String,
    pub pool_fee: u32,
    pub tick_spacing: i32,
    pub zero_for_one: bool,
    pub hook_fee_bps: u16,
    pub creator_tax_bps: u16,
    pub guardian: String,
    pub gas_limit: u64,
    pub min_broadcast_window_seconds: u64,
    pub event_getlogs_max_span: u64,
}

/// Individual route admission pins each fee to its immutable Coordinator.
/// The reverse pair shares its market and safety policy, but swap_fee_units
/// uses a different input-note denomination in each direction (ETH vs meme).
pub fn validate_reverse_pair(buy: &PrivacySwapConfig, sell: &PrivacySwapConfig) -> Result<()> {
    if buy.direction != "buy"
        || sell.direction != "sell"
        || buy.market != sell.market
        || buy.meme_token != sell.meme_token
        || buy.asset_symbol != sell.asset_symbol
        || buy.asset_name != sell.asset_name
        || buy.input_pool != sell.output_pool
        || buy.output_pool != sell.input_pool
        || buy.input_scale != sell.output_scale
        || buy.output_scale != sell.input_scale
        || buy.input_verifier_set_id != sell.output_verifier_set_id
        || buy.output_verifier_set_id != sell.input_verifier_set_id
        || buy.input_token != sell.output_token
        || buy.output_token != sell.input_token
        || buy.registry != sell.registry
        || buy.market_profile != sell.market_profile
        || buy.factory != sell.factory
        || buy.factory_runtime_codehash != sell.factory_runtime_codehash
        || buy.pool_manager != sell.pool_manager
        || buy.hook != sell.hook
        || buy.weth != sell.weth
        || buy.v3_factory != sell.v3_factory
        || buy.v3_factory_runtime_codehash != sell.v3_factory_runtime_codehash
        || buy.pool != sell.pool
        || buy.pool_runtime_codehash != sell.pool_runtime_codehash
        || buy.pair_token != sell.pair_token
        || buy.pool_fee != sell.pool_fee
        || buy.tick_spacing != sell.tick_spacing
        || buy.hook_fee_bps != sell.hook_fee_bps
        || buy.creator_tax_bps != sell.creator_tax_bps
        || buy.zero_for_one == sell.zero_for_one
        || buy.fee_collector != sell.fee_collector
        || buy.guardian != sell.guardian
        || buy.max_ttl_seconds != sell.max_ttl_seconds
        || buy.max_market_slippage_bps_cap != sell.max_market_slippage_bps_cap
        || buy.quoter != sell.quoter
        || buy.quoter_runtime_codehash != sell.quoter_runtime_codehash
    {
        return Err(anyhow!("privacy-swap buy/sell routes are not exact reverses"));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
pub struct SwapPlanJson {
    pub gross_input_units: String,
    pub input_unshield_fee_units: String,
    pub input_scale: String,
    pub gross_output_units: String,
    pub output_shield_fee_units: String,
    pub net_output_units: String,
    pub output_scale: String,
    pub quoted_input_wei: String,
    pub amount_in_maximum_wei: String,
    pub max_input_surplus_wei: String,
    pub max_market_slippage_bps: u16,
    pub valid_until: String,
    pub route_hash: String,
    pub salt: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct QuoteEvidenceJson {
    pub market: String,
    pub market_version: u8,
    pub chain_id: u64,
    pub route_id: String,
    pub block_number: u64,
    pub block_hash: String,
    pub quoter: String,
    pub quoter_runtime_codehash: String,
    pub factory: String,
    pub factory_runtime_codehash: String,
    pub launch_phase: u8,
    pub pool_fee: u32,
    pub hook_fee_bps: u16,
    pub creator_tax_bps: u16,
    pub want_output_wei: String,
    pub amount_in_wei: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapPlanV2 {
    pub gross_input_units: u64,
    pub input_unshield_fee_units: u64,
    pub input_scale: Uint,
    pub gross_output_units: u64,
    pub output_shield_fee_units: u64,
    pub net_output_units: u64,
    pub output_scale: Uint,
    pub quoted_input_wei: Uint,
    pub amount_in_maximum_wei: Uint,
    pub max_input_surplus_wei: Uint,
    pub max_market_slippage_bps: u16,
    pub valid_until: u64,
    pub route_hash: [u8; 32],
    pub salt: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ValidatedPlan {
    pub plan: SwapPlanV2,
    pub want_output_wei: Uint,
}

fn parse_u64_decimal(value: &str, field: &str) -> Result<u64> {
    if value.is_empty() || value.starts_with('+') || value.chars().any(|c| !c.is_ascii_digit()) {
        return Err(anyhow!("{field} must be an unsigned decimal string"));
    }
    value
        .parse::<u64>()
        .with_context(|| format!("{field} exceeds uint64"))
}

fn parse_u48_decimal(value: &str, field: &str) -> Result<u64> {
    let value = parse_u64_decimal(value, field)?;
    if value > U48_MAX {
        return Err(anyhow!("{field} exceeds uint48"));
    }
    Ok(value)
}

fn parse_uint_decimal(value: &str, field: &str) -> Result<Uint> {
    if value.is_empty() || value.starts_with('+') || value.chars().any(|c| !c.is_ascii_digit()) {
        return Err(anyhow!("{field} must be an unsigned decimal string"));
    }
    Uint::from_dec_str(value).with_context(|| format!("{field} exceeds uint256"))
}

pub fn parse_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let decoded = hex::decode(raw).with_context(|| format!("{field} must be hex"))?;
    if decoded.len() != N {
        return Err(anyhow!("{field} must be {N} bytes"));
    }
    Ok(decoded.try_into().expect("length checked"))
}

fn address(value: &str, field: &str) -> Result<Address> {
    Ok(Address::from(parse_fixed_hex::<20>(value, field)?))
}

fn selector(signature: &[u8]) -> [u8; 4] {
    Keccak256::digest(signature)[..4]
        .try_into()
        .expect("selector")
}

fn with_selector(signature: &[u8], tokens: &[Token]) -> Vec<u8> {
    let mut calldata = Vec::new();
    calldata.extend_from_slice(&selector(signature));
    calldata.extend_from_slice(&encode(tokens));
    calldata
}

impl TryFrom<SwapPlanJson> for SwapPlanV2 {
    type Error = anyhow::Error;

    fn try_from(value: SwapPlanJson) -> Result<Self> {
        Ok(Self {
            gross_input_units: parse_u64_decimal(&value.gross_input_units, "gross_input_units")?,
            input_unshield_fee_units: parse_u48_decimal(
                &value.input_unshield_fee_units,
                "input_unshield_fee_units",
            )?,
            input_scale: parse_uint_decimal(&value.input_scale, "input_scale")?,
            gross_output_units: parse_u64_decimal(&value.gross_output_units, "gross_output_units")?,
            output_shield_fee_units: parse_u48_decimal(
                &value.output_shield_fee_units,
                "output_shield_fee_units",
            )?,
            net_output_units: parse_u64_decimal(&value.net_output_units, "net_output_units")?,
            output_scale: parse_uint_decimal(&value.output_scale, "output_scale")?,
            quoted_input_wei: parse_uint_decimal(&value.quoted_input_wei, "quoted_input_wei")?,
            amount_in_maximum_wei: parse_uint_decimal(
                &value.amount_in_maximum_wei,
                "amount_in_maximum_wei",
            )?,
            max_input_surplus_wei: parse_uint_decimal(
                &value.max_input_surplus_wei,
                "max_input_surplus_wei",
            )?,
            max_market_slippage_bps: value.max_market_slippage_bps,
            valid_until: parse_u64_decimal(&value.valid_until, "valid_until")?,
            route_hash: parse_fixed_hex(&value.route_hash, "route_hash")?,
            salt: parse_fixed_hex(&value.salt, "salt")?,
        })
    }
}

pub fn parse_route_data(value: &str) -> Result<Vec<u8>> {
    let route = hex::decode(
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value),
    )
    .context("route_data must be hex")?;
    if !matches!(route.len(), PONS_V1_ROUTE_DATA_LEN | PONS_V2_ROUTE_DATA_LEN) {
        return Err(anyhow!(
            "route_data must be a canonical Pons v1 ({PONS_V1_ROUTE_DATA_LEN} byte) or v2 ({PONS_V2_ROUTE_DATA_LEN} byte) route"
        ));
    }
    Ok(route)
}

pub fn route_hash(route: &[u8]) -> [u8; 32] {
    Keccak256::digest(route).into()
}

fn plan_token(plan: &SwapPlanV2) -> Token {
    Token::Tuple(vec![
        Token::Uint(Uint::from(plan.gross_input_units)),
        Token::Uint(Uint::from(plan.input_unshield_fee_units)),
        Token::Uint(plan.input_scale),
        Token::Uint(Uint::from(plan.gross_output_units)),
        Token::Uint(Uint::from(plan.output_shield_fee_units)),
        Token::Uint(Uint::from(plan.net_output_units)),
        Token::Uint(plan.output_scale),
        Token::Uint(plan.quoted_input_wei),
        Token::Uint(plan.amount_in_maximum_wei),
        Token::Uint(plan.max_input_surplus_wei),
        Token::Uint(Uint::from(plan.max_market_slippage_bps)),
        Token::Uint(Uint::from(plan.valid_until)),
        Token::FixedBytes(plan.route_hash.to_vec()),
        Token::FixedBytes(plan.salt.to_vec()),
    ])
}

pub fn validate_plan(
    json: SwapPlanJson,
    config: &PrivacySwapConfig,
    now_seconds: u64,
) -> Result<ValidatedPlan> {
    validate_plan_value(SwapPlanV2::try_from(json)?, config, now_seconds)
}

pub fn validate_plan_value(
    plan: SwapPlanV2,
    config: &PrivacySwapConfig,
    now_seconds: u64,
) -> Result<ValidatedPlan> {
    if plan.valid_until < now_seconds {
        return Err(anyhow!("privacy-swap plan expired at {}", plan.valid_until));
    }
    if plan.valid_until
        > now_seconds
            .checked_add(config.max_ttl_seconds)
            .ok_or_else(|| anyhow!("privacy-swap maximum deadline overflow"))?
    {
        return Err(anyhow!("privacy-swap plan exceeds configured MAX_TTL"));
    }
    if plan.valid_until
        < now_seconds
            .checked_add(config.min_broadcast_window_seconds)
            .ok_or_else(|| anyhow!("privacy-swap broadcast deadline overflow"))?
    {
        return Err(anyhow!(
            "privacy-swap plan has less than the minimum broadcast window"
        ));
    }
    if plan.route_hash != config.route_hash {
        return Err(anyhow!(
            "privacy-swap route hash differs from configured route"
        ));
    }
    if plan.input_scale != config.input_scale || plan.output_scale != config.output_scale {
        return Err(anyhow!("privacy-swap pool scale snapshot mismatch"));
    }
    if plan.input_unshield_fee_units != config.input_unshield_fee_units
        || plan.output_shield_fee_units != config.output_shield_fee_units
    {
        return Err(anyhow!("privacy-swap pool fee snapshot mismatch"));
    }
    if plan.gross_input_units <= plan.input_unshield_fee_units
        || plan.gross_output_units <= plan.output_shield_fee_units
    {
        return Err(anyhow!(
            "privacy-swap gross amount must exceed its pool fee"
        ));
    }
    if plan.net_output_units != plan.gross_output_units - plan.output_shield_fee_units {
        return Err(anyhow!("privacy-swap output gross/net formula mismatch"));
    }
    let input_received = Uint::from(plan.gross_input_units - plan.input_unshield_fee_units)
        .checked_mul(plan.input_scale)
        .ok_or_else(|| anyhow!("privacy-swap input amount exceeds uint256"))?;
    let fixed_fee = Uint::from(config.swap_fee_units)
        .checked_mul(plan.input_scale)
        .ok_or_else(|| anyhow!("privacy-swap fixed fee exceeds uint256"))?;
    let expected_maximum = input_received
        .checked_sub(fixed_fee)
        .ok_or_else(|| anyhow!("privacy-swap input does not cover fixed fee"))?;
    if expected_maximum.is_zero() || plan.amount_in_maximum_wei != expected_maximum {
        return Err(anyhow!("amount_in_maximum_wei violates exact-debit budget"));
    }
    if plan.quoted_input_wei.is_zero() || plan.quoted_input_wei > plan.amount_in_maximum_wei {
        return Err(anyhow!("quoted_input_wei is outside the market budget"));
    }
    if plan.max_market_slippage_bps > config.max_market_slippage_bps_cap {
        return Err(anyhow!("privacy-swap slippage exceeds Coordinator cap"));
    }
    let delta = plan.amount_in_maximum_wei - plan.quoted_input_wei;
    let maximum_delta = plan
        .quoted_input_wei
        .checked_mul(Uint::from(plan.max_market_slippage_bps))
        .ok_or_else(|| anyhow!("privacy-swap slippage multiplication overflow"))?
        / Uint::from(BPS_DENOMINATOR);
    if delta > maximum_delta {
        return Err(anyhow!(
            "privacy-swap budget exceeds reference quote slippage"
        ));
    }
    if plan.max_input_surplus_wei >= plan.amount_in_maximum_wei {
        return Err(anyhow!(
            "privacy-swap surplus limit is outside market budget"
        ));
    }
    let want_output_wei = Uint::from(plan.gross_output_units)
        .checked_mul(plan.output_scale)
        .ok_or_else(|| anyhow!("privacy-swap output amount exceeds uint256"))?;
    if want_output_wei >= (Uint::one() << 127) {
        return Err(anyhow!(
            "privacy-swap exact output exceeds the admitted adapter signed amount domain"
        ));
    }
    Ok(ValidatedPlan {
        plan,
        want_output_wei,
    })
}

pub fn validate_quote_evidence(
    evidence: &QuoteEvidenceJson,
    config: &PrivacySwapConfig,
    validated: &ValidatedPlan,
) -> Result<()> {
    let expected_version = if config.market == PONS_V1_MARKET { 1 } else { 2 };
    let expected_phase = if config.market == PONS_V1_MARKET { 0 } else { 2 };
    if evidence.block_number == 0
        || evidence.chain_id != ROBINHOOD_CHAIN_ID
        || evidence.market != config.market
        || evidence.market_version != expected_version
        || parse_fixed_hex::<32>(&evidence.route_id, "quote route_id")? != config.route_id
        || evidence.launch_phase != expected_phase
        || evidence.pool_fee != config.pool_fee
        || evidence.hook_fee_bps != config.hook_fee_bps
        || evidence.creator_tax_bps != config.creator_tax_bps
        || !evidence.quoter.eq_ignore_ascii_case(&config.quoter)
        || parse_fixed_hex::<32>(&evidence.quoter_runtime_codehash, "quote quoter codehash")?
            != config.quoter_runtime_codehash
        || !evidence.factory.eq_ignore_ascii_case(&config.factory)
        || parse_fixed_hex::<32>(&evidence.factory_runtime_codehash, "quote factory codehash")?
            != config.factory_runtime_codehash
        || parse_uint_decimal(&evidence.want_output_wei, "quote want_output_wei")?
            != validated.want_output_wei
        || parse_uint_decimal(&evidence.amount_in_wei, "quote amount_in_wei")?
            != validated.plan.quoted_input_wei
    {
        return Err(anyhow!(
            "privacy-swap quote evidence differs from the admitted plan/route"
        ));
    }
    parse_fixed_hex::<32>(&evidence.block_hash, "quote block_hash")?;
    Ok(())
}

pub fn validate_current_quote(validated: &ValidatedPlan, current_quote: Uint) -> Result<()> {
    let plan = &validated.plan;
    if current_quote.is_zero() || current_quote > plan.amount_in_maximum_wei {
        return Err(anyhow!(
            "current market exact-output quote exceeds maximum input"
        ));
    }
    if current_quote > plan.quoted_input_wei {
        let maximum_increase = plan
            .quoted_input_wei
            .checked_mul(Uint::from(plan.max_market_slippage_bps))
            .ok_or_else(|| anyhow!("current quote slippage multiplication overflow"))?
            / Uint::from(BPS_DENOMINATOR);
        if current_quote - plan.quoted_input_wei > maximum_increase {
            return Err(anyhow!("current market quote exceeds wallet slippage"));
        }
    }
    if plan.amount_in_maximum_wei - current_quote > plan.max_input_surplus_wei {
        return Err(anyhow!("current market quote would exceed the surplus cap"));
    }
    Ok(())
}

pub fn swap_selector() -> [u8; 4] {
    selector(SWAP_SIG)
}

pub fn encode_swap_calldata(
    plan: &SwapPlanV2,
    route_data: &[u8],
    unshield_call: &PrivacyCallArgs,
    shield_call: &PrivacyCallArgs,
) -> Vec<u8> {
    with_selector(
        SWAP_SIG,
        &[
            plan_token(plan),
            Token::Bytes(route_data.to_vec()),
            privacy_call_token(unshield_call),
            privacy_call_token(shield_call),
        ],
    )
}

pub fn encode_swap_context_calldata(plan: &SwapPlanV2, shield_call: &PrivacyCallArgs) -> Vec<u8> {
    with_selector(
        SWAP_CONTEXT_SIG,
        &[plan_token(plan), privacy_call_token(shield_call)],
    )
}

pub fn compute_context(
    chain_id: u64,
    config: &PrivacySwapConfig,
    plan: &SwapPlanV2,
    shield_call: &PrivacyCallArgs,
) -> Result<[u8; 32]> {
    let domain: [u8; 32] = Keccak256::digest(b"PERC20.PrivacySwap.exact-debit.v2").into();
    let encoded = encode(&[
        Token::FixedBytes(domain.to_vec()),
        Token::Uint(Uint::from(chain_id)),
        Token::Address(address(&config.coordinator, "coordinator")?),
        Token::Uint(Uint::from(PROTOCOL_VERSION)),
        Token::Uint(Uint::from(APPLICATION_VERSION)),
        Token::Address(address(&config.registry, "registry")?),
        Token::Address(address(&config.input_pool, "input_pool")?),
        Token::Address(address(&config.output_pool, "output_pool")?),
        Token::FixedBytes(config.input_verifier_set_id.to_vec()),
        Token::FixedBytes(config.output_verifier_set_id.to_vec()),
        Token::Address(address(&config.input_token, "input_token")?),
        Token::Address(address(&config.output_token, "output_token")?),
        Token::Address(address(&config.adapter, "adapter")?),
        Token::FixedBytes(config.adapter_runtime_codehash.to_vec()),
        Token::FixedBytes(config.market_profile.to_vec()),
        Token::FixedBytes(config.route_id.to_vec()),
        Token::Address(address(&config.fee_collector, "fee_collector")?),
        Token::Uint(Uint::from(config.swap_fee_units)),
        Token::Uint(Uint::from(config.max_ttl_seconds)),
        Token::Uint(Uint::from(config.max_market_slippage_bps_cap)),
        plan_token(plan),
        Token::FixedBytes(privacy_call_commit(shield_call).to_vec()),
    ]);
    Ok(Keccak256::digest(encoded).into())
}

pub fn encode_v4_quote_calldata(config: &PrivacySwapConfig, amount_out: Uint) -> Result<Vec<u8>> {
    if amount_out.is_zero() || amount_out >= (Uint::one() << 128) {
        return Err(anyhow!("V4 exact output is outside uint128"));
    }
    let pair = address(&config.pair_token, "pair_token")?;
    let meme = address(&config.meme_token, "meme_token")?;
    let (currency0, currency1) = if pair < meme {
        (pair, meme)
    } else {
        (meme, pair)
    };
    let pool_key = Token::Tuple(vec![
        Token::Address(currency0),
        Token::Address(currency1),
        Token::Uint(Uint::from(config.pool_fee)),
        Token::Int(int_to_uint(config.tick_spacing as i64)),
        Token::Address(address(&config.hook, "hook")?),
    ]);
    Ok(with_selector(
        V4_QUOTE_SIG,
        &[Token::Tuple(vec![
            pool_key,
            Token::Bool(config.zero_for_one),
            Token::Uint(amount_out),
            Token::Bytes(Vec::new()),
        ])],
    ))
}

pub fn v3_exact_output_path(config: &PrivacySwapConfig) -> Result<Vec<u8>> {
    let mut path = Vec::with_capacity(43);
    path.extend_from_slice(address(&config.output_token, "output_token")?.as_bytes());
    path.extend_from_slice(&config.pool_fee.to_be_bytes()[1..]);
    path.extend_from_slice(address(&config.input_token, "input_token")?.as_bytes());
    Ok(path)
}

pub fn encode_v3_quote_calldata(config: &PrivacySwapConfig, amount_out: Uint) -> Result<Vec<u8>> {
    if amount_out.is_zero() {
        return Err(anyhow!("V3 exact output must be positive"));
    }
    Ok(with_selector(
        V3_QUOTE_SIG,
        &[Token::Bytes(v3_exact_output_path(config)?), Token::Uint(amount_out)],
    ))
}

pub fn encode_v3_get_pool_calldata(config: &PrivacySwapConfig) -> Result<Vec<u8>> {
    Ok(with_selector(
        GET_POOL_SIG,
        &[
            Token::Address(address(&config.meme_token, "meme_token")?),
            Token::Address(address(&config.pair_token, "pair_token")?),
            Token::Uint(Uint::from(config.pool_fee)),
        ],
    ))
}

pub fn pons_v2_pool_id(config: &PrivacySwapConfig) -> Result<[u8; 32]> {
    let pair = address(&config.pair_token, "pair_token")?;
    let meme = address(&config.meme_token, "meme_token")?;
    let (currency0, currency1) = if pair < meme { (pair, meme) } else { (meme, pair) };
    Ok(Keccak256::digest(encode(&[
        Token::Address(currency0),
        Token::Address(currency1),
        Token::Uint(Uint::from(config.pool_fee)),
        Token::Int(int_to_uint(config.tick_spacing as i64)),
        Token::Address(address(&config.hook, "hook")?),
    ]))
    .into())
}

pub fn encode_hook_launch_calldata(config: &PrivacySwapConfig) -> Result<Vec<u8>> {
    Ok(with_selector(
        HOOK_LAUNCH_SIG,
        &[Token::FixedBytes(pons_v2_pool_id(config)?.to_vec())],
    ))
}

fn int_to_uint(value: i64) -> Uint {
    if value >= 0 {
        Uint::from(value as u64)
    } else {
        Uint::MAX - Uint::from(value.unsigned_abs() - 1)
    }
}

pub fn encode_get_launch_calldata(meme_token: &str) -> Result<Vec<u8>> {
    Ok(with_selector(
        GET_LAUNCHED_TOKEN_SIG,
        &[Token::Address(address(meme_token, "meme_token")?)],
    ))
}

pub fn encode_v1_graduation_status_calldata(meme_token: &str) -> Result<Vec<u8>> {
    Ok(with_selector(
        GRADUATION_STATUS_SIG,
        &[Token::Address(address(meme_token, "meme_token")?)],
    ))
}

pub fn validate_launch_result(value: &str, config: &PrivacySwapConfig) -> Result<()> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("Pons launch record must be ABI hex")?;
    if raw.len() < 15 * 32 {
        return Err(anyhow!("Pons launch record is incomplete"));
    }
    let word = |index: usize| -> &[u8] { &raw[index * 32..(index + 1) * 32] };
    if word(0)[12..] != parse_fixed_hex::<20>(&config.meme_token, "meme_token")?
        || word(4)[12..] != parse_fixed_hex::<20>(&config.pair_token, "pair_token")?
        || Uint::from_big_endian(word(6)) != Uint::from(config.pool_fee)
        || Uint::from_big_endian(word(7)) != int_to_uint(config.tick_spacing as i64)
        || Uint::from_big_endian(word(8)) != Uint::from(config.creator_tax_bps)
        || Uint::from_big_endian(word(10)) != Uint::from(2)
        || Uint::from_big_endian(word(14)) != Uint::from(1)
    {
        return Err(anyhow!(
            "Pons launch is not the admitted PoolCreated market"
        ));
    }
    Ok(())
}

pub fn validate_v1_launch_result(value: &str, config: &PrivacySwapConfig) -> Result<()> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("Pons v1 launch record must be ABI hex")?;
    if raw.len() < 13 * 32 {
        return Err(anyhow!("Pons v1 launch record is incomplete"));
    }
    let word = |index: usize| -> &[u8] { &raw[index * 32..(index + 1) * 32] };
    if word(0)[12..] != parse_fixed_hex::<20>(&config.meme_token, "meme_token")?
        || word(2)[12..] != parse_fixed_hex::<20>(&config.pair_token, "pair_token")?
        || Uint::from_big_endian(word(10)) != Uint::from(config.pool_fee)
        || Uint::from_big_endian(word(11)) != Uint::from(1)
    {
        return Err(anyhow!("Pons v1 launch is not the admitted V3 market"));
    }
    Ok(())
}

pub fn validate_v1_graduation_result(value: &str) -> Result<()> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("Pons v1 graduation status must be ABI hex")?;
    if raw.len() < 3 * 32 || Uint::from_big_endian(&raw[2 * 32..3 * 32]) != Uint::one() {
        return Err(anyhow!("Pons v1 token has not reached its factory graduation threshold"));
    }
    Ok(())
}

pub fn validate_v3_pool_result(value: &str, config: &PrivacySwapConfig) -> Result<()> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("V3 getPool result must be ABI hex")?;
    if raw.len() < 32 || raw[..12] != [0u8; 12]
        || raw[12..32] != parse_fixed_hex::<20>(&config.pool, "pool")?
    {
        return Err(anyhow!("V3 factory getPool differs from the admitted pool"));
    }
    Ok(())
}

pub fn validate_hook_fee_result(value: &str, config: &PrivacySwapConfig) -> Result<()> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("Pons v2 hook launch record must be ABI hex")?;
    if raw.len() < 13 * 32 {
        return Err(anyhow!("Pons v2 hook launch record is incomplete"));
    }
    let word = |index: usize| -> &[u8] { &raw[index * 32..(index + 1) * 32] };
    let pair = address(&config.pair_token, "pair_token")?;
    let meme = address(&config.meme_token, "meme_token")?;
    let meme_is_currency0 = meme < pair;
    if Uint::from_big_endian(word(0)) != Uint::from(1)
        || Uint::from_big_endian(word(1)) != Uint::from(u8::from(meme_is_currency0))
        || word(2)[12..] != parse_fixed_hex::<20>(&config.meme_token, "meme_token")?
        || word(3)[12..] != parse_fixed_hex::<20>(&config.pair_token, "pair_token")?
        || Uint::from_big_endian(word(7)) != Uint::from(config.creator_tax_bps)
        || Uint::from_big_endian(word(10)) != Uint::from(config.hook_fee_bps)
    {
        return Err(anyhow!("Pons v2 hook fee policy differs from the admitted route"));
    }
    Ok(())
}

fn word_at(calldata: &[u8], index: usize) -> Result<Uint> {
    let start = 4 + index * 32;
    let word = calldata
        .get(start..start + 32)
        .ok_or_else(|| anyhow!("privacy-swap calldata is shorter than the plan head"))?;
    Ok(Uint::from_big_endian(word))
}

fn word_u64(calldata: &[u8], index: usize, field: &str, maximum: u64) -> Result<u64> {
    let value = word_at(calldata, index)?;
    if value > Uint::from(maximum) {
        return Err(anyhow!("{field} exceeds its ABI width"));
    }
    Ok(value.as_u64())
}

fn word_bytes32(calldata: &[u8], index: usize) -> Result<[u8; 32]> {
    let start = 4 + index * 32;
    Ok(calldata[start..start + 32]
        .try_into()
        .expect("bounds checked"))
}

pub fn decode_swap_plan_calldata(calldata: &[u8]) -> Result<SwapPlanV2> {
    if calldata.get(..4) != Some(swap_selector().as_slice()) {
        return Err(anyhow!(
            "persisted transaction is not PrivacySwapCoordinatorV2.swap"
        ));
    }
    let _ = word_at(calldata, 13)?;
    Ok(SwapPlanV2 {
        gross_input_units: word_u64(calldata, 0, "gross_input_units", u64::MAX)?,
        input_unshield_fee_units: word_u64(calldata, 1, "input_unshield_fee_units", U48_MAX)?,
        input_scale: word_at(calldata, 2)?,
        gross_output_units: word_u64(calldata, 3, "gross_output_units", u64::MAX)?,
        output_shield_fee_units: word_u64(calldata, 4, "output_shield_fee_units", U48_MAX)?,
        net_output_units: word_u64(calldata, 5, "net_output_units", u64::MAX)?,
        output_scale: word_at(calldata, 6)?,
        quoted_input_wei: word_at(calldata, 7)?,
        amount_in_maximum_wei: word_at(calldata, 8)?,
        max_input_surplus_wei: word_at(calldata, 9)?,
        max_market_slippage_bps: word_u64(calldata, 10, "max_market_slippage_bps", u16::MAX as u64)?
            as u16,
        valid_until: word_u64(calldata, 11, "valid_until", u64::MAX)?,
        route_hash: word_bytes32(calldata, 12)?,
        salt: word_bytes32(calldata, 13)?,
    })
}

pub fn parse_first_abi_uint(value: &str, field: &str) -> Result<Uint> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() < 64 {
        return Err(anyhow!("{field} returned fewer than 32 bytes"));
    }
    Ok(Uint::from_big_endian(
        &hex::decode(&raw[..64]).with_context(|| format!("{field} returned invalid hex"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BULL: &str = "0x49bac47750f3dcdba49350b5d74fd399e90f97c6";
    const BULL_FACTORY: &str = "0x7ed598bcef8bd9edd8c97a195c6d13f40801ec7e";
    const BULL_HOOK: &str = "0xe5e702641ea86f4ae6cc3cdaed2b886f976be044";
    const ROBINHOOD_WETH: &str = "0x0bd7d308f8e1639fab988df18a8011f41eacad73";

    fn bull_buy_route() -> Vec<u8> {
        encode(&[
            Token::FixedBytes(PONS_V2_MARKET_PROFILE_HASH.to_vec()),
            Token::Address(address(BULL_FACTORY, "factory").unwrap()),
            Token::Address(address(ROBINHOOD_V4_POOL_MANAGER, "pool_manager").unwrap()),
            Token::Address(address(BULL_HOOK, "hook").unwrap()),
            Token::Address(address(BULL, "meme_token").unwrap()),
            Token::Address(Address::zero()),
            Token::Address(address(ROBINHOOD_WETH, "input_token").unwrap()),
            Token::Address(address(BULL, "output_token").unwrap()),
            Token::Address(Address::zero()),
            Token::Address(address(BULL, "currency1").unwrap()),
            Token::Uint(Uint::zero()),
            Token::Int(Uint::from(200u64)),
            Token::Bool(true),
            Token::Uint(Uint::from(100u64)),
            Token::Uint(Uint::zero()),
        ])
    }

    fn config() -> PrivacySwapConfig {
        let route = bull_buy_route();
        PrivacySwapConfig {
            accepting: true,
            market: PONS_V2_MARKET.into(),
            route_id: [0x11; 32],
            direction: "buy".into(),
            asset_symbol: "BULL".into(),
            asset_name: "The Bull".into(),
            coordinator: format!("0x{}", "11".repeat(20)),
            registry: format!("0x{}", "22".repeat(20)),
            input_pool: format!("0x{}", "33".repeat(20)),
            output_pool: format!("0x{}", "44".repeat(20)),
            input_verifier_set_id: [0x55; 32],
            output_verifier_set_id: [0x66; 32],
            input_token: ROBINHOOD_WETH.into(),
            output_token: BULL.into(),
            input_scale: Uint::one(),
            output_scale: Uint::from(10_000_000_000u64),
            input_unshield_fee_units: 10,
            output_shield_fee_units: 2,
            adapter: format!("0x{}", "99".repeat(20)),
            adapter_runtime_codehash: [0xaa; 32],
            market_profile: PONS_V2_MARKET_PROFILE_HASH,
            fee_collector: format!("0x{}", "bb".repeat(20)),
            swap_fee_units: 5,
            max_ttl_seconds: 900,
            max_market_slippage_bps_cap: 500,
            route_hash: route_hash(&route),
            route_data: route,
            quoter: ROBINHOOD_V4_QUOTER.into(),
            quoter_runtime_codehash: parse_fixed_hex(
                "d707b1da8cb165e5ea35a3b4450d971eb562ec171e23492aa117036b78a868f6",
                "quoter_runtime_codehash",
            )
            .unwrap(),
            factory: BULL_FACTORY.into(),
            factory_runtime_codehash: parse_fixed_hex(
                "89a27da6f703e0a7cdd4f233e7cb57604ff75b164530962d3ff7cf8483a67d84",
                "factory_runtime_codehash",
            )
            .unwrap(),
            pool_manager: ROBINHOOD_V4_POOL_MANAGER.into(),
            hook: BULL_HOOK.into(),
            weth: ROBINHOOD_WETH.into(),
            v3_factory: format!("0x{}", "00".repeat(20)),
            v3_factory_runtime_codehash: [0u8; 32],
            pool: format!("0x{}", "00".repeat(20)),
            pool_runtime_codehash: [0u8; 32],
            meme_token: BULL.into(),
            pair_token: format!("0x{}", "00".repeat(20)),
            pool_fee: 0,
            tick_spacing: 200,
            zero_for_one: true,
            hook_fee_bps: 100,
            creator_tax_bps: 0,
            guardian: format!("0x{}", "ff".repeat(20)),
            gas_limit: 12_000_000,
            min_broadcast_window_seconds: 30,
            event_getlogs_max_span: 101,
        }
    }

    fn reverse_config(buy: &PrivacySwapConfig) -> PrivacySwapConfig {
        let mut sell = buy.clone();
        sell.direction = "sell".into();
        std::mem::swap(&mut sell.input_pool, &mut sell.output_pool);
        std::mem::swap(&mut sell.input_token, &mut sell.output_token);
        std::mem::swap(&mut sell.input_scale, &mut sell.output_scale);
        std::mem::swap(&mut sell.input_verifier_set_id, &mut sell.output_verifier_set_id);
        sell.zero_for_one = !buy.zero_for_one;
        sell.swap_fee_units = 17_000;
        sell
    }

    #[test]
    fn reverse_pair_allows_independently_denominated_fees() {
        let buy = config();
        let sell = reverse_config(&buy);
        assert_ne!(buy.swap_fee_units, sell.swap_fee_units);
        validate_reverse_pair(&buy, &sell).unwrap();
        let mut same_numeric_fee = sell;
        same_numeric_fee.swap_fee_units = buy.swap_fee_units;
        validate_reverse_pair(&buy, &same_numeric_fee).unwrap();
    }

    #[test]
    fn reverse_pair_preserves_market_scale_fee_recipient_and_safety_pins() {
        let buy = config();
        let original = reverse_config(&buy);
        let mut sell = original.clone();
        sell.fee_collector = sell.guardian.clone();
        assert!(validate_reverse_pair(&buy, &sell).is_err());
        sell = original.clone();
        sell.creator_tax_bps += 1;
        assert!(validate_reverse_pair(&buy, &sell).is_err());
        sell = original.clone();
        sell.input_scale += Uint::one();
        assert!(validate_reverse_pair(&buy, &sell).is_err());
        sell = original.clone();
        sell.max_ttl_seconds += 1;
        assert!(validate_reverse_pair(&buy, &sell).is_err());
        sell = original;
        sell.direction = "buy".into();
        assert!(validate_reverse_pair(&buy, &sell).is_err());
    }

    fn plan_json() -> SwapPlanJson {
        SwapPlanJson {
            gross_input_units: "1000".into(),
            input_unshield_fee_units: "10".into(),
            input_scale: "1".into(),
            gross_output_units: "100".into(),
            output_shield_fee_units: "2".into(),
            net_output_units: "98".into(),
            output_scale: "10000000000".into(),
            quoted_input_wei: "980".into(),
            amount_in_maximum_wei: "985".into(),
            max_input_surplus_wei: "10".into(),
            max_market_slippage_bps: 100,
            valid_until: "1700000120".into(),
            route_hash: format!("0x{}", hex::encode(config().route_hash)),
            salt: format!("0x{}", "ff".repeat(32)),
        }
    }

    fn empty_call() -> PrivacyCallArgs {
        PrivacyCallArgs {
            actions: Vec::new(),
            binding_proof: [[0u8; 32]; 8],
        }
    }

    #[test]
    fn plan_context_and_calldata_are_stable() {
        let cfg = config();
        let validated = validate_plan(plan_json(), &cfg, 1_700_000_000).unwrap();
        validate_current_quote(&validated, Uint::from(980)).unwrap();
        assert_eq!(validated.want_output_wei, Uint::from(1_000_000_000_000u64));
        let calldata = encode_swap_calldata(
            &validated.plan,
            &cfg.route_data,
            &empty_call(),
            &empty_call(),
        );
        assert_eq!(&calldata[..4], &swap_selector());
        assert_eq!(
            decode_swap_plan_calldata(&calldata).unwrap(),
            validated.plan
        );
        assert_eq!(
            hex::encode(compute_context(4_663, &cfg, &validated.plan, &empty_call()).unwrap()),
            "44cff9b3c5fef1beee8bc5b12443e1e8caca24b0c6d44ce700e8c79ec6042f38"
        );
    }

    #[test]
    fn v4_quote_and_launch_calls_use_the_reviewed_abis() {
        let cfg = config();
        let quote = encode_v4_quote_calldata(&cfg, Uint::from(1_000)).unwrap();
        assert_eq!(&quote[..4], &[0x58, 0x73, 0x30, 0x73]);
        let launch = encode_get_launch_calldata(&cfg.meme_token).unwrap();
        assert_eq!(&launch[..4], &[0x3c, 0xf2, 0x8b, 0x5a]);
    }

    #[test]
    fn v1_quote_launch_and_pool_checks_use_the_single_v3_fee_tier() {
        let mut cfg = config();
        cfg.market = PONS_V1_MARKET.into();
        cfg.market_profile = PONS_V1_MARKET_PROFILE_HASH;
        cfg.input_token = ROBINHOOD_WETH.into();
        cfg.output_token = BULL.into();
        cfg.pair_token = ROBINHOOD_WETH.into();
        cfg.pool_fee = 3_000;
        cfg.hook_fee_bps = 0;
        cfg.creator_tax_bps = 0;
        cfg.v3_factory = format!("0x{}", "77".repeat(20));
        cfg.pool = format!("0x{}", "88".repeat(20));

        let quote = encode_v3_quote_calldata(&cfg, Uint::from(1_000)).unwrap();
        assert_eq!(&quote[..4], &selector(V3_QUOTE_SIG));
        assert_eq!(
            v3_exact_output_path(&cfg).unwrap(),
            [
                address(BULL, "meme").unwrap().as_bytes(),
                &[0x00, 0x0b, 0xb8],
                address(ROBINHOOD_WETH, "pair").unwrap().as_bytes(),
            ]
            .concat()
        );

        let launch = encode(&[
            Token::Address(address(BULL, "meme").unwrap()),
            Token::Address(Address::repeat_byte(1)),
            Token::Address(address(ROBINHOOD_WETH, "pair").unwrap()),
            Token::Address(Address::repeat_byte(2)),
            Token::Uint(Uint::one()),
            Token::Uint(Uint::zero()),
            Token::Uint(Uint::zero()),
            Token::Uint(Uint::from(10)),
            Token::Uint(Uint::from(1_000_000)),
            Token::Bool(false),
            Token::Uint(Uint::from(3_000)),
            Token::Bool(true),
            Token::Uint(Uint::zero()),
        ]);
        validate_v1_launch_result(&format!("0x{}", hex::encode(launch)), &cfg).unwrap();
        let graduation = encode(&[
            Token::Uint(Uint::from(2)),
            Token::Uint(Uint::one()),
            Token::Bool(true),
        ]);
        validate_v1_graduation_result(&format!("0x{}", hex::encode(graduation))).unwrap();
        let graduation_call = encode_v1_graduation_status_calldata(BULL).unwrap();
        assert_eq!(&graduation_call[..4], &selector(GRADUATION_STATUS_SIG));
        let pool = encode(&[Token::Address(address(&cfg.pool, "pool").unwrap())]);
        validate_v3_pool_result(&format!("0x{}", hex::encode(pool)), &cfg).unwrap();
    }
}
