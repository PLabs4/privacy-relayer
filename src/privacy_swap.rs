use anyhow::{anyhow, Context, Result};
use ethabi::{encode, Address, Token, Uint};
use privacy_core::ethereum::{privacy_call_commit, PrivacyCallArgs};
use serde::Deserialize;
use sha3::{Digest, Keccak256};

use crate::fee_calldata::privacy_call_token;

pub const ROUTE_DATA_LEN: usize = 13 * 32;
pub const PROTOCOL_VERSION: u64 = 3;
pub const APPLICATION_VERSION: u64 = 2;
pub const ROBINHOOD_CHAIN_ID: u64 = 4_663;
pub const MARKET_PROFILE: &str = "pons-v2-graduated-v4";
pub const MARKET_PROFILE_HASH: [u8; 32] = [
    0xca, 0x70, 0x54, 0x99, 0x53, 0x57, 0xc0, 0x7f, 0xf4, 0x83, 0x2b, 0xab, 0x91, 0xaf, 0xfb, 0x75,
    0xb2, 0xaa, 0x41, 0x85, 0x21, 0x3b, 0x34, 0x48, 0x5c, 0x4e, 0x62, 0xdc, 0x0e, 0x74, 0xef, 0xc8,
];
pub const ROBINHOOD_V4_POOL_MANAGER: &str = "0x8366a39cc670b4001a1121b8f6a443a643e40951";
pub const ROBINHOOD_V4_QUOTER: &str = "0x8dc178efb8111bb0973dd9d722ebeff267c98f94";
const BPS_DENOMINATOR: u64 = 10_000;
const U48_MAX: u64 = (1u64 << 48) - 1;

const SWAP_SIG: &[u8] = b"swap((uint64,uint48,uint256,uint64,uint48,uint64,uint256,uint256,uint256,uint256,uint16,uint64,bytes32,bytes32),bytes,(bytes,uint256[8]),(bytes,uint256[8]))";
const SWAP_CONTEXT_SIG: &[u8] = b"swapContext((uint64,uint48,uint256,uint64,uint48,uint64,uint256,uint256,uint256,uint256,uint16,uint64,bytes32,bytes32),(bytes,uint256[8]))";
const V4_QUOTE_SIG: &[u8] =
    b"quoteExactOutputSingle(((address,address,uint24,int24,address),bool,uint128,bytes))";
const GET_LAUNCHED_TOKEN_SIG: &[u8] = b"getLaunchedToken(address)";

#[derive(Clone, Debug)]
pub struct PrivacySwapConfig {
    pub accepting: bool,
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
    pub meme_token: String,
    pub pair_token: String,
    pub pool_fee: u32,
    pub tick_spacing: i32,
    pub zero_for_one: bool,
    pub guardian: String,
    pub gas_limit: u64,
    pub min_broadcast_window_seconds: u64,
    pub event_getlogs_max_span: u64,
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
    pub chain_id: u64,
    pub route_id: String,
    pub block_number: u64,
    pub block_hash: String,
    pub quoter: String,
    pub quoter_runtime_codehash: String,
    pub factory: String,
    pub factory_runtime_codehash: String,
    pub launch_phase: u8,
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
    if route.len() != ROUTE_DATA_LEN {
        return Err(anyhow!("route_data must be {ROUTE_DATA_LEN} bytes"));
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
            "privacy-swap exact output exceeds V4 signed delta domain"
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
    if evidence.block_number == 0
        || evidence.chain_id != ROBINHOOD_CHAIN_ID
        || parse_fixed_hex::<32>(&evidence.route_id, "quote route_id")? != config.route_id
        || evidence.launch_phase != 2
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
            "current V4 exact-output quote exceeds maximum input"
        ));
    }
    if current_quote > plan.quoted_input_wei {
        let maximum_increase = plan
            .quoted_input_wei
            .checked_mul(Uint::from(plan.max_market_slippage_bps))
            .ok_or_else(|| anyhow!("current quote slippage multiplication overflow"))?
            / Uint::from(BPS_DENOMINATOR);
        if current_quote - plan.quoted_input_wei > maximum_increase {
            return Err(anyhow!("current V4 quote exceeds wallet slippage"));
        }
    }
    if plan.amount_in_maximum_wei - current_quote > plan.max_input_surplus_wei {
        return Err(anyhow!("current V4 quote would exceed the surplus cap"));
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
        || Uint::from_big_endian(word(10)) != Uint::from(2)
        || Uint::from_big_endian(word(14)) != Uint::from(1)
    {
        return Err(anyhow!(
            "Pons launch is not the admitted PoolCreated market"
        ));
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

    fn config() -> PrivacySwapConfig {
        let route = vec![0x11; ROUTE_DATA_LEN];
        PrivacySwapConfig {
            accepting: true,
            route_id: [0x11; 32],
            direction: "buy".into(),
            asset_symbol: "MEME".into(),
            asset_name: "Curated Meme".into(),
            coordinator: format!("0x{}", "11".repeat(20)),
            registry: format!("0x{}", "22".repeat(20)),
            input_pool: format!("0x{}", "33".repeat(20)),
            output_pool: format!("0x{}", "44".repeat(20)),
            input_verifier_set_id: [0x55; 32],
            output_verifier_set_id: [0x66; 32],
            input_token: format!("0x{}", "77".repeat(20)),
            output_token: format!("0x{}", "88".repeat(20)),
            input_scale: Uint::one(),
            output_scale: Uint::from(10_000_000_000u64),
            input_unshield_fee_units: 10,
            output_shield_fee_units: 2,
            adapter: format!("0x{}", "99".repeat(20)),
            adapter_runtime_codehash: [0xaa; 32],
            market_profile: MARKET_PROFILE_HASH,
            fee_collector: format!("0x{}", "bb".repeat(20)),
            swap_fee_units: 5,
            max_ttl_seconds: 900,
            max_market_slippage_bps_cap: 500,
            route_hash: route_hash(&route),
            route_data: route,
            quoter: ROBINHOOD_V4_QUOTER.into(),
            quoter_runtime_codehash: [0xdd; 32],
            factory: format!("0x{}", "cc".repeat(20)),
            factory_runtime_codehash: [0xee; 32],
            pool_manager: ROBINHOOD_V4_POOL_MANAGER.into(),
            hook: format!("0x{}", "dd".repeat(20)),
            weth: format!("0x{}", "ee".repeat(20)),
            meme_token: format!("0x{}", "88".repeat(20)),
            pair_token: format!("0x{}", "77".repeat(20)),
            pool_fee: 10_000,
            tick_spacing: 200,
            zero_for_one: true,
            guardian: format!("0x{}", "ff".repeat(20)),
            gas_limit: 12_000_000,
            min_broadcast_window_seconds: 30,
            event_getlogs_max_span: 101,
        }
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
            "9d1c994c65ad4571c4f04cf85601040fc9c143665dd5b7fefa162f4610ae6263"
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
}
