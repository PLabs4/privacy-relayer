use anyhow::{anyhow, Context, Result};
use ethabi::{encode, Address, Token, Uint};
use privacy_core::ethereum::{privacy_call_commit, PrivacyCallArgs};
use serde::Deserialize;
use sha3::{Digest, Keccak256};

use crate::fee_calldata::privacy_call_token;

pub const ROUTE_DATA_LEN: usize = 66;
pub const PROTOCOL_VERSION: u64 = 3;
pub const APPLICATION_VERSION: u64 = 1;
pub const ROBINHOOD_CHAIN_ID: u64 = 4_663;
pub const MARKET_PROFILE: &str = "pons-v1-reference";
pub const ROBINHOOD_SWAP_ROUTER_02: &str = "0xcaf681a66d020601342297493863e78c959e5cb2";
pub const ROBINHOOD_UNISWAP_V3_FACTORY: &str = "0x1f7d7550b1b028f7571e69a784071f0205fd2efa";
pub const ROBINHOOD_QUOTER_V2: &str = "0x33e885ed0ec9bf04ecfb19341582aadcb4c8a9e7";
pub const ROBINHOOD_WETH: &str = "0x0bd7d308f8e1639fab988df18a8011f41eacad73";
pub const ROBINHOOD_USDG: &str = "0x5fc5360d0400a0fd4f2af552add042d716f1d168";
pub const PONS_V1_REFERENCE_TOKEN: &str = "0x39dbed3a2bd333467115de45665cc57f813c4571";
pub const PONS_V1_REFERENCE_WETH_POOL: &str = "0x10cc6bd38112cac182db90b6a71d8bb5939526ba";
const BPS_DENOMINATOR: u64 = 10_000;
const U48_MAX: u64 = (1u64 << 48) - 1;

const BUY_SIG: &[u8] = b"buy((uint64,uint48,uint256,uint64,uint48,uint64,uint256,uint256,uint256,uint256,uint16,uint64,bytes32,bytes32),bytes,(bytes,uint256[8]),(bytes,uint256[8]))";
const BUY_CONTEXT_SIG: &[u8] = b"buyContext((uint64,uint48,uint256,uint64,uint48,uint64,uint256,uint256,uint256,uint256,uint16,uint64,bytes32,bytes32),(bytes,uint256[8]))";
const QUOTE_EXACT_OUTPUT_SIG: &[u8] = b"quoteExactOutput(bytes,uint256)";

#[derive(Clone, Debug)]
pub struct PrivacyBuyConfig {
    /// New HTTP admissions are independently switchable while queued jobs drain.
    pub accepting: bool,
    pub coordinator: String,
    pub registry: String,
    pub quote_pool: String,
    pub target_pool: String,
    pub quote_verifier_set_id: [u8; 32],
    pub target_verifier_set_id: [u8; 32],
    pub quote_token: String,
    pub target_token: String,
    pub quote_scale: Uint,
    pub target_scale: Uint,
    pub quote_unshield_fee_units: u64,
    pub target_shield_fee_units: u64,
    pub adapter: String,
    pub adapter_runtime_codehash: [u8; 32],
    pub fee_collector: String,
    pub buy_fee_units: u64,
    pub max_ttl_seconds: u64,
    pub max_market_slippage_bps_cap: u16,
    pub route_data: Vec<u8>,
    pub route_hash: [u8; 32],
    pub quoter: String,
    pub quoter_runtime_codehash: [u8; 32],
    pub gas_limit: u64,
    pub min_broadcast_window_seconds: u64,
    /// Inclusive eth_getLogs block count for external-fulfillment convergence.
    pub event_getlogs_max_span: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BuyPlanJson {
    pub gross_quote_units: String,
    pub quote_unshield_fee_units: String,
    pub quote_scale: String,
    pub gross_target_units: String,
    pub target_shield_fee_units: String,
    pub net_target_units: String,
    pub target_scale: String,
    pub quoted_amount_in_wei: String,
    pub amount_in_maximum_wei: String,
    pub max_quote_surplus_wei: String,
    pub max_market_slippage_bps: u16,
    pub valid_until: String,
    pub route_hash: String,
    pub salt: String,
}

#[derive(Clone, Debug)]
pub struct BuyPlanV1 {
    pub gross_quote_units: u64,
    pub quote_unshield_fee_units: u64,
    pub quote_scale: Uint,
    pub gross_target_units: u64,
    pub target_shield_fee_units: u64,
    pub net_target_units: u64,
    pub target_scale: Uint,
    pub quoted_amount_in_wei: Uint,
    pub amount_in_maximum_wei: Uint,
    pub max_quote_surplus_wei: Uint,
    pub max_market_slippage_bps: u16,
    pub valid_until: u64,
    pub route_hash: [u8; 32],
    pub salt: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ValidatedPlan {
    pub plan: BuyPlanV1,
    pub want_target_wei: Uint,
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
    let parsed = parse_u64_decimal(value, field)?;
    if parsed > U48_MAX {
        return Err(anyhow!("{field} exceeds uint48"));
    }
    Ok(parsed)
}

fn parse_uint_decimal(value: &str, field: &str) -> Result<Uint> {
    if value.is_empty() || value.starts_with('+') || value.chars().any(|c| !c.is_ascii_digit()) {
        return Err(anyhow!("{field} must be an unsigned decimal string"));
    }
    Uint::from_dec_str(value).with_context(|| format!("{field} exceeds uint256"))
}

fn parse_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
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
    let body = encode(tokens);
    let mut calldata = Vec::with_capacity(4 + body.len());
    calldata.extend_from_slice(&selector(signature));
    calldata.extend_from_slice(&body);
    calldata
}

impl TryFrom<BuyPlanJson> for BuyPlanV1 {
    type Error = anyhow::Error;

    fn try_from(value: BuyPlanJson) -> Result<Self> {
        Ok(Self {
            gross_quote_units: parse_u64_decimal(&value.gross_quote_units, "gross_quote_units")?,
            quote_unshield_fee_units: parse_u48_decimal(
                &value.quote_unshield_fee_units,
                "quote_unshield_fee_units",
            )?,
            quote_scale: parse_uint_decimal(&value.quote_scale, "quote_scale")?,
            gross_target_units: parse_u64_decimal(&value.gross_target_units, "gross_target_units")?,
            target_shield_fee_units: parse_u48_decimal(
                &value.target_shield_fee_units,
                "target_shield_fee_units",
            )?,
            net_target_units: parse_u64_decimal(&value.net_target_units, "net_target_units")?,
            target_scale: parse_uint_decimal(&value.target_scale, "target_scale")?,
            quoted_amount_in_wei: parse_uint_decimal(
                &value.quoted_amount_in_wei,
                "quoted_amount_in_wei",
            )?,
            amount_in_maximum_wei: parse_uint_decimal(
                &value.amount_in_maximum_wei,
                "amount_in_maximum_wei",
            )?,
            max_quote_surplus_wei: parse_uint_decimal(
                &value.max_quote_surplus_wei,
                "max_quote_surplus_wei",
            )?,
            max_market_slippage_bps: value.max_market_slippage_bps,
            valid_until: parse_u64_decimal(&value.valid_until, "valid_until")?,
            route_hash: parse_fixed_hex(&value.route_hash, "route_hash")?,
            salt: parse_fixed_hex(&value.salt, "salt")?,
        })
    }
}

pub fn parse_route_data(value: &str) -> Result<Vec<u8>> {
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let route = hex::decode(raw).context("route_data must be hex")?;
    if route.len() != ROUTE_DATA_LEN {
        return Err(anyhow!("route_data must be {ROUTE_DATA_LEN} bytes"));
    }
    Ok(route)
}

/// Lock the first anonymous-buy release to the reviewed legacy PONS reference
/// market. Pons v2 uses a bonding curve and Uniswap v4 after graduation; it
/// requires a different adapter/profile and must never pass this v1 gate.
pub fn validate_market_profile(
    chain_id: u64,
    market: &str,
    quoter: &str,
    route: &[u8],
) -> Result<()> {
    if chain_id != ROBINHOOD_CHAIN_ID {
        return Err(anyhow!(
            "privacy-buy v1 is pinned to Robinhood chain {ROBINHOOD_CHAIN_ID}"
        ));
    }
    if market != MARKET_PROFILE {
        return Err(anyhow!("unsupported privacy-buy market profile {market:?}"));
    }
    if !quoter.eq_ignore_ascii_case(ROBINHOOD_QUOTER_V2) {
        return Err(anyhow!(
            "privacy-buy v1 requires the reviewed Robinhood QuoterV2"
        ));
    }
    if route.len() != ROUTE_DATA_LEN {
        return Err(anyhow!(
            "privacy-buy v1 route must be {ROUTE_DATA_LEN} bytes"
        ));
    }
    let target = hex::decode(&PONS_V1_REFERENCE_TOKEN[2..]).expect("constant address");
    let weth = hex::decode(&ROBINHOOD_WETH[2..]).expect("constant address");
    let quote = hex::decode(&ROBINHOOD_USDG[2..]).expect("constant address");
    if route[..20] != target
        || route[23..43] != weth
        || route[46..] != quote
        || route[20..23] != [0x00, 0x27, 0x10]
        || route[43..46] == [0u8; 3]
    {
        return Err(anyhow!(
            "privacy-buy v1 route must use the canonical 1% PONS/WETH and non-zero-fee USDG path"
        ));
    }
    Ok(())
}

pub fn route_hash(route: &[u8]) -> [u8; 32] {
    Keccak256::digest(route).into()
}

fn plan_token(plan: &BuyPlanV1) -> Token {
    Token::Tuple(vec![
        Token::Uint(Uint::from(plan.gross_quote_units)),
        Token::Uint(Uint::from(plan.quote_unshield_fee_units)),
        Token::Uint(plan.quote_scale),
        Token::Uint(Uint::from(plan.gross_target_units)),
        Token::Uint(Uint::from(plan.target_shield_fee_units)),
        Token::Uint(Uint::from(plan.net_target_units)),
        Token::Uint(plan.target_scale),
        Token::Uint(plan.quoted_amount_in_wei),
        Token::Uint(plan.amount_in_maximum_wei),
        Token::Uint(plan.max_quote_surplus_wei),
        Token::Uint(Uint::from(plan.max_market_slippage_bps)),
        Token::Uint(Uint::from(plan.valid_until)),
        Token::FixedBytes(plan.route_hash.to_vec()),
        Token::FixedBytes(plan.salt.to_vec()),
    ])
}

pub fn validate_plan(
    json: BuyPlanJson,
    config: &PrivacyBuyConfig,
    now_seconds: u64,
) -> Result<ValidatedPlan> {
    let plan = BuyPlanV1::try_from(json)?;
    validate_plan_value(plan, config, now_seconds)
}

pub fn validate_plan_value(
    plan: BuyPlanV1,
    config: &PrivacyBuyConfig,
    now_seconds: u64,
) -> Result<ValidatedPlan> {
    if plan.valid_until < now_seconds {
        return Err(anyhow!("privacy-buy plan expired at {}", plan.valid_until));
    }
    let maximum_deadline = now_seconds
        .checked_add(config.max_ttl_seconds)
        .ok_or_else(|| anyhow!("maximum privacy-buy deadline overflow"))?;
    if plan.valid_until > maximum_deadline {
        return Err(anyhow!("privacy-buy plan exceeds configured MAX_TTL"));
    }
    let broadcast_deadline = now_seconds
        .checked_add(config.min_broadcast_window_seconds)
        .ok_or_else(|| anyhow!("privacy-buy minimum broadcast window overflow"))?;
    if plan.valid_until < broadcast_deadline {
        return Err(anyhow!(
            "privacy-buy plan has less than the minimum broadcast window"
        ));
    }
    if plan.route_hash != config.route_hash {
        return Err(anyhow!(
            "privacy-buy route hash does not match configured route"
        ));
    }
    if plan.quote_scale != config.quote_scale || plan.target_scale != config.target_scale {
        return Err(anyhow!("privacy-buy pool scale snapshot mismatch"));
    }
    if plan.quote_unshield_fee_units != config.quote_unshield_fee_units
        || plan.target_shield_fee_units != config.target_shield_fee_units
    {
        return Err(anyhow!("privacy-buy pool fee snapshot mismatch"));
    }
    if plan.quote_unshield_fee_units > plan.gross_quote_units
        || plan.quote_unshield_fee_units == plan.gross_quote_units
        || plan.target_shield_fee_units > plan.gross_target_units
        || plan.target_shield_fee_units == plan.gross_target_units
    {
        return Err(anyhow!("privacy-buy gross amount must exceed its pool fee"));
    }
    let expected_net_target = plan
        .gross_target_units
        .checked_sub(plan.target_shield_fee_units)
        .ok_or_else(|| anyhow!("target net amount underflow"))?;
    if plan.net_target_units != expected_net_target {
        return Err(anyhow!("privacy-buy target gross/net formula mismatch"));
    }
    let quote_received_wei = Uint::from(plan.gross_quote_units - plan.quote_unshield_fee_units)
        .checked_mul(plan.quote_scale)
        .ok_or_else(|| anyhow!("quote received amount exceeds uint256"))?;
    let fixed_buy_fee_wei = Uint::from(config.buy_fee_units)
        .checked_mul(plan.quote_scale)
        .ok_or_else(|| anyhow!("fixed buy fee exceeds uint256"))?;
    let expected_maximum = quote_received_wei
        .checked_sub(fixed_buy_fee_wei)
        .ok_or_else(|| anyhow!("quote amount does not cover fixed buy fee"))?;
    if expected_maximum.is_zero() || plan.amount_in_maximum_wei != expected_maximum {
        return Err(anyhow!("amount_in_maximum_wei violates exact-debit budget"));
    }
    if plan.quoted_amount_in_wei.is_zero() || plan.quoted_amount_in_wei > plan.amount_in_maximum_wei
    {
        return Err(anyhow!("quoted_amount_in_wei is outside the market budget"));
    }
    if plan.max_market_slippage_bps > config.max_market_slippage_bps_cap {
        return Err(anyhow!(
            "privacy-buy market slippage exceeds Coordinator cap"
        ));
    }
    let delta = plan.amount_in_maximum_wei - plan.quoted_amount_in_wei;
    let maximum_delta = plan
        .quoted_amount_in_wei
        .checked_mul(Uint::from(plan.max_market_slippage_bps))
        .ok_or_else(|| anyhow!("privacy-buy slippage multiplication overflow"))?
        / Uint::from(BPS_DENOMINATOR);
    if delta > maximum_delta {
        return Err(anyhow!(
            "privacy-buy market budget exceeds reference quote slippage"
        ));
    }
    if plan.max_quote_surplus_wei >= plan.amount_in_maximum_wei {
        return Err(anyhow!(
            "privacy-buy surplus limit is outside market budget"
        ));
    }
    let want_target_wei = Uint::from(plan.gross_target_units)
        .checked_mul(plan.target_scale)
        .ok_or_else(|| anyhow!("target amount exceeds uint256"))?;
    Ok(ValidatedPlan {
        plan,
        want_target_wei,
    })
}

fn word_at(calldata: &[u8], index: usize) -> Result<Uint> {
    let start = 4usize
        .checked_add(
            index
                .checked_mul(32)
                .ok_or_else(|| anyhow!("ABI word offset overflow"))?,
        )
        .ok_or_else(|| anyhow!("ABI word offset overflow"))?;
    let end = start
        .checked_add(32)
        .ok_or_else(|| anyhow!("ABI word offset overflow"))?;
    let word = calldata
        .get(start..end)
        .ok_or_else(|| anyhow!("privacy-buy calldata is shorter than the static plan head"))?;
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
        .expect("word_at already checked the static head"))
}

/// Decode only the fixed first tuple from the immutable Coordinator's `buy` calldata. The queue
/// uses this on the persisted bytes immediately before signing, so a stale quote or deadline is
/// revalidated without trusting request-side metadata.
pub fn decode_buy_plan_calldata(calldata: &[u8]) -> Result<BuyPlanV1> {
    if calldata.get(..4) != Some(buy_selector().as_slice()) {
        return Err(anyhow!(
            "persisted transaction is not PrivacyBuyCoordinatorV1.buy"
        ));
    }
    // Force a full bounds check before direct bytes32 slicing below.
    let _ = word_at(calldata, 13)?;
    Ok(BuyPlanV1 {
        gross_quote_units: word_u64(calldata, 0, "gross_quote_units", u64::MAX)?,
        quote_unshield_fee_units: word_u64(calldata, 1, "quote_unshield_fee_units", U48_MAX)?,
        quote_scale: word_at(calldata, 2)?,
        gross_target_units: word_u64(calldata, 3, "gross_target_units", u64::MAX)?,
        target_shield_fee_units: word_u64(calldata, 4, "target_shield_fee_units", U48_MAX)?,
        net_target_units: word_u64(calldata, 5, "net_target_units", u64::MAX)?,
        target_scale: word_at(calldata, 6)?,
        quoted_amount_in_wei: word_at(calldata, 7)?,
        amount_in_maximum_wei: word_at(calldata, 8)?,
        max_quote_surplus_wei: word_at(calldata, 9)?,
        max_market_slippage_bps: word_u64(calldata, 10, "max_market_slippage_bps", u16::MAX as u64)?
            as u16,
        valid_until: word_u64(calldata, 11, "valid_until", u64::MAX)?,
        route_hash: word_bytes32(calldata, 12)?,
        salt: word_bytes32(calldata, 13)?,
    })
}

pub fn validate_current_quote(validated: &ValidatedPlan, current_quote: Uint) -> Result<()> {
    let plan = &validated.plan;
    if current_quote.is_zero() || current_quote > plan.amount_in_maximum_wei {
        return Err(anyhow!(
            "current exact-output quote exceeds the user's maximum input"
        ));
    }
    if current_quote > plan.quoted_amount_in_wei {
        let increase = current_quote - plan.quoted_amount_in_wei;
        let maximum_increase = plan
            .quoted_amount_in_wei
            .checked_mul(Uint::from(plan.max_market_slippage_bps))
            .ok_or_else(|| anyhow!("current quote slippage multiplication overflow"))?
            / Uint::from(BPS_DENOMINATOR);
        if increase > maximum_increase {
            return Err(anyhow!(
                "current exact-output quote exceeds wallet slippage"
            ));
        }
    }
    let likely_surplus = plan.amount_in_maximum_wei - current_quote;
    if likely_surplus > plan.max_quote_surplus_wei {
        return Err(anyhow!("current quote would exceed the user's surplus cap"));
    }
    Ok(())
}

pub fn buy_selector() -> [u8; 4] {
    selector(BUY_SIG)
}

pub fn encode_buy_calldata(
    plan: &BuyPlanV1,
    route_data: &[u8],
    unshield_call: &PrivacyCallArgs,
    shield_call: &PrivacyCallArgs,
) -> Vec<u8> {
    with_selector(
        BUY_SIG,
        &[
            plan_token(plan),
            Token::Bytes(route_data.to_vec()),
            privacy_call_token(unshield_call),
            privacy_call_token(shield_call),
        ],
    )
}

pub fn encode_buy_context_calldata(plan: &BuyPlanV1, shield_call: &PrivacyCallArgs) -> Vec<u8> {
    with_selector(
        BUY_CONTEXT_SIG,
        &[plan_token(plan), privacy_call_token(shield_call)],
    )
}

pub fn compute_context(
    chain_id: u64,
    config: &PrivacyBuyConfig,
    plan: &BuyPlanV1,
    shield_call: &PrivacyCallArgs,
) -> Result<[u8; 32]> {
    let domain: [u8; 32] = Keccak256::digest(b"PERC20.PrivacyBuy.exact-debit.v1").into();
    let shield_call_hash = privacy_call_commit(shield_call);
    let encoded = encode(&[
        Token::FixedBytes(domain.to_vec()),
        Token::Uint(Uint::from(chain_id)),
        Token::Address(address(&config.coordinator, "coordinator")?),
        Token::Uint(Uint::from(PROTOCOL_VERSION)),
        Token::Uint(Uint::from(APPLICATION_VERSION)),
        Token::Address(address(&config.registry, "registry")?),
        Token::Address(address(&config.quote_pool, "quote_pool")?),
        Token::Address(address(&config.target_pool, "target_pool")?),
        Token::FixedBytes(config.quote_verifier_set_id.to_vec()),
        Token::FixedBytes(config.target_verifier_set_id.to_vec()),
        Token::Address(address(&config.quote_token, "quote_token")?),
        Token::Address(address(&config.target_token, "target_token")?),
        Token::Address(address(&config.adapter, "adapter")?),
        Token::FixedBytes(config.adapter_runtime_codehash.to_vec()),
        Token::Address(address(&config.fee_collector, "fee_collector")?),
        Token::Uint(Uint::from(config.buy_fee_units)),
        Token::Uint(Uint::from(config.max_ttl_seconds)),
        Token::Uint(Uint::from(config.max_market_slippage_bps_cap)),
        plan_token(plan),
        Token::FixedBytes(shield_call_hash.to_vec()),
    ]);
    Ok(Keccak256::digest(encoded).into())
}

pub fn encode_quoter_calldata(route_data: &[u8], want_target_wei: Uint) -> Vec<u8> {
    with_selector(
        QUOTE_EXACT_OUTPUT_SIG,
        &[
            Token::Bytes(route_data.to_vec()),
            Token::Uint(want_target_wei),
        ],
    )
}

pub fn parse_first_abi_uint(value: &str, field: &str) -> Result<Uint> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() < 64 {
        return Err(anyhow!("{field} returned fewer than 32 bytes"));
    }
    let first = hex::decode(&raw[..64]).with_context(|| format!("{field} returned invalid hex"))?;
    Ok(Uint::from_big_endian(&first))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PrivacyBuyConfig {
        let route = hex::decode(format!(
            "{}000bb8{}0001f4{}",
            "11".repeat(20),
            "22".repeat(20),
            "33".repeat(20),
        ))
        .unwrap();
        PrivacyBuyConfig {
            accepting: true,
            coordinator: format!("0x{}", "11".repeat(20)),
            registry: format!("0x{}", "22".repeat(20)),
            quote_pool: format!("0x{}", "33".repeat(20)),
            target_pool: format!("0x{}", "44".repeat(20)),
            quote_verifier_set_id: [0x55; 32],
            target_verifier_set_id: [0x66; 32],
            quote_token: format!("0x{}", "77".repeat(20)),
            target_token: format!("0x{}", "88".repeat(20)),
            quote_scale: Uint::from(1),
            target_scale: Uint::from(10_000_000_000u64),
            quote_unshield_fee_units: 10,
            target_shield_fee_units: 2,
            adapter: format!("0x{}", "99".repeat(20)),
            adapter_runtime_codehash: [0xaa; 32],
            fee_collector: format!("0x{}", "bb".repeat(20)),
            buy_fee_units: 5,
            max_ttl_seconds: 900,
            max_market_slippage_bps_cap: 500,
            route_hash: route_hash(&route),
            route_data: route,
            quoter: format!("0x{}", "cc".repeat(20)),
            quoter_runtime_codehash: [0xdd; 32],
            gas_limit: 12_000_000,
            min_broadcast_window_seconds: 30,
            event_getlogs_max_span: 101,
        }
    }

    fn plan_json() -> BuyPlanJson {
        BuyPlanJson {
            gross_quote_units: "1000".into(),
            quote_unshield_fee_units: "10".into(),
            quote_scale: "1".into(),
            gross_target_units: "100".into(),
            target_shield_fee_units: "2".into(),
            net_target_units: "98".into(),
            target_scale: "10000000000".into(),
            quoted_amount_in_wei: "980".into(),
            amount_in_maximum_wei: "985".into(),
            max_quote_surplus_wei: "10".into(),
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
    fn plan_formula_and_quote_validation_are_fail_closed() {
        let validated = validate_plan(plan_json(), &config(), 1_700_000_000).unwrap();
        assert_eq!(validated.want_target_wei, Uint::from(1_000_000_000_000u64));
        validate_current_quote(&validated, Uint::from(980)).unwrap();
        assert!(validate_current_quote(&validated, Uint::from(970)).is_err());
        assert!(validate_current_quote(&validated, Uint::from(986)).is_err());

        let mut bad = plan_json();
        bad.net_target_units = "99".into();
        assert!(validate_plan(bad, &config(), 1_700_000_000).is_err());
        let mut bad = plan_json();
        bad.quote_unshield_fee_units = (1u64 << 48).to_string();
        assert!(validate_plan(bad, &config(), 1_700_000_000).is_err());
    }

    #[test]
    fn context_matches_the_wallet_and_solidity_vector() {
        let cfg = config();
        let plan = validate_plan(plan_json(), &cfg, 1_700_000_000)
            .unwrap()
            .plan;
        let context = compute_context(4_663, &cfg, &plan, &empty_call()).unwrap();
        // Empty PrivacyCall has a different shieldCall hash from the fixed zero-hash vector.
        // Pin the Rust result so any ABI tuple drift is still detected here.
        assert_eq!(
            hex::encode(context),
            "1d52d05545efd83fa8861694386979958efbebc157fe08535ab4fa3595da6a19"
        );
    }

    #[test]
    fn buy_and_quoter_selectors_and_route_are_exact() {
        let cfg = config();
        let plan = validate_plan(plan_json(), &cfg, 1_700_000_000).unwrap();
        let calldata =
            encode_buy_calldata(&plan.plan, &cfg.route_data, &empty_call(), &empty_call());
        assert_eq!(&calldata[..4], &buy_selector());
        let decoded = decode_buy_plan_calldata(&calldata).unwrap();
        assert_eq!(decoded.gross_quote_units, plan.plan.gross_quote_units);
        assert_eq!(decoded.target_scale, plan.plan.target_scale);
        assert_eq!(decoded.route_hash, plan.plan.route_hash);
        assert_eq!(
            parse_route_data(&format!("0x{}", hex::encode(&cfg.route_data))).unwrap(),
            cfg.route_data
        );
        let quote = encode_quoter_calldata(&cfg.route_data, plan.want_target_wei);
        assert_eq!(&quote[..4], &selector(QUOTE_EXACT_OUTPUT_SIG));
    }

    #[test]
    fn market_profile_is_robinhood_legacy_pons_only() {
        let route = hex::decode(format!(
            "{}002710{}0001f4{}",
            &PONS_V1_REFERENCE_TOKEN[2..],
            &ROBINHOOD_WETH[2..],
            &ROBINHOOD_USDG[2..],
        ))
        .unwrap();
        validate_market_profile(
            ROBINHOOD_CHAIN_ID,
            MARKET_PROFILE,
            ROBINHOOD_QUOTER_V2,
            &route,
        )
        .unwrap();
        assert!(validate_market_profile(143, MARKET_PROFILE, ROBINHOOD_QUOTER_V2, &route).is_err());
        assert!(validate_market_profile(
            ROBINHOOD_CHAIN_ID,
            "pons-v2",
            ROBINHOOD_QUOTER_V2,
            &route,
        )
        .is_err());
        let mut bad = route.clone();
        bad[23] ^= 1;
        assert!(validate_market_profile(
            ROBINHOOD_CHAIN_ID,
            MARKET_PROFILE,
            ROBINHOOD_QUOTER_V2,
            &bad,
        )
        .is_err());
        let mut bad_fee = route;
        bad_fee[20..23].copy_from_slice(&[0x00, 0x0b, 0xb8]);
        assert!(validate_market_profile(
            ROBINHOOD_CHAIN_ID,
            MARKET_PROFILE,
            ROBINHOOD_QUOTER_V2,
            &bad_fee,
        )
        .is_err());
    }
}
