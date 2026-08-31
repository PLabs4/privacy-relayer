//! Calldata encoders for the protocol-fee release (see PERC20 `docs/tx_fee_impl.md`).
//!
//! These live here rather than in `privacy-core` because the fee work changed two on-chain
//! signatures and the core crate is pinned to a published git rev:
//!
//! * `ERC20Shield.unshield` grew a `(bytes32 context, address executor)` pair, so
//!   `privacy_core::ethereum::encode_wrapped_unshield_calldata` (which still encodes the old
//!   3-argument form) no longer matches the deployed ABI.
//! * `Perc20FeeGateway.transferWithFee` is new.
//!
//! The `PrivacyCall` tuple encoding is reproduced verbatim from `privacy-core` — the helper it
//! uses is private there. Keep the two in sync: `PrivacyCall` is
//! `(bytes abi.encode(BundleAction[]), uint256[8] bindingProof)`, and the nested `actions` blob
//! carries the eight `IEndpointCore.BundleAction` fields in declaration order.
//!
//! Once these signatures land in a `privacy-core` release, delete this module and switch back
//! to the upstream encoders.

use ethabi::{encode, Token, Uint};
use privacy_core::ethereum::{BundleActionArgs, PrivacyCallArgs};
use sha3::{Digest, Keccak256};

fn selector(signature: &[u8]) -> [u8; 4] {
    Keccak256::digest(signature)[..4]
        .try_into()
        .expect("selector is 4 bytes")
}

fn with_selector(sel: [u8; 4], body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&sel);
    out.extend_from_slice(&body);
    out
}

/// `IEndpointCore.BundleAction[]` as an ethabi token.
fn bundle_actions_token(actions: &[BundleActionArgs]) -> Token {
    Token::Array(
        actions
            .iter()
            .map(|a| {
                let pub_fields_token = Token::FixedArray(
                    a.pub_fields
                        .iter()
                        .map(|b| Token::Uint(Uint::from_big_endian(b)))
                        .collect(),
                );
                Token::Tuple(vec![
                    Token::FixedBytes(a.cmx.to_vec()),
                    Token::Bytes(a.enc_ciphertext.clone()),
                    Token::Bytes(a.out_ciphertext.clone()),
                    Token::FixedBytes(a.epk.to_vec()),
                    Token::FixedBytes(a.nf_old.to_vec()),
                    Token::FixedBytes(a.anchor.to_vec()),
                    Token::Bytes(a.proof.clone()),
                    pub_fields_token,
                ])
            })
            .collect(),
    )
}

/// The `PrivacyCall` tuple: `(bytes abi.encode(BundleAction[]), uint256[8] bindingProof)`.
pub(crate) fn privacy_call_token(call: &PrivacyCallArgs) -> Token {
    let actions_bytes = encode(&[bundle_actions_token(&call.actions)]);
    let binding_proof_token = Token::FixedArray(
        call.binding_proof
            .iter()
            .map(|b| Token::Uint(Uint::from_big_endian(b)))
            .collect(),
    );
    Token::Tuple(vec![Token::Bytes(actions_bytes), binding_proof_token])
}

const UNSHIELD_V2_SIG: &[u8] = b"unshield(uint256,address,bytes32,address,(bytes,uint256[8]))";
const NATIVE_ETH_UNSHIELD_SIG: &[u8] = b"unshieldETH(uint256,address,(bytes,uint256[8]))";
/// The original single-fee-asset gateway. The fee pool is immutable on the gateway and is not
/// part of the calldata; the only address argument is the pool receiving the transfer.
const LEGACY_TRANSFER_WITH_FEE_SIG: &[u8] =
    b"transferWithFee(address,(bytes,uint256[8]),(bytes,uint256[8]))";
/// The multi-fee-asset gateway: `feePool` is the FIRST argument, because the gateway accepts
/// several fee assets and prices `(fee asset, target pool)` PAIRS. The single-asset form
/// (`transferWithFee(address,…)`, selector `0x4c4ba93b`) is gone — a relayer built against it
/// reverts with a decode error, not a helpful message, so this constant is what must be kept in
/// step with `PERC20/contracts/ptoken/Perc20FeeGateway.sol`.
const TRANSFER_WITH_FEE_SIG: &[u8] =
    b"transferWithFee(address,address,(bytes,uint256[8]),(bytes,uint256[8]))";
const SWAP_CANCEL_SIG: &[u8] = b"cancel(bytes32)";
const SWAP_INITIATE_V2_SIG: &[u8] = b"initiateSwap(address,address,(bytes,uint256[8]),(bytes32,address,bytes32,bytes32,uint256,uint256,uint64,bytes32,(bytes32,uint256,uint256),(bytes32,uint256,uint256),address,uint256),bytes,uint256[3])";
const SWAP_SETTLE_V2_SIG: &[u8] = b"settle(bytes32,bytes32,(bytes,uint256[8]),(bytes,uint256[8]),((bytes,uint256[8]),uint256[3]),((bytes,uint256[8]),uint256[3]))";

#[derive(Clone, Debug)]
pub struct OrderRefArgs {
    pub terms_hash: [u8; 32],
    pub auth_key_x: [u8; 32],
    pub auth_key_y: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct MatchPermitArgs {
    pub permit_nonce: [u8; 32],
    pub expected_initiator: [u8; 20],
    pub expected_commit_b: [u8; 32],
    pub htlc_hash: [u8; 32],
    pub rk_bx: [u8; 32],
    pub rk_by: [u8; 32],
    pub deadline: u64,
    pub salt: [u8; 32],
    pub maker: OrderRefArgs,
    pub taker: OrderRefArgs,
    pub fee_pool: [u8; 20],
    pub fee_units: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct OrderFeeAuthArgs {
    pub fee_call: Option<PrivacyCallArgs>,
    pub exempt_sig: [[u8; 32]; 3],
}

fn order_ref_token(order: &OrderRefArgs) -> Token {
    Token::Tuple(vec![
        Token::FixedBytes(order.terms_hash.to_vec()),
        Token::Uint(Uint::from_big_endian(&order.auth_key_x)),
        Token::Uint(Uint::from_big_endian(&order.auth_key_y)),
    ])
}

fn match_permit_token(permit: &MatchPermitArgs) -> Token {
    Token::Tuple(vec![
        Token::FixedBytes(permit.permit_nonce.to_vec()),
        Token::Address(ethabi::Address::from(permit.expected_initiator)),
        Token::FixedBytes(permit.expected_commit_b.to_vec()),
        Token::FixedBytes(permit.htlc_hash.to_vec()),
        Token::Uint(Uint::from_big_endian(&permit.rk_bx)),
        Token::Uint(Uint::from_big_endian(&permit.rk_by)),
        Token::Uint(Uint::from(permit.deadline)),
        Token::FixedBytes(permit.salt.to_vec()),
        order_ref_token(&permit.maker),
        order_ref_token(&permit.taker),
        Token::Address(ethabi::Address::from(permit.fee_pool)),
        Token::Uint(Uint::from_big_endian(&permit.fee_units)),
    ])
}

fn empty_privacy_call_token() -> Token {
    Token::Tuple(vec![
        Token::Bytes(Vec::new()),
        Token::FixedArray((0..8).map(|_| Token::Uint(Uint::zero())).collect()),
    ])
}

/// A Baby JubJub Schnorr signature `[Rx, Ry, s]` as the ABI's `uint256[3]`.
fn sig3_token(signature: &[[u8; 32]; 3]) -> Token {
    Token::FixedArray(
        signature
            .iter()
            .map(|value| Token::Uint(Uint::from_big_endian(value)))
            .collect(),
    )
}

fn order_fee_auth_token(auth: &OrderFeeAuthArgs) -> Token {
    Token::Tuple(vec![
        auth.fee_call
            .as_ref()
            .map(privacy_call_token)
            .unwrap_or_else(empty_privacy_call_token),
        sig3_token(&auth.exempt_sig),
    ])
}

/// Fee-v2 `DexGateway.initiateSwap`: the exact matcher permit and signature are relayed without
/// interpretation after the HTTP layer has parsed their fixed-width fields.
pub fn encode_swap_initiate_v2_calldata(
    pool_a: &[u8; 20],
    pool_b: &[u8; 20],
    call_a: &PrivacyCallArgs,
    permit: &MatchPermitArgs,
    matcher_signature: &[u8],
    initiator_sig: &[[u8; 32]; 3],
) -> Vec<u8> {
    with_selector(
        selector(SWAP_INITIATE_V2_SIG),
        encode(&[
            Token::Address(ethabi::Address::from(*pool_a)),
            Token::Address(ethabi::Address::from(*pool_b)),
            privacy_call_token(call_a),
            match_permit_token(permit),
            Token::Bytes(matcher_signature.to_vec()),
            sig3_token(initiator_sig),
        ]),
    )
}

/// Fee-v2 three-stage settlement. Principal calls stay value-neutral; each order contributes an
/// independent fee call on first fill or a BabyJubJub exemption signature on later fills.
pub fn encode_swap_settle_v2_calldata(
    swap_id: &[u8; 32],
    secret: &[u8; 32],
    call_a: &PrivacyCallArgs,
    call_b: &PrivacyCallArgs,
    maker_fee: &OrderFeeAuthArgs,
    taker_fee: &OrderFeeAuthArgs,
) -> Vec<u8> {
    with_selector(
        selector(SWAP_SETTLE_V2_SIG),
        encode(&[
            Token::FixedBytes(swap_id.to_vec()),
            Token::FixedBytes(secret.to_vec()),
            privacy_call_token(call_a),
            privacy_call_token(call_b),
            order_fee_auth_token(maker_fee),
            order_fee_auth_token(taker_fee),
        ]),
    )
}

pub fn unshield_v2_selector() -> [u8; 4] {
    selector(UNSHIELD_V2_SIG)
}

pub fn transfer_with_fee_selector() -> [u8; 4] {
    selector(TRANSFER_WITH_FEE_SIG)
}

pub fn legacy_transfer_with_fee_selector() -> [u8; 4] {
    selector(LEGACY_TRANSFER_WITH_FEE_SIG)
}

pub fn native_eth_unshield_selector() -> [u8; 4] {
    selector(NATIVE_ETH_UNSHIELD_SIG)
}

/// `DexGateway.cancel(swapId)`. The relay EOA opened sponsored swaps, so it is the only caller
/// the gateway accepts after the on-chain deadline.
pub fn encode_swap_cancel_calldata(swap_id: &[u8; 32]) -> Vec<u8> {
    with_selector(
        selector(SWAP_CANCEL_SIG),
        encode(&[Token::FixedBytes(swap_id.to_vec())]),
    )
}

/// `ERC20Shield.unshield(amountUnits, recipient, context, executor, call)`.
///
/// The pool deducts `unshieldFeeUnits` from `amountUnits` and sends it to `feeCollector`; the
/// recipient receives the remainder. Both the fee and `context` are folded into `recipientMeta`
/// on-chain, so a rate change between proving and submission makes the Binding proof fail
/// instead of silently paying the user less — the relayer never needs a slippage guard.
///
/// Plain withdrawals pass `context = 0` and `executor = 0`.
pub fn encode_unshield_v2_calldata(
    amount_units: u64,
    recipient: &[u8; 20],
    context: &[u8; 32],
    executor: &[u8; 20],
    call: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::Uint(Uint::from(amount_units)),
        Token::Address(ethabi::Address::from(*recipient)),
        Token::FixedBytes(context.to_vec()),
        Token::Address(ethabi::Address::from(*executor)),
        privacy_call_token(call),
    ];
    with_selector(unshield_v2_selector(), encode(&tokens))
}

/// `NativeEthGateway.unshieldETH(amountUnits, finalRecipient, call)`.
///
/// The gateway supplies itself as the pool recipient/executor and derives the
/// application context on-chain. The caller supplies only the already-proved
/// bundle and final native recipient; any mismatch fails the pool Binding proof.
pub fn encode_native_eth_unshield_calldata(
    amount_units: u64,
    final_recipient: &[u8; 20],
    call: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::Uint(Uint::from(amount_units)),
        Token::Address(ethabi::Address::from(*final_recipient)),
        privacy_call_token(call),
    ];
    with_selector(native_eth_unshield_selector(), encode(&tokens))
}

/// `ERC20Shield.transfer(PrivacyCall)` — the no-executor overload (`_transfer(address(0), …)`),
/// i.e. a permissionless shielded transfer paid for by the relayer's EOA.
///
/// Distinct from the two-arg `transfer(address,(bytes,uint256[8]))` the swap legs use: that one
/// binds an executor and reverts `UnauthorizedExecutor` for any other sender. A bundle proved
/// WITHOUT `executor_hex` must go through this overload — passing it to the two-arg form with
/// `address(0)` would encode a different selector and fail to decode.
pub const TRANSFER_SIG: &[u8] = b"transfer((bytes,uint256[8]))";

pub fn transfer_selector() -> [u8; 4] {
    selector(TRANSFER_SIG)
}

pub fn encode_transfer_calldata(call: &PrivacyCallArgs) -> Vec<u8> {
    with_selector(transfer_selector(), encode(&[privacy_call_token(call)]))
}

/// `Perc20FeeGateway.transferWithFee(feePool, pool, opCall, feeCall)`.
///
/// `opCall` must have been proved with `executor = <gateway address>`; `feeCall` is an unshield
/// bundle against `fee_pool` whose amount/recipient/context the gateway supplies itself, so a
/// mismatch fails the Binding proof rather than passing an unchecked value through.
///
/// `fee_pool` must be one the governor has priced for `pool` — the gateway checks
/// `transferFeeUnits[feePool][pool] != 0` before it calls into `feePool` at all, so an unpriced
/// pair reverts `FeeNotConfigured` rather than reaching an arbitrary contract.
pub fn encode_transfer_with_fee_calldata(
    fee_pool: &[u8; 20],
    pool: &[u8; 20],
    op_call: &PrivacyCallArgs,
    fee_call: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::Address(ethabi::Address::from(*fee_pool)),
        Token::Address(ethabi::Address::from(*pool)),
        privacy_call_token(op_call),
        privacy_call_token(fee_call),
    ];
    with_selector(transfer_with_fee_selector(), encode(&tokens))
}

/// Legacy `Perc20FeeGateway.transferWithFee(pool, opCall, feeCall)`.
///
/// The fee-paying pool is implicit in the v1 gateway's immutable `feePool()` getter. Callers
/// must only select this encoding after boot-time verification that `feePool()` matches the
/// configured fee pool.
pub fn encode_legacy_transfer_with_fee_calldata(
    pool: &[u8; 20],
    op_call: &PrivacyCallArgs,
    fee_call: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::Address(ethabi::Address::from(*pool)),
        privacy_call_token(op_call),
        privacy_call_token(fee_call),
    ];
    with_selector(legacy_transfer_with_fee_selector(), encode(&tokens))
}

/// `Perc20FeeGateway.transferWithFee(pool, pool, combinedCall, EMPTY)` — the same-asset form,
/// used when the transferred asset IS the fee asset. Both address arguments are that one pool:
/// the gateway rejects `pool != feePool` in this mode with `NotFeeAsset` before anything else.
///
/// The single bundle both moves the notes and unshields the fee, which is what lets a wallet
/// with one note pay for its own transfer; two bundles in one pool would have to spend that
/// note twice and revert on the duplicate nullifier.
///
/// The empty fee call must be an EMPTY `bytes`, which is why this does not go through
/// `privacy_call_token` with an empty action list: that encodes `BundleAction[](0)` as 64 bytes
/// (offset + zero length), and the gateway tests `feeCall.actions.length == 0`. A 64-byte
/// "empty" would silently take the two-bundle branch and be rejected by the pool as an empty
/// bundle — fail-closed, but for a reason nobody would find quickly.
pub fn encode_transfer_with_fee_same_asset_calldata(
    pool: &[u8; 20],
    combined_call: &PrivacyCallArgs,
) -> Vec<u8> {
    let empty_call = Token::Tuple(vec![
        Token::Bytes(Vec::new()),
        Token::FixedArray(vec![Token::Uint(Uint::zero()); 8]),
    ]);
    let tokens = vec![
        Token::Address(ethabi::Address::from(*pool)),
        Token::Address(ethabi::Address::from(*pool)),
        privacy_call_token(combined_call),
        empty_call,
    ];
    with_selector(transfer_with_fee_selector(), encode(&tokens))
}

/// Legacy same-asset form. The single address is both the transferred pool and the gateway's
/// boot-verified immutable fee pool; an empty fee call selects the combined-bundle path.
pub fn encode_legacy_transfer_with_fee_same_asset_calldata(
    pool: &[u8; 20],
    combined_call: &PrivacyCallArgs,
) -> Vec<u8> {
    let empty_call = Token::Tuple(vec![
        Token::Bytes(Vec::new()),
        Token::FixedArray(vec![Token::Uint(Uint::zero()); 8]),
    ]);
    let tokens = vec![
        Token::Address(ethabi::Address::from(*pool)),
        privacy_call_token(combined_call),
        empty_call,
    ];
    with_selector(legacy_transfer_with_fee_selector(), encode(&tokens))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Selectors are what the `/submit_raw` policy table is keyed on, so pin them.
    #[test]
    fn selectors_match_signatures() {
        assert_eq!(unshield_v2_selector(), selector(UNSHIELD_V2_SIG));
        assert_eq!(transfer_with_fee_selector(), selector(TRANSFER_WITH_FEE_SIG));
        assert_eq!(
            legacy_transfer_with_fee_selector(),
            selector(LEGACY_TRANSFER_WITH_FEE_SIG)
        );
        assert_eq!(native_eth_unshield_selector(), selector(NATIVE_ETH_UNSHIELD_SIG));
        // must differ from the legacy 3-arg unshield the contract no longer exposes
        assert_ne!(
            unshield_v2_selector(),
            selector(b"unshield(uint256,address,(bytes,uint256[8]))")
        );
    }

    #[test]
    fn swap_cancel_encodes_one_bytes32_argument() {
        let cd = encode_swap_cancel_calldata(&[0xAB; 32]);
        assert_eq!(&cd[..4], &selector(SWAP_CANCEL_SIG));
        assert_eq!(&cd[4..36], &[0xAB; 32]);
    }

    #[test]
    fn native_eth_unshield_targets_gateway_three_arg_abi() {
        let cd = encode_native_eth_unshield_calldata(7, &[0x44; 20], &empty_call());
        assert_eq!(&cd[..4], &native_eth_unshield_selector());
        let body = &cd[4..];
        assert_eq!(Uint::from_big_endian(&body[0..32]), Uint::from(7));
        assert_eq!(&body[32 + 12..64], &[0x44u8; 20]);
        assert_eq!(Uint::from_big_endian(&body[64..96]), Uint::from(96));
    }

    /// The permissionless `transfer` overload must NOT collide with the executor-gated one the
    /// swap legs use — picking the wrong overload is a revert with a misleading reason.
    #[test]
    fn transfer_selector_is_the_no_executor_overload() {
        assert_eq!(transfer_selector(), selector(TRANSFER_SIG));
        assert_ne!(
            transfer_selector(),
            selector(b"transfer(address,(bytes,uint256[8]))")
        );
        // protocol 3 shape: the PrivacyCall carries a uint256[8] binding PROOF, not a [3] sig.
        assert_ne!(
            transfer_selector(),
            selector(b"transfer((bytes,uint256[3]))")
        );
    }

    fn empty_call() -> PrivacyCallArgs {
        PrivacyCallArgs { actions: vec![], binding_proof: [[0u8; 32]; 8] }
    }

    #[test]
    fn unshield_v2_head_has_five_static_words() {
        let cd = encode_unshield_v2_calldata(7, &[0x11; 20], &[0x22; 32], &[0x33; 20], &empty_call());
        assert_eq!(&cd[..4], &unshield_v2_selector());
        let body = &cd[4..];
        // amountUnits
        assert_eq!(Uint::from_big_endian(&body[0..32]), Uint::from(7));
        // recipient (right-aligned address)
        assert_eq!(&body[32 + 12..64], &[0x11u8; 20]);
        // context
        assert_eq!(&body[64..96], &[0x22u8; 32]);
        // executor
        assert_eq!(&body[96 + 12..128], &[0x33u8; 20]);
        // fifth head word is the offset to the PrivacyCall tuple: 5 * 32
        assert_eq!(Uint::from_big_endian(&body[128..160]), Uint::from(160));
    }

    #[test]
    fn transfer_with_fee_carries_two_distinct_calls() {
        let mut fee = empty_call();
        fee.binding_proof[0] = [0xAB; 32];
        let cd = encode_transfer_with_fee_calldata(&[0xFE; 20], &[0x44; 20], &empty_call(), &fee);
        assert_eq!(&cd[..4], &transfer_with_fee_selector());
        let body = &cd[4..];
        // arg0 is the FEE asset, arg1 the target pool — swapping them would price off the wrong
        // row of the gateway's table and unshield from the wrong pool.
        assert_eq!(&body[12..32], &[0xFEu8; 20]);
        assert_eq!(&body[44..64], &[0x44u8; 20]);
        // two dynamic tuples → two distinct offsets
        let off_op = Uint::from_big_endian(&body[64..96]);
        let off_fee = Uint::from_big_endian(&body[96..128]);
        assert_ne!(off_op, off_fee);
        // the fee leg's distinguishing binding word must appear in the payload
        assert!(cd.windows(32).any(|w| w == [0xABu8; 32]));
    }

    /// The single-fee-asset gateway's selector must NOT be what we emit: a relayer still
    /// encoding `0x4c4ba93b` reaches the new gateway as an unknown selector and reverts in the
    /// fallback, which reads as "the pool rejected the bundle" rather than "wrong ABI".
    #[test]
    fn transfer_with_fee_is_the_multi_fee_asset_signature() {
        assert_ne!(
            transfer_with_fee_selector(),
            legacy_transfer_with_fee_selector()
        );
        assert_eq!(transfer_with_fee_selector(), [0x25, 0x78, 0x4a, 0x2e]);
        assert_eq!(legacy_transfer_with_fee_selector(), [0x4c, 0x4b, 0xa9, 0x3b]);
    }

    #[test]
    fn legacy_transfer_with_fee_has_one_address_and_two_distinct_calls() {
        let mut fee = empty_call();
        fee.binding_proof[0] = [0xAB; 32];
        let cd = encode_legacy_transfer_with_fee_calldata(&[0x44; 20], &empty_call(), &fee);
        assert_eq!(&cd[..4], &legacy_transfer_with_fee_selector());
        let body = &cd[4..];
        assert_eq!(&body[12..32], &[0x44u8; 20]);
        let off_op = Uint::from_big_endian(&body[32..64]);
        let off_fee = Uint::from_big_endian(&body[64..96]);
        assert_ne!(off_op, off_fee);
        assert!(cd.windows(32).any(|w| w == [0xABu8; 32]));
    }

    /// The same-asset form rides the SAME selector; the mode switch is the empty `actions`.
    /// Asserting the emptiness is the point: an `actions` of 64 bytes (an ABI-encoded empty
    /// array) reads as the two-bundle form and the gateway would route it the other way.
    #[test]
    fn same_asset_reuses_transfer_with_fee_with_an_empty_fee_call() {
        let mut call = empty_call();
        call.binding_proof[0] = [0xCD; 32];
        let cd = encode_transfer_with_fee_same_asset_calldata(&[0x55; 20], &call);
        assert_eq!(&cd[..4], &transfer_with_fee_selector());
        let body = &cd[4..];
        // Same-asset means BOTH address arguments are that one pool; the gateway rejects any
        // other combination with `NotFeeAsset` before it looks at anything else.
        assert_eq!(&body[12..32], &[0x55u8; 20]);
        assert_eq!(&body[44..64], &[0x55u8; 20]);
        assert!(cd.windows(32).any(|w| w == [0xCDu8; 32]));

        // Walk to the fee tuple and read its `actions` length: it must be exactly 0.
        let off_fee = Uint::from_big_endian(&body[96..128]).as_usize();
        let fee_tuple = &body[off_fee..];
        let off_actions = Uint::from_big_endian(&fee_tuple[0..32]).as_usize();
        assert_eq!(
            Uint::from_big_endian(&fee_tuple[off_actions..off_actions + 32]),
            Uint::zero(),
            "the fee call's actions must be EMPTY bytes — that is the same-asset mode switch",
        );
    }

    #[test]
    fn legacy_same_asset_uses_legacy_selector_and_empty_fee_call() {
        let mut call = empty_call();
        call.binding_proof[0] = [0xCD; 32];
        let cd = encode_legacy_transfer_with_fee_same_asset_calldata(&[0x55; 20], &call);
        assert_eq!(&cd[..4], &legacy_transfer_with_fee_selector());
        let body = &cd[4..];
        assert_eq!(&body[12..32], &[0x55u8; 20]);
        assert!(cd.windows(32).any(|w| w == [0xCDu8; 32]));

        let off_fee = Uint::from_big_endian(&body[64..96]).as_usize();
        let fee_tuple = &body[off_fee..];
        let off_actions = Uint::from_big_endian(&fee_tuple[0..32]).as_usize();
        assert_eq!(
            Uint::from_big_endian(&fee_tuple[off_actions..off_actions + 32]),
            Uint::zero(),
        );
    }
}
