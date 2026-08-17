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
fn privacy_call_token(call: &PrivacyCallArgs) -> Token {
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
const TRANSFER_WITH_FEE_SIG: &[u8] =
    b"transferWithFee(address,(bytes,uint256[8]),(bytes,uint256[8]))";

pub fn unshield_v2_selector() -> [u8; 4] {
    selector(UNSHIELD_V2_SIG)
}

pub fn transfer_with_fee_selector() -> [u8; 4] {
    selector(TRANSFER_WITH_FEE_SIG)
}

pub fn native_eth_unshield_selector() -> [u8; 4] {
    selector(NATIVE_ETH_UNSHIELD_SIG)
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

/// `Perc20FeeGateway.transferWithFee(pool, opCall, feeCall)`.
///
/// `opCall` must have been proved with `executor = <gateway address>`; `feeCall` is a pUSDC
/// unshield bundle whose amount/recipient/context the gateway supplies itself, so a mismatch
/// fails the Binding proof rather than passing an unchecked value through.
pub fn encode_transfer_with_fee_calldata(
    pool: &[u8; 20],
    op_call: &PrivacyCallArgs,
    fee_call: &PrivacyCallArgs,
) -> Vec<u8> {
    let tokens = vec![
        Token::Address(ethabi::Address::from(*pool)),
        privacy_call_token(op_call),
        privacy_call_token(fee_call),
    ];
    with_selector(transfer_with_fee_selector(), encode(&tokens))
}

/// `Perc20FeeGateway.transferWithFee(pool, combinedCall, EMPTY)` — the same-asset form, used
/// when the transferred asset IS the fee asset.
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
        privacy_call_token(combined_call),
        empty_call,
    ];
    with_selector(transfer_with_fee_selector(), encode(&tokens))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Selectors are what the `/submit_raw` policy table is keyed on, so pin them.
    #[test]
    fn selectors_match_signatures() {
        assert_eq!(unshield_v2_selector(), selector(UNSHIELD_V2_SIG));
        assert_eq!(transfer_with_fee_selector(), selector(TRANSFER_WITH_FEE_SIG));
        assert_eq!(native_eth_unshield_selector(), selector(NATIVE_ETH_UNSHIELD_SIG));
        // must differ from the legacy 3-arg unshield the contract no longer exposes
        assert_ne!(
            unshield_v2_selector(),
            selector(b"unshield(uint256,address,(bytes,uint256[8]))")
        );
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
        let cd = encode_transfer_with_fee_calldata(&[0x44; 20], &empty_call(), &fee);
        assert_eq!(&cd[..4], &transfer_with_fee_selector());
        let body = &cd[4..];
        assert_eq!(&body[12..32], &[0x44u8; 20]);
        // two dynamic tuples → two distinct offsets
        let off_op = Uint::from_big_endian(&body[32..64]);
        let off_fee = Uint::from_big_endian(&body[64..96]);
        assert_ne!(off_op, off_fee);
        // the fee leg's distinguishing binding word must appear in the payload
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
        assert_eq!(&body[12..32], &[0x55u8; 20]);
        assert!(cd.windows(32).any(|w| w == [0xCDu8; 32]));

        // Walk to the fee tuple and read its `actions` length: it must be exactly 0.
        let off_fee = Uint::from_big_endian(&body[64..96]).as_usize();
        let fee_tuple = &body[off_fee..];
        let off_actions = Uint::from_big_endian(&fee_tuple[0..32]).as_usize();
        assert_eq!(
            Uint::from_big_endian(&fee_tuple[off_actions..off_actions + 32]),
            Uint::zero(),
            "the fee call's actions must be EMPTY bytes — that is the same-asset mode switch",
        );
    }
}
