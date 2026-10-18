//! Pure validation rules for CSR registration cells (v1).
//! No syscalls here: the same code runs in the contract and in native tests.

use blake2b_ref::Blake2bBuilder;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// Standard secp256k1/blake160 sighash lock (same on testnet and mainnet), hash_type = type.
pub const SIGHASH_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];
pub const HASH_TYPE_TYPE: u8 = 1;
pub const DOMAIN_BIND: &[u8] = b"CSR/v1/bind";
const FIXED_LEN: usize = 139;
/// secp256k1 group order / 2, big-endian.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(i8)]
pub enum Error {
    BadArgs = 10,
    TooShort = 11,
    BadVersion = 12,
    BadNetwork = 13,
    NetworkMismatch = 14,
    BadMode = 15,
    BadFlags = 16,
    BadLength = 17,
    BadEndpoint = 18,
    PullWithoutEndpoint = 19,
    PushWithEndpoint = 20,
    BadPubkey = 21,
    BadBindSignature = 22,
    WrongLock = 23,
}

/// What the contract needs to know about the lock of a registration output.
pub struct LockInfo<'a> {
    pub code_hash: &'a [u8],
    pub hash_type: u8,
    pub args: &'a [u8],
}

pub fn ckb_blake2b(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

fn network_name(id: u8) -> Option<&'static [u8]> {
    match id {
        0 => Some(b"testnet"),
        1 => Some(b"mainnet"),
        _ => None,
    }
}

fn valid_pubkey(pk: &[u8]) -> bool {
    pk.len() == 33 && (pk[0] == 2 || pk[0] == 3) && VerifyingKey::from_sec1_bytes(pk).is_ok()
}

/// Verify a 65-byte recoverable signature `r ‖ s ‖ recid` over `msg` by `pubkey` (low-s only).
pub fn verify_recoverable(pubkey: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    if sig.len() != 65 || sig[64] > 3 {
        return false;
    }
    if sig[32..64] > HALF_N[..] {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&sig[..64]) else { return false };
    let Some(recid) = RecoveryId::from_byte(sig[64]) else { return false };
    match VerifyingKey::recover_from_prehash(msg, &signature, recid) {
        Ok(vk) => vk.to_encoded_point(true).as_bytes() == pubkey,
        Err(_) => false,
    }
}

/// Validate one registration output: its data, the type args (network id) and its lock.
pub fn check_output(type_args: &[u8], data: &[u8], lock: &LockInfo) -> Result<(), Error> {
    if type_args.len() != 1 {
        return Err(Error::BadArgs);
    }
    let expected_net = type_args[0];
    let net_name = network_name(expected_net).ok_or(Error::BadArgs)?;
    if data.len() < FIXED_LEN {
        return Err(Error::TooShort);
    }
    if data[0] != 1 {
        return Err(Error::BadVersion);
    }
    if data[1] > 1 {
        return Err(Error::BadNetwork);
    }
    if data[1] != expected_net {
        return Err(Error::NetworkMismatch);
    }
    if data[2] > 1 {
        return Err(Error::BadMode);
    }
    if data[3] & !1 != 0 {
        return Err(Error::BadFlags);
    }
    let ep_len = u16::from_le_bytes([data[137], data[138]]) as usize;
    if data.len() != FIXED_LEN + ep_len {
        return Err(Error::BadLength);
    }
    let endpoint = &data[FIXED_LEN..];
    if core::str::from_utf8(endpoint).is_err() {
        return Err(Error::BadEndpoint);
    }
    let pull = data[2] == 0;
    if pull && endpoint.is_empty() {
        return Err(Error::PullWithoutEndpoint);
    }
    if !pull && !endpoint.is_empty() {
        return Err(Error::PushWithEndpoint);
    }
    let service_pk = &data[4..37];
    let p2p_pk = &data[37..70];
    let bind_sig = &data[70..135];
    if !valid_pubkey(service_pk) || !valid_pubkey(p2p_pk) {
        return Err(Error::BadPubkey);
    }
    let msg = ckb_blake2b(&[DOMAIN_BIND, service_pk, net_name]);
    if !verify_recoverable(p2p_pk, &msg, bind_sig) {
        return Err(Error::BadBindSignature);
    }
    let blake160 = &ckb_blake2b(&[service_pk])[..20];
    if lock.code_hash != SIGHASH_CODE_HASH || lock.hash_type != HASH_TYPE_TYPE || lock.args != blake160 {
        return Err(Error::WrongLock);
    }
    Ok(())
}
