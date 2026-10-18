//! Integration tests for the CSR registration type script.
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{bytes::Bytes, core::{ScriptHashType, TransactionBuilder, TransactionView}, packed::*, prelude::*};
use ckb_testtool::context::Context;
use blake2b_ref::Blake2bBuilder;
use k256::ecdsa::SigningKey;

const MAX_CYCLES: u64 = 100_000_000;
const SIGHASH_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];

fn ckb_blake2b(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    for p in parts { h.update(p); }
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

fn key(n: u8) -> SigningKey {
    let mut s = [0u8; 32];
    s[31] = n;
    SigningKey::from_slice(&s).unwrap()
}

fn pubkey(k: &SigningKey) -> Vec<u8> {
    k.verifying_key().to_encoded_point(true).as_bytes().to_vec()
}

/// Registration cell data v1, signed with the P2P key for `net_name`.
fn registration(net: u8, mode: u8, endpoint: &str, svc: &SigningKey, p2p: &SigningKey, net_name: &str) -> Vec<u8> {
    let svc_pk = pubkey(svc);
    let msg = ckb_blake2b(&[b"CSR/v1/bind", &svc_pk, net_name.as_bytes()]);
    let (sig, recid) = p2p.sign_prehash_recoverable(&msg).unwrap();
    let mut d = vec![1u8, net, mode, 1];
    d.extend_from_slice(&svc_pk);
    d.extend_from_slice(&pubkey(p2p));
    d.extend_from_slice(&sig.to_bytes());
    d.push(recid.to_byte());
    d.extend_from_slice(&8115u16.to_le_bytes());
    d.extend_from_slice(&(endpoint.len() as u16).to_le_bytes());
    d.extend_from_slice(endpoint.as_bytes());
    d
}

fn sighash_lock(svc: &SigningKey) -> Script {
    let args = ckb_blake2b(&[&pubkey(svc)])[..20].to_vec();
    Script::new_builder()
        .code_hash(SIGHASH_CODE_HASH)
        .hash_type(ScriptHashType::Type)
        .args(Bytes::from(args))
        .build()
}

struct Env {
    context: Context,
    reg_type: Script,
    always: Script,
}

fn env(network_arg: u8) -> Env {
    let mut context = Context::default();
    let reg_op = context.deploy_cell_by_name("csr-registration");
    let always_op = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let reg_type = context.build_script(&reg_op, Bytes::from(vec![network_arg])).expect("script");
    let always = context.build_script(&always_op, Bytes::new()).expect("script");
    Env { context, reg_type, always }
}

fn funding_input(e: &mut Env) -> CellInput {
    let op = e.context.create_cell(
        CellOutput::new_builder().capacity(1_000_000_000_000u64).lock(e.always.clone()).build(),
        Bytes::new(),
    );
    CellInput::new_builder().previous_output(op).build()
}

fn reg_output(reg_type: &Script, lock: Script) -> CellOutput {
    CellOutput::new_builder()
        .capacity(50_000_000_000u64)
        .lock(lock)
        .type_(Some(reg_type.clone()))
        .build()
}

fn tx(context: &mut Context, inputs: Vec<CellInput>, outputs: Vec<(CellOutput, Vec<u8>)>) -> TransactionView {
    let (outs, datas): (Vec<_>, Vec<_>) = outputs.into_iter().unzip();
    let datas: Vec<Bytes> = datas.into_iter().map(Bytes::from).collect();
    let t = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outs)
        .outputs_data(datas.pack())
        .build();
    context.complete_tx(t)
}

fn assert_code(e: &Env, t: &TransactionView, code: i8) {
    let err = e.context.verify_tx(t, MAX_CYCLES).expect_err("transaction should fail");
    let text = err.to_string();
    assert!(text.contains(&format!("error code {}", code)) || text.contains(&format!("code {}", code)),
            "expected error code {code}, got: {text}");
}

#[test]
fn create_pull_registration() {
    let mut e = env(0);
    let (svc, p2p) = (key(22), key(33));
    let input = funding_input(&mut e);
    let data = registration(0, 0, "https://runner.example.org:8443", &svc, &p2p, "testnet");
    let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), data)]);
    let cycles = e.context.verify_tx(&t, MAX_CYCLES).expect("valid registration");
    println!("create_pull_registration cycles: {cycles}");
}

#[test]
fn create_push_registration() {
    let mut e = env(0);
    let (svc, p2p) = (key(22), key(33));
    let input = funding_input(&mut e);
    let data = registration(0, 1, "", &svc, &p2p, "testnet");
    let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), data)]);
    e.context.verify_tx(&t, MAX_CYCLES).expect("valid registration");
}

#[test]
fn lock_must_be_service_key_sighash() {
    let mut e = env(0);
    let (svc, p2p) = (key(22), key(33));
    let input = funding_input(&mut e);
    let data = registration(0, 0, "https://r.example", &svc, &p2p, "testnet");
    let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, sighash_lock(&key(99))), data.clone())]);
    assert_code(&e, &t, 23);
    let input = funding_input(&mut e);
    let always = e.always.clone();
    let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, always), data)]);
    assert_code(&e, &t, 23);
}

#[test]
fn bind_signature_must_verify() {
    let mut e = env(0);
    let (svc, p2p) = (key(22), key(33));
    let input = funding_input(&mut e);
    let mut data = registration(0, 0, "https://r.example", &svc, &p2p, "testnet");
    data[80] ^= 1;
    let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), data)]);
    assert_code(&e, &t, 22);
    // signed for mainnet but registered on testnet
    let input = funding_input(&mut e);
    let data = registration(0, 0, "https://r.example", &svc, &p2p, "mainnet");
    let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), data)]);
    assert_code(&e, &t, 22);
}

#[test]
fn network_must_match_type_args() {
    let mut e = env(1);
    let (svc, p2p) = (key(22), key(33));
    let input = funding_input(&mut e);
    let data = registration(0, 0, "https://r.example", &svc, &p2p, "testnet");
    let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), data)]);
    assert_code(&e, &t, 14);
}

#[test]
fn malformed_data_rejected() {
    let mut e = env(0);
    let (svc, p2p) = (key(22), key(33));
    let good = registration(0, 0, "https://r.example", &svc, &p2p, "testnet");
    let cases: Vec<(Vec<u8>, i8)> = vec![
        (good[..100].to_vec(), 11),
        ({ let mut d = good.clone(); d[0] = 2; d }, 12),
        ({ let mut d = good.clone(); d[3] = 3; d }, 16),
        ({ let mut d = good.clone(); d.push(b'x'); d }, 17),
        (registration(0, 0, "", &svc, &p2p, "testnet"), 19),
        (registration(0, 1, "https://x", &svc, &p2p, "testnet"), 20),
    ];
    for (data, code) in cases {
        let input = funding_input(&mut e);
        let t = tx(&mut e.context, vec![input], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), data)]);
        assert_code(&e, &t, code);
    }
}

#[test]
fn every_output_is_checked() {
    let mut e = env(0);
    let (svc, p2p) = (key(22), key(33));
    let input = funding_input(&mut e);
    let good = registration(0, 0, "https://r.example", &svc, &p2p, "testnet");
    let mut bad = good.clone();
    bad[0] = 9;
    let t = tx(&mut e.context, vec![input], vec![
        (reg_output(&e.reg_type, sighash_lock(&svc)), good),
        (reg_output(&e.reg_type, sighash_lock(&svc)), bad),
    ]);
    assert_code(&e, &t, 12);
}

#[test]
fn destroy_and_update() {
    let mut e = env(0);
    let (svc, p2p) = (key(22), key(33));
    let data = registration(0, 0, "https://r.example", &svc, &p2p, "testnet");
    // An existing registration cell. In these tests its lock is not executed
    // (the sighash code is not deployed), so only the type script is exercised.
    let reg_op = e.context.create_cell(reg_output(&e.reg_type, e.always.clone()), Bytes::from(data.clone()));
    let reg_in = CellInput::new_builder().previous_output(reg_op).build();
    let always = e.always.clone();
    let plain = CellOutput::new_builder().capacity(40_000_000_000u64).lock(always).build();
    let t = tx(&mut e.context, vec![reg_in.clone()], vec![(plain, vec![])]);
    e.context.verify_tx(&t, MAX_CYCLES).expect("destroying a registration is allowed");
    // update: new endpoint, still valid
    let moved = registration(0, 0, "https://moved.example", &svc, &p2p, "testnet");
    let t = tx(&mut e.context, vec![reg_in.clone()], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), moved)]);
    e.context.verify_tx(&t, MAX_CYCLES).expect("valid update");
    // update to something invalid
    let mut broken = data.clone();
    broken[3] = 2;
    let t = tx(&mut e.context, vec![reg_in], vec![(reg_output(&e.reg_type, sighash_lock(&svc)), broken)]);
    assert_code(&e, &t, 16);
}
