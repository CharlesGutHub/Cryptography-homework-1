use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
use rand_core::OsRng;
use hex::encode as hex_encode;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

/// HKDF Extract
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).unwrap();
    mac.update(ikm);
    let result = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&result);
    prk
}

/// HKDF Expand (1 block)
fn hkdf_expand_single(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(info);
    input.push(0x01u8);

    let mut mac = HmacSha256::new_from_slice(prk).unwrap();
    mac.update(&input);
    let out = mac.finalize().into_bytes();
    let mut okm = [0u8; 32];
    okm.copy_from_slice(&out);
    okm
}

/// DeriveHS
fn derive_hs(gxy: &[u8]) -> [u8; 32] {
    let zeros = [0u8; 32];
    let es = hkdf_extract(&zeros, &zeros);
    let des = hkdf_expand_single(&es, &sha256_bytes(b"DerivedES"));
    hkdf_extract(&des, &sha256_bytes(gxy))
}

/// KeySchedule1
fn key_schedule_1(gxy: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hs = derive_hs(gxy);
    let k1c = hkdf_expand_single(&hs, &sha256_bytes(b"ClientKE"));
    let k1s = hkdf_expand_single(&hs, &sha256_bytes(b"ServerKE"));
    (k1c, k1s)
}

/// KeySchedule2
fn key_schedule_2(
    nc: &[u8],
    x: &[u8],
    ns: &[u8],
    y: &[u8],
    gxy: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let hs = derive_hs(gxy);

    let mut buf_c = Vec::new();
    buf_c.extend_from_slice(nc);
    buf_c.extend_from_slice(x);
    buf_c.extend_from_slice(ns);
    buf_c.extend_from_slice(y);
    buf_c.extend_from_slice(b"ClientKC");
    let client_kc = sha256_bytes(&buf_c);

    let mut buf_s = Vec::new();
    buf_s.extend_from_slice(nc);
    buf_s.extend_from_slice(x);
    buf_s.extend_from_slice(ns);
    buf_s.extend_from_slice(y);
    buf_s.extend_from_slice(b"ServerKC");
    let server_kc = sha256_bytes(&buf_s);

    let k2c = hkdf_expand_single(&hs, &client_kc);
    let k2s = hkdf_expand_single(&hs, &server_kc);
    (k2c, k2s)
}

/// KeySchedule3
fn key_schedule_3(
    nc: &[u8],
    x: &[u8],
    ns: &[u8],
    y: &[u8],
    gxy: &[u8],
    sigma: &[u8],
    cert_pks: &[u8],
    macs: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let hs = derive_hs(gxy);
    let dhs = hkdf_expand_single(&hs, &sha256_bytes(b"DerivedHS"));
    let zeros = [0u8; 32];
    let ms = hkdf_extract(&dhs, &zeros);

    let mut client_buf = Vec::new();
    client_buf.extend_from_slice(nc);
    client_buf.extend_from_slice(x);
    client_buf.extend_from_slice(ns);
    client_buf.extend_from_slice(y);
    client_buf.extend_from_slice(sigma);
    client_buf.extend_from_slice(cert_pks);
    client_buf.extend_from_slice(macs);
    client_buf.extend_from_slice(b"ClientEncK");
    let client_skh = sha256_bytes(&client_buf);

    let mut server_buf = Vec::new();
    server_buf.extend_from_slice(nc);
    server_buf.extend_from_slice(x);
    server_buf.extend_from_slice(ns);
    server_buf.extend_from_slice(y);
    server_buf.extend_from_slice(sigma);
    server_buf.extend_from_slice(cert_pks);
    server_buf.extend_from_slice(macs);
    server_buf.extend_from_slice(b"ServerEncK");
    let server_skh = sha256_bytes(&server_buf);

    let k3c = hkdf_expand_single(&ms, &client_skh);
    let k3s = hkdf_expand_single(&ms, &server_skh);

    (k3c, k3s)
}

/// Compute HMAC
fn compute_hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

fn main() {
    let gxy = b"example_gxy_value";
    let nonce_c = b"client_nonce_123";
    let nonce_s = b"server_nonce_456";
    let x = b"client_X";
    let y = b"server_Y";

    let (k1c, k1s) = key_schedule_1(gxy);
    println!("K1_C = {}", hex_encode(k1c));
    println!("K1_S = {}", hex_encode(k1s));

    let (k2c, k2s) = key_schedule_2(nonce_c, x, nonce_s, y, gxy);
    println!("K2_C = {}", hex_encode(k2c));
    println!("K2_S = {}", hex_encode(k2s));

    // Signing key
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let cert_pk_s = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    // Message to sign (the hash)
    let mut sign_msg = Vec::new();
    sign_msg.extend_from_slice(nonce_c);
    sign_msg.extend_from_slice(x);
    sign_msg.extend_from_slice(nonce_s);
    sign_msg.extend_from_slice(y);
    sign_msg.extend_from_slice(&cert_pk_s);

    let sign_msg_hash = sha256_bytes(&sign_msg);

    let sigma = signing_key.sign(&sign_msg_hash).to_vec();
    println!("sigma = {}", hex_encode(&sigma));

    // Build signature object from raw (r||s)
    let r = &sigma[..32];
    let s = &sigma[32..];
    let sig = Signature::from_scalars(*array_from_slice_32(r), *array_from_slice_32(s)).unwrap();

    let verified = verifying_key.verify(&sign_msg_hash, &sig).is_ok();
    println!("Signature verified? {}", verified);

    // MAC S
    let mut mac_input_s = Vec::new();
    mac_input_s.extend_from_slice(nonce_c);
    mac_input_s.extend_from_slice(x);
    mac_input_s.extend_from_slice(nonce_s);
    mac_input_s.extend_from_slice(y);
    mac_input_s.extend_from_slice(&sigma);
    mac_input_s.extend_from_slice(&cert_pk_s);
    mac_input_s.extend_from_slice(b"ServerMAC");

    let mac_s_hash = sha256_bytes(&mac_input_s);
    let mac_s = compute_hmac(&k2s, &mac_s_hash);
    println!("macS = {}", hex_encode(mac_s));

    let macs_equal = ConstantTimeEq::ct_eq(&mac_s[..], &compute_hmac(&k2s, &mac_s_hash)[..])
        .unwrap_u8() == 1;
    println!("macS matches? {}", macs_equal);

    let (k3c, k3s) =
        key_schedule_3(nonce_c, x, nonce_s, y, gxy, &sigma, &cert_pk_s, &mac_s);
    println!("K3_C = {}", hex_encode(k3c));
    println!("K3_S = {}", hex_encode(k3s));
}

/// Converts &[u8] of len 32 into &[u8;32]
fn array_from_slice_32(slice: &[u8]) -> &[u8; 32] {
    slice.try_into().expect("slice len must be 32")
}
