use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, OsRng}, Nonce};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}},
    EncodedPoint, PublicKey,
};
use rand_core::RngCore;
use sha2::Sha256;
use hex;
use std::io::{self, Write};

pub fn run() {
    // --- 1. ECDSA pour signatures ---
    let alice_sign = SigningKey::random(&mut OsRng);
    let bob_sign   = SigningKey::random(&mut OsRng);
    let alice_verify = VerifyingKey::from(&alice_sign);
    let bob_verify   = VerifyingKey::from(&bob_sign);

    // --- 2. Nonces pour les messages ---
    let mut nonce_a = [0u8; 32];
    let mut nonce_b = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_a);
    OsRng.fill_bytes(&mut nonce_b);

    // --- 3. Sérialisation des clés publiques pour le message ---
    let alice_pub_sig = alice_verify.to_encoded_point(false);
    let bob_pub_sig   = bob_verify.to_encoded_point(false);

    let mut message = Vec::new();
    message.extend_from_slice(&nonce_a);
    message.extend_from_slice(&nonce_b);
    message.extend_from_slice(alice_pub_sig.as_bytes());
    message.extend_from_slice(bob_pub_sig.as_bytes());

    // --- 4. Signatures et vérification ---
    let sig_b = bob_sign.sign(&message);
    bob_verify.verify(&message, &sig_b).unwrap();

    let sig_a = alice_sign.sign(&message);
    alice_verify.verify(&message, &sig_a).unwrap();

    // --- 5. ECDH pour clé partagée ---
    let alice_secret = EphemeralSecret::random(&mut OsRng);
    let bob_secret   = EphemeralSecret::random(&mut OsRng);

    let alice_pub_ecdh = PublicKey::from(&alice_secret);
    let bob_pub_ecdh   = PublicKey::from(&bob_secret);

    let alice_shared = alice_secret.diffie_hellman(&bob_pub_ecdh);
    let bob_shared   = bob_secret.diffie_hellman(&alice_pub_ecdh);

    // --- 6. HKDF pour dériver la clé AES-256 ---
    let hkdf_a = Hkdf::<Sha256>::new(None, alice_shared.raw_secret_bytes());
    let hkdf_b = Hkdf::<Sha256>::new(None, bob_shared.raw_secret_bytes());

    let mut sk_a_derived = [0u8; 32];
    let mut sk_b_derived = [0u8; 32];
    hkdf_a.expand(b"Alice->Bob", &mut sk_a_derived).unwrap();
    hkdf_b.expand(b"Alice->Bob", &mut sk_b_derived).unwrap();

    println!("Shared key Alice: {}", hex::encode(&sk_a_derived));
    println!("Shared key Bob  : {}", hex::encode(&sk_b_derived));

    // --- 7. AEAD AES-GCM ---
    let cipher_a = Aes256Gcm::new_from_slice(&sk_a_derived).unwrap();
    let cipher_b = Aes256Gcm::new_from_slice(&sk_b_derived).unwrap();

    let mut nonce_aead_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_aead_bytes);
    let nonce_aead = Nonce::from_slice(&nonce_aead_bytes);

    print!("Enter the message you want to send: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let data = input.trim().as_bytes();

    let ciphertext = cipher_a.encrypt(nonce_aead, data).unwrap();
    println!("Ciphertext sent by Alice: {}", hex::encode(&ciphertext));

    let plaintext = cipher_b.decrypt(nonce_aead, ciphertext.as_ref()).unwrap();
    println!("Decrypted message by Bob: {}", String::from_utf8(plaintext).unwrap());
}
