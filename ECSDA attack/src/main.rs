use p256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    AffinePoint, ProjectivePoint, Scalar, SecretKey,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use hex::ToHex;
use num_bigint::BigUint;

fn scalar_from_u128_reduced(k: &BigUint) -> Scalar {
    let mut bytes = [0u8; 32];
    let k_bytes = k.to_bytes_be();
    if k_bytes.len() <= 32 {
        bytes[32 - k_bytes.len()..].copy_from_slice(&k_bytes);
    } else {
        bytes.copy_from_slice(&k_bytes[k_bytes.len() - 32..]);
    }
    Scalar::from_be_bytes_reduced(bytes.into())
}

fn scalar_from_bytes_reduced(bytes: &[u8]) -> Scalar {
    let mut buf = [0u8; 32];
    if bytes.len() <= 32 {
        buf[32 - bytes.len()..].copy_from_slice(bytes);
    } else {
        buf.copy_from_slice(&bytes[bytes.len() - 32..]);
    }
    Scalar::from_be_bytes_reduced(buf.into())
}

fn main() {
    // --- Generate ECDSA P-256 private key (SecretKey)
    let secret = SecretKey::random(&mut OsRng);

    let scalar_d: Scalar = {
        let sk_bytes = secret.to_be_bytes();
        Scalar::from_be_bytes_reduced(sk_bytes.into())
    };

    let d_bytes = scalar_d.to_bytes();
    let d_hex = d_bytes.encode_hex::<String>();

    // --- Two messages
    let m1 = b"Message for ECDSA nonce reuse attack";
    let m2 = b"Another message for ECDSA nonce reuse attack";

    let h1_bytes = Sha256::digest(m1);
    let h2_bytes = Sha256::digest(m2);

    let h1 = scalar_from_bytes_reduced(&h1_bytes);
    let h2 = scalar_from_bytes_reduced(&h2_bytes);

    // --- Fixed nonce k
    let k_big = BigUint::parse_bytes(
        b"1234567890123456789012345678901234567890",
        10,
    )
    .expect("parse k");

    let k_scalar = scalar_from_u128_reduced(&k_big);

    // --- Compute R = k * G
    let generator = ProjectivePoint::GENERATOR;
    let r_point = generator * k_scalar;
    let r_affine = AffinePoint::from(r_point);

    // Extract X coordinate via SEC1 encoding
    let encoded = r_affine.to_encoded_point(true); // compressed
    let encoded_bytes = encoded.as_bytes();
    let rx_bytes: &[u8] = &encoded_bytes[1..33]; // skip the first byte (tag)
    let rx_hex = rx_bytes.encode_hex::<String>();

    let r_scalar = scalar_from_bytes_reduced(rx_bytes);
    let r_bytes = r_scalar.to_bytes();
    let r_hex = r_bytes.encode_hex::<String>();

    // --- Compute signatures
    let k_inv = k_scalar.invert().expect("k invertible");
    let rd = r_scalar * scalar_d;

    let s1 = k_inv * (h1 + rd);
    let s2 = k_inv * (h2 + rd);

    let s1_hex = s1.to_bytes().encode_hex::<String>();
    let s2_hex = s2.to_bytes().encode_hex::<String>();

    println!("Private scalar d (hex): {}", d_hex);
    println!("R.x (raw) hex:          {}", rx_hex);
    println!("r (reduced) hex:        {}", r_hex);
    println!("s1 hex:                 {}", s1_hex);
    println!("s2 hex:                 {}", s2_hex);

    // ================= Attack: recover k and d
    let num = h1 - h2;
    let den = s1 - s2;
    let den_inv = den.invert().expect("den invertible");
    let k_recovered = num * den_inv;

    let r_inv = r_scalar.invert().expect("r invertible");
    let d_recovered = (s1 * k_recovered - h1) * r_inv;

    println!("\nRecovered k (hex):    {}", k_recovered.to_bytes().encode_hex::<String>());
    println!("Original k reduced:   {}", k_scalar.to_bytes().encode_hex::<String>());

    println!("\nRecovered d (hex):    {}", d_recovered.to_bytes().encode_hex::<String>());
    println!("Actual d (hex):       {}", d_hex);

    println!("\nSUCCESS: {}", d_recovered.to_bytes() == d_bytes);
}
