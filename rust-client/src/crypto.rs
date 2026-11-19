//! Crypto primitives matching the Python reference implementation:
//! HKDF-SHA256 key derivation, AES-256-GCM payloads and HMAC-SHA256 requests.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

pub const ENC_INFO: &[u8] = b"vpn-poller-enc";
pub const HMAC_INFO: &[u8] = b"vpn-poller-hmac";
pub const NONCE_LEN: usize = 12;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct Keys {
    pub enc: [u8; 32],
    pub hmac: [u8; 32],
}

impl Keys {
    pub fn from_psk_b64(psk_b64: &str) -> Result<Self> {
        let psk = STANDARD
            .decode(psk_b64.trim())
            .context("PSK is not valid base64")?;
        Ok(Self {
            enc: derive(&psk, ENC_INFO)?,
            hmac: derive(&psk, HMAC_INFO)?,
        })
    }

    /// Per-user mode: the subscription secret is base64url and is used as
    /// raw PSK bytes (mirrors `base64.b64encode(secret)` on the Python side).
    pub fn from_user_secret(secret_b64url: &str) -> Result<Self> {
        let secret = b64u_decode(secret_b64url)?;
        Ok(Self {
            enc: derive(&secret, ENC_INFO)?,
            hmac: derive(&secret, HMAC_INFO)?,
        })
    }
}

fn derive(psk: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, psk);
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(out)
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("AES-GCM encryption cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        bail!("ciphertext too short");
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&blob[..NONCE_LEN]), &blob[NONCE_LEN..])
        .map_err(|_| anyhow::anyhow!("AES-GCM authentication failed"))
}

/// Lowercase hex HMAC-SHA256, the format the server expects in `X-Mac`.
pub fn sign(key: &[u8; 32], data: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    hex(&mac.finalize().into_bytes())
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn b64u_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64u_decode(s: &str) -> Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD
        .decode(s.trim())
        .context("invalid base64url value")?)
}

pub fn random_id() -> [u8; 16] {
    let mut out = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors generated with the Python implementation (crypto_utils.py)
    // using a synthetic PSK, not any deployed secret.
    const PSK: &str = "hK9u23BG0kZp4no3XtbOqFbS0m4pUtWro+wfK7wc7jA=";
    const ENC_KEY: &str = "cabc16d518cf287f895ad889d7fd09f85b573b369ffefed25c2fc9a492f59728";
    const HMAC_KEY: &str = "994cdb8d3224b5c42cc6ebdfbb9ae1f4a9465318a7564733fccd1aadc5fda634";
    const SIGN: &str = "8228288c80a04d35eddb820caf8657c67b81b0384fd633596eb802520e48bbd4";

    #[test]
    fn derives_same_keys_as_python() {
        let keys = Keys::from_psk_b64(PSK).unwrap();
        assert_eq!(hex(&keys.enc), ENC_KEY);
        assert_eq!(hex(&keys.hmac), HMAC_KEY);
    }

    #[test]
    fn signs_like_python() {
        let keys = Keys::from_psk_b64(PSK).unwrap();
        assert_eq!(sign(&keys.hmac, b"hello-world"), SIGN);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let keys = Keys::from_psk_b64(PSK).unwrap();
        let blob = encrypt(&keys.enc, b"payload");
        assert_eq!(decrypt(&keys.enc, &blob).unwrap(), b"payload");
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt(&keys.enc, &tampered).is_err());
    }

    #[test]
    fn base64url_roundtrip() {
        let raw = [0xfb, 0xff, 0x01, 0x02, 0x03];
        assert_eq!(b64u_decode(&b64u_encode(&raw)).unwrap(), raw);
    }
}
