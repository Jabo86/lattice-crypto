//! Buste cifrate con **dati autenticati aggiuntivi** (AAD) — AES-256-GCM.
//! Formato: `v1:<base64(nonce(12) ‖ ciphertext+tag)>`.
//!
//! L'AAD non viene cifrato ma **entra nel tag**: legare la busta al suo contesto
//! (identificativo del destinatario, della conversazione, dell'oggetto) impedisce di
//! spostare una busta valida in un posto dove significherebbe un'altra cosa.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;

/// Sigilla `plaintext` legandolo ad `aad`.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "cifratura fallita".to_string())?;
    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ct);
    Ok(format!("v1:{}", STANDARD.encode(&blob)))
}

/// Apre una busta, pretendendo lo stesso `aad` con cui è stata sigillata.
pub fn open(key: &[u8; 32], token: &str, aad: &[u8]) -> Result<Vec<u8>, String> {
    let (version, payload) = token
        .split_once(':')
        .ok_or_else(|| "la busta deve essere nella forma 'vN:...'".to_string())?;
    if version != "v1" {
        return Err(format!("versione di busta sconosciuta: {version}"));
    }
    let raw = STANDARD
        .decode(payload)
        .map_err(|_| "base64 non valido".to_string())?;
    if raw.len() < 12 {
        return Err("busta troppo corta".into());
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ct, aad })
        .map_err(|_| "apertura fallita: chiave o contesto sbagliati, oppure busta manomessa".into())
}

/// Come [`seal`], per testo.
pub fn seal_text(key: &[u8; 32], plaintext: &str, aad: &[u8]) -> Result<String, String> {
    seal(key, plaintext.as_bytes(), aad)
}

/// Come [`open`], per testo.
pub fn open_text(key: &[u8; 32], token: &str, aad: &[u8]) -> Result<String, String> {
    let bytes = open(key, token, aad)?;
    String::from_utf8(bytes).map_err(|_| "il testo aperto non è UTF-8".into())
}

#[cfg(test)]
mod prove {
    use super::*;
    fn k() -> [u8; 32] {
        crate::atrest::key_from_hex(&"3c".repeat(32)).unwrap()
    }

    #[test]
    fn andata_e_ritorno() {
        let t = seal_text(&k(), "ciao", b"conversazione:42").unwrap();
        assert!(t.starts_with("v1:"));
        assert_eq!(open_text(&k(), &t, b"conversazione:42").unwrap(), "ciao");
    }

    #[test]
    fn contesto_diverso_non_apre() {
        let t = seal_text(&k(), "ciao", b"conversazione:42").unwrap();
        assert!(
            open_text(&k(), &t, b"conversazione:43").is_err(),
            "una busta spostata in un altro contesto non deve aprirsi"
        );
    }

    #[test]
    fn testo_cifrato_manomesso_rifiutato() {
        let t = seal_text(&k(), "importo: 100", b"a").unwrap();
        let mut b = t.into_bytes();
        let i = b.len() - 2;
        b[i] = if b[i] == b'A' { b'B' } else { b'A' };
        assert!(open_text(&k(), &String::from_utf8(b).unwrap(), b"a").is_err());
    }

    #[test]
    fn buste_rotte_danno_errore_non_panico() {
        assert!(open(&k(), "senza-versione", b"").is_err());
        assert!(open(&k(), "v2:AAAA", b"").is_err());
        assert!(open(&k(), "v1:###", b"").is_err());
        assert!(open(&k(), "v1:AAAA", b"").is_err());
    }

    #[test]
    fn il_chiaro_non_compare_nella_busta() {
        let t = seal_text(&k(), "parola-segreta", b"").unwrap();
        assert!(!t.contains("parola-segreta"));
    }
}
