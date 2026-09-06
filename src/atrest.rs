//! Cifratura delle chiavi private **a riposo** — AES-256-GCM.
//! Formato archiviato: `enc:v1:<nonce_hex>:<ct_hex>`.
//!
//! Nel nodo la chiave a 32 byte arriva da `KEYSTORE_ENC_KEY`; qui arriva come parametro,
//! perché una libreria che legge l'ambiente non si può provare.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

/// Interpreta una chiave a 32 byte scritta in hex (64 caratteri). Le copie intermedie
/// vengono azzerate: senza questo, la chiave resta nello heap fino al riuso della memoria
/// e un core dump la contiene in chiaro (era il difetto C-01 dell'audit v5.2).
pub fn key_from_hex(hex_key: &str) -> Option<[u8; 32]> {
    let mut trimmed = hex_key.trim().to_string();
    let mut bytes = hex::decode(&trimmed).ok()?;
    let out: Option<[u8; 32]> = bytes.clone().try_into().ok();
    bytes.zeroize();
    trimmed.zeroize();
    out
}

/// Sigilla un segreto per l'archiviazione.
pub fn seal_secret(key: &[u8; 32], plain: &str) -> Result<String, String> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "chiave non valida".to_string())?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
        .map_err(|_| "cifratura fallita".to_string())?;
    Ok(format!("enc:v1:{}:{}", hex::encode(nonce), hex::encode(ct)))
}

/// Apre un segreto archiviato.
///
/// **Fail-closed**: se il valore è sigillato ma non apribile (chiave sbagliata, dato
/// manomesso, formato rotto) ritorna `Err`, mai il testo cifrato e mai una stringa a caso.
/// Un valore senza il prefisso `enc:v1:` è considerato testo in chiaro: è la migrazione
/// trasparente dagli archivi scritti prima che la cifratura esistesse.
pub fn open_secret(key: &[u8; 32], stored: &str) -> Result<String, String> {
    let rest = match stored.strip_prefix("enc:v1:") {
        Some(r) => r,
        None => return Ok(stored.to_string()),
    };
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "chiave non valida".to_string())?;
    let mut it = rest.splitn(2, ':');
    let nonce = match hex::decode(it.next().unwrap_or("")) {
        Ok(n) if n.len() == 12 => n,
        _ => return Err("nonce assente o di lunghezza sbagliata".into()),
    };
    let ct =
        hex::decode(it.next().unwrap_or("")).map_err(|_| "testo cifrato non hex".to_string())?;
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| "apertura fallita: chiave sbagliata o dato manomesso".to_string())?;
    String::from_utf8(pt).map_err(|_| "il testo aperto non è UTF-8".into())
}

/// Vero se il valore è sigillato (e quindi serve la chiave per leggerlo).
pub fn is_sealed(stored: &str) -> bool {
    stored.starts_with("enc:v1:")
}

#[cfg(test)]
mod prove {
    use super::*;
    const K: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    #[test]
    fn andata_e_ritorno() {
        let k = key_from_hex(K).unwrap();
        let sigillato = seal_secret(&k, "chiave-privata-hex").unwrap();
        assert!(is_sealed(&sigillato));
        assert!(
            !sigillato.contains("chiave-privata-hex"),
            "il chiaro non deve comparire"
        );
        assert_eq!(open_secret(&k, &sigillato).unwrap(), "chiave-privata-hex");
    }

    #[test]
    fn due_sigilli_dello_stesso_segreto_sono_diversi() {
        let k = key_from_hex(K).unwrap();
        assert_ne!(
            seal_secret(&k, "s").unwrap(),
            seal_secret(&k, "s").unwrap(),
            "nonce casuale: due cifrature identiche tradirebbero l'uguaglianza dei segreti"
        );
    }

    #[test]
    fn chiave_sbagliata_non_apre() {
        let k = key_from_hex(K).unwrap();
        let altra = key_from_hex(&"ab".repeat(32)).unwrap();
        let s = seal_secret(&k, "segreto").unwrap();
        assert!(open_secret(&altra, &s).is_err());
    }

    #[test]
    fn dato_manomesso_rifiutato() {
        let k = key_from_hex(K).unwrap();
        let s = seal_secret(&k, "segreto").unwrap();
        let mut b = s.into_bytes();
        let ultimo = b.len() - 1;
        b[ultimo] = if b[ultimo] == b'a' { b'b' } else { b'a' };
        assert!(
            open_secret(&k, &String::from_utf8(b).unwrap()).is_err(),
            "GCM deve accorgersene"
        );
    }

    #[test]
    fn valore_in_chiaro_passa_invariato() {
        let k = key_from_hex(K).unwrap();
        assert_eq!(open_secret(&k, "vecchio-valore").unwrap(), "vecchio-valore");
        assert!(!is_sealed("vecchio-valore"));
    }

    #[test]
    fn formati_rotti_danno_errore_non_panico() {
        let k = key_from_hex(K).unwrap();
        assert!(open_secret(&k, "enc:v1:").is_err());
        assert!(open_secret(&k, "enc:v1:zz:zz").is_err());
        assert!(open_secret(&k, "enc:v1:00112233:aabb").is_err());
        assert!(key_from_hex("troppo-corta").is_none());
        assert!(key_from_hex("aabb").is_none());
    }

    #[test]
    fn segreto_vuoto_resta_vuoto() {
        let k = key_from_hex(K).unwrap();
        assert_eq!(seal_secret(&k, "").unwrap(), "");
    }
}
