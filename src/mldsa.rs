//! ML-DSA-65 (FIPS 204) — firme post-quantistiche, tramite il crate puro-Rust `fips204`.
//! Byte-compatibile con `@noble/post-quantum` sul client e con `pqcrypto` in Python.

use fips204::ml_dsa_65::{try_keygen, PrivateKey, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{SerDes, Signer, Verifier};
use sha3::{Digest, Sha3_256};

/// Verifica una firma ML-DSA-65 separata (contesto vuoto) su `msg`.
///
/// Ritorna `false` per qualunque motivo: hex malformato, lunghezze sbagliate, chiave non
/// valida, firma non valida. Non distingue i casi **di proposito**: chi verifica non deve
/// poter dedurre *perché* ha fallito.
pub fn verify_mldsa(pk_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_arr: [u8; PK_LEN] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; SIG_LEN] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk = match PublicKey::try_from_bytes(pk_arr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    pk.verify(msg, &sig_arr, &[])
}

/// Genera una coppia di chiavi ML-DSA-65: `(chiave_pubblica_hex, chiave_privata_hex)`.
pub fn keygen_hex() -> (String, String) {
    let (pk, sk) = try_keygen().expect("ml-dsa keygen");
    (hex::encode(pk.into_bytes()), hex::encode(sk.into_bytes()))
}

/// Firma `msg` (contesto vuoto) e ritorna la firma in hex. `None` se la chiave non è valida.
pub fn sign_mldsa(sk_hex: &str, msg: &[u8]) -> Option<String> {
    let sk_bytes = hex::decode(sk_hex).ok()?;
    let arr: [u8; SK_LEN] = sk_bytes.try_into().ok()?;
    let sk = PrivateKey::try_from_bytes(arr).ok()?;
    let sig = sk.try_sign(msg, &[]).ok()?;
    Some(hex::encode(sig))
}

/// Impronta di una chiave pubblica: SHA3-256 troncato a 16 byte, in maiuscolo.
/// È quella che l'utente confronta a voce o con il QR nella verifica reciproca.
pub fn fingerprint(pk_hex: &str) -> String {
    let pk = hex::decode(pk_hex).unwrap_or_default();
    let mut h = Sha3_256::new();
    h.update(&pk);
    let d = h.finalize();
    hex::encode(&d[..16]).to_uppercase()
}

/// SHA3-512 in hex. È l'hash usato per i blocchi della catena.
pub fn sha3_512_hex(data: &[u8]) -> String {
    use sha3::Sha3_512;
    let mut h = Sha3_512::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod prove {
    use super::*;

    #[test]
    fn firma_e_verifica() {
        let (pk, sk) = keygen_hex();
        let sig = sign_mldsa(&sk, b"messaggio").unwrap();
        assert!(verify_mldsa(&pk, b"messaggio", &sig));
    }

    #[test]
    fn un_bit_diverso_nel_messaggio_invalida_la_firma() {
        let (pk, sk) = keygen_hex();
        let sig = sign_mldsa(&sk, b"bonifico di 100").unwrap();
        assert!(!verify_mldsa(&pk, b"bonifico di 900", &sig));
    }

    #[test]
    fn firma_manomessa_rifiutata() {
        let (pk, sk) = keygen_hex();
        let sig = sign_mldsa(&sk, b"m").unwrap();
        let mut rotta = sig.clone().into_bytes();
        rotta[10] = if rotta[10] == b'a' { b'b' } else { b'a' };
        assert!(!verify_mldsa(&pk, b"m", &String::from_utf8(rotta).unwrap()));
    }

    #[test]
    fn chiave_di_un_altro_non_verifica() {
        let (_pk1, sk1) = keygen_hex();
        let (pk2, _sk2) = keygen_hex();
        let sig = sign_mldsa(&sk1, b"m").unwrap();
        assert!(!verify_mldsa(&pk2, b"m", &sig));
    }

    #[test]
    fn ingressi_malformati_non_vanno_in_panico() {
        assert!(!verify_mldsa("non-hex", b"m", "zz"));
        assert!(!verify_mldsa("", b"m", ""));
        assert!(!verify_mldsa("aabb", b"m", "ccdd"));
        assert!(sign_mldsa("non-hex", b"m").is_none());
        assert!(sign_mldsa("aabb", b"m").is_none());
    }

    #[test]
    fn lunghezze_fips204_categoria_3() {
        let (pk, sk) = keygen_hex();
        assert_eq!(pk.len(), PK_LEN * 2, "chiave pubblica: 1952 byte");
        assert_eq!(sk.len(), SK_LEN * 2, "chiave privata: 4032 byte");
        assert_eq!(
            sign_mldsa(&sk, b"m").unwrap().len(),
            SIG_LEN * 2,
            "firma: 3309 byte"
        );
    }

    #[test]
    fn impronta_stabile_e_maiuscola() {
        let f = fingerprint("00ff");
        assert_eq!(f.len(), 32);
        assert_eq!(f, f.to_uppercase());
        assert_eq!(
            f,
            fingerprint("00ff"),
            "la stessa chiave dà la stessa impronta"
        );
        assert_ne!(f, fingerprint("00fe"));
    }

    #[test]
    fn sha3_512_valore_noto() {
        // Vettore noto: SHA3-512 della stringa vuota.
        assert_eq!(
            sha3_512_hex(b""),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }
}
