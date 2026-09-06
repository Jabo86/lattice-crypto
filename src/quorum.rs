//! Soglie del consenso QBFT e messaggio canonico del blocco.
//!
//! Le stesse funzioni del nodo, senza database e senza variabili d'ambiente. La
//! dimostrazione delle proprietà (intersezione dei quorum, accordo, vivacità condizionata)
//! è pubblica: <https://lattice-network.it/prova-qbft>.

/// Numero di firme distinte necessarie: `q(n) = ⌈2n/3⌉`, calcolato in interi come
/// `(2n+2)/3`. Con `n = 1` il quorum è 1 (nodo isolato: non c'è consenso da proteggere);
/// da due nodi in su **non può mai essere 1**.
pub fn quorum_for(n: i64) -> i64 {
    if n <= 0 {
        return 3;
    }
    if n == 1 {
        return 1;
    }
    let q = (2 * n + 2) / 3;
    if q < 2 {
        2
    } else {
        q
    }
}

/// Guasti tollerati: `f(n) = ⌊(n−1)/3⌋`.
pub fn faults_tolerated(n: i64) -> i64 {
    if n <= 0 {
        0
    } else {
        (n - 1) / 3
    }
}

/// Quorum applicato: `max(configurato, q(n))`. La configurazione può **alzare** l'asticella,
/// mai abbassarla: è il motivo per cui un errore di configurazione non degrada la sicurezza.
pub fn quorum_effective(n: i64, configured: i64) -> i64 {
    let min_safe = quorum_for(n);
    if configured > min_safe {
        configured
    } else {
        min_safe
    }
}

/// Nodi in comune fra due quorum qualsiasi: `2q − n`. Deve essere `≥ f + 1`, altrimenti
/// l'intersezione può essere composta di soli nodi malevoli e l'accordo non è dimostrabile.
pub fn intersection_size(n: i64) -> i64 {
    2 * quorum_for(n) - n
}

/// Vero se la soglia regge la safety per quel numero di validatori.
pub fn safety_holds(n: i64) -> bool {
    // Scritto come > f invece di >= f + 1: e la stessa cosa sugli interi.
    n <= 1 || intersection_size(n) > faults_tolerated(n)
}

/// Margine di vivacità: `n − f − q`. Se è 0, **tutti** i nodi onesti devono rispondere
/// (è il caso di `n = 10`, `q = 7`: tollera 3 guasti in totale, non 3 malevoli più un'assenza).
pub fn liveness_margin(n: i64) -> i64 {
    n - faults_tolerated(n) - quorum_for(n)
}

/// Il messaggio che ogni validatore firma. L'ordine dei campi è parte del protocollo:
/// `chain_id|index|timestamp|previous_hash|merkle_root|transactions_count|block_hash`.
///
/// `chain_id` dentro la firma dà separazione fra catene; `index` lega il voto a un'altezza:
/// una firma non si può riciclare né su un'altra catena né a un'altra altezza.
#[allow(clippy::too_many_arguments)]
pub fn block_canonical_message(
    chain_id: &str,
    index: i64,
    timestamp: &str,
    previous_hash: &str,
    merkle_root: &str,
    transactions_count: i64,
    block_hash: &str,
) -> Vec<u8> {
    [
        chain_id.to_string(),
        index.to_string(),
        timestamp.to_string(),
        previous_hash.to_string(),
        merkle_root.to_string(),
        transactions_count.to_string(),
        block_hash.to_string(),
    ]
    .join("|")
    .into_bytes()
}

/// Conta i voti validi su `msg`, **deduplicando per firmatario**: un nodo che risponde due
/// volte conta una volta. Senza questa deduplica il quorum si potrebbe raggiungere da soli.
///
/// `votes` è una sequenza di `(identificativo_validatore, chiave_pubblica_hex, firma_hex)`;
/// `registry` contiene gli identificativi ammessi.
pub fn count_valid_votes(
    msg: &[u8],
    votes: &[(String, String, String)],
    registry: &[String],
) -> usize {
    let mut visti: Vec<&str> = Vec::new();
    for (id, pk_hex, sig_hex) in votes {
        if id.is_empty() || visti.contains(&id.as_str()) {
            continue;
        }
        if !registry.iter().any(|r| r == id) {
            continue;
        }
        if crate::mldsa::verify_mldsa(pk_hex, msg, sig_hex) {
            visti.push(id);
        }
    }
    visti.len()
}

#[cfg(test)]
mod prove {
    use super::*;

    #[test]
    fn produzione_dieci_su_tre_sette() {
        assert_eq!(quorum_for(10), 7);
        assert_eq!(faults_tolerated(10), 3);
        assert_eq!(intersection_size(10), 4);
        assert_eq!(
            liveness_margin(10),
            0,
            "n=10 non ha margine: 3 guasti in totale"
        );
    }

    #[test]
    fn formula_uguale_al_soffitto_di_due_terzi() {
        for n in 2..=3000i64 {
            let atteso = (2 * n + 2) / 3; // ⌈2n/3⌉ in interi
            assert_eq!(quorum_for(n), atteso, "n = {n}");
        }
    }

    #[test]
    fn safety_per_ogni_numero_di_validatori() {
        for n in 1..=3000i64 {
            assert!(safety_holds(n), "intersezione insufficiente per n = {n}");
        }
    }

    #[test]
    fn vivacita_mai_impossibile() {
        for n in 2..=3000i64 {
            assert!(
                liveness_margin(n) >= 0,
                "quorum irraggiungibile dai soli onesti: n = {n}"
            );
        }
    }

    #[test]
    fn la_configurazione_non_abbassa_mai_la_soglia() {
        for n in 2..=200i64 {
            for cfg in 0..=40i64 {
                assert!(quorum_effective(n, cfg) >= quorum_for(n), "n={n} cfg={cfg}");
            }
        }
        assert_eq!(
            quorum_effective(10, 3),
            7,
            "un 3 in configurazione non abbassa il 7"
        );
        assert_eq!(
            quorum_effective(10, 9),
            9,
            "una soglia più alta viene rispettata"
        );
    }

    #[test]
    fn due_quorum_hanno_sempre_un_onesto_in_comune_n10() {
        // Enumerazione esaustiva: tutte le coppie di quorum × tutte le terne malevole.
        let n = 10usize;
        let sub = |k: usize| -> Vec<Vec<usize>> {
            let mut out = vec![];
            for m in 0u32..(1 << n) {
                if m.count_ones() as usize == k {
                    out.push((0..n).filter(|i| m & (1 << i) != 0).collect());
                }
            }
            out
        };
        let quorumi = sub(7);
        let malevoli = sub(3);
        assert_eq!(quorumi.len(), 120);
        assert_eq!(malevoli.len(), 120);
        let mut controlli = 0u64;
        for a in 0..quorumi.len() {
            for b in (a + 1)..quorumi.len() {
                let inter: Vec<usize> = quorumi[a]
                    .iter()
                    .cloned()
                    .filter(|x| quorumi[b].contains(x))
                    .collect();
                assert!(inter.len() >= 4);
                for m in &malevoli {
                    controlli += 1;
                    assert!(
                        inter.iter().any(|x| !m.contains(x)),
                        "esiste un'intersezione di soli nodi malevoli: impossibile per costruzione"
                    );
                }
            }
        }
        assert_eq!(controlli, 856_800);
    }

    #[test]
    fn messaggio_canonico_legato_a_catena_e_altezza() {
        let a = block_canonical_message("cat-a", 7, "t", "p", "m", 0, "h");
        assert_eq!(String::from_utf8(a.clone()).unwrap(), "cat-a|7|t|p|m|0|h");
        assert_ne!(
            a,
            block_canonical_message("cat-b", 7, "t", "p", "m", 0, "h"),
            "altra catena"
        );
        assert_ne!(
            a,
            block_canonical_message("cat-a", 8, "t", "p", "m", 0, "h"),
            "altra altezza"
        );
    }

    #[test]
    fn i_voti_si_contano_una_volta_per_validatore() {
        let msg = block_canonical_message("c", 1, "t", "p", "m", 0, "h");
        let (pk, sk) = crate::mldsa::keygen_hex();
        let sig = crate::mldsa::sign_mldsa(&sk, &msg).unwrap();
        let registro = vec!["VAL-01".to_string(), "VAL-02".to_string()];

        let doppio = vec![
            ("VAL-01".into(), pk.clone(), sig.clone()),
            ("VAL-01".into(), pk.clone(), sig.clone()),
        ];
        assert_eq!(
            count_valid_votes(&msg, &doppio, &registro),
            1,
            "no doppio voto"
        );

        let fuori_registro = vec![("VAL-99".into(), pk.clone(), sig.clone())];
        assert_eq!(count_valid_votes(&msg, &fuori_registro, &registro), 0);

        let firma_finta = vec![("VAL-02".into(), pk.clone(), "00".repeat(3309))];
        assert_eq!(count_valid_votes(&msg, &firma_finta, &registro), 0);

        let (pk2, sk2) = crate::mldsa::keygen_hex();
        let buoni = vec![
            ("VAL-01".into(), pk, sig),
            (
                "VAL-02".into(),
                pk2,
                crate::mldsa::sign_mldsa(&sk2, &msg).unwrap(),
            ),
        ];
        assert_eq!(count_valid_votes(&msg, &buoni, &registro), 2);
    }
}
