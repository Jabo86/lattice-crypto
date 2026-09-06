//! # lattice-crypto
//!
//! Le primitive crittografiche del nodo Lattice, estratte in una libreria che si compila e
//! si prova **da sola**. Non è una riscrittura per la vetrina: sono le stesse funzioni del
//! server (`crypto.rs`, `envelope.rs`, `chain.rs`), con una sola differenza dichiarata —
//! **le chiavi arrivano come parametro** invece di essere lette da variabili d'ambiente,
//! perché una libreria che legge l'ambiente non è provabile.
//!
//! Il resto del nodo resta chiuso, per scelta. Quello che qui è aperto è ciò che serve per
//! rispondere a una domanda scomoda: *la crittografia fa davvero quello che dite?*
//!
//! ## Cosa c'è
//!
//! | modulo | cosa fa |
//! |---|---|
//! | [`mldsa`] | firme post-quantistiche ML-DSA-65 (FIPS 204), impronte, SHA3-512 |
//! | [`atrest`] | cifratura delle chiavi private a riposo (AES-256-GCM, formato `enc:v1:`) |
//! | [`envelope`] | buste cifrate con dati autenticati aggiuntivi (AES-256-GCM, formato `v1:`) |
//! | [`quorum`] | soglie del consenso QBFT e messaggio canonico del blocco |
//!
//! ## Cosa NON c'è, e perché
//!
//! Non c'è il ratchet delle conversazioni, che vive **sul dispositivo** ed è pubblicato con
//! il client Android (<https://github.com/Jabo86/lattice-android>): è là che va letto, perché
//! è là che gira. Non ci sono chiavi, non c'è logica di rete, non c'è accesso al database.
//!
//! ## Compatibilità dichiarata
//!
//! I formati sono gli stessi che circolano in rete: firme e chiavi in **hex**, impronte
//! **SHA3-256 troncate a 16 byte in maiuscolo**, buste `v1:<base64(nonce‖ct)>`, segreti a
//! riposo `enc:v1:<nonce_hex>:<ct_hex>`. Una firma prodotta qui è verificabile dal client
//! Android (`@noble/post-quantum`) e viceversa: se un giorno non lo fosse, è un difetto
//! nostro e vogliamo saperlo — `security@lattice-network.it`.

pub mod atrest;
pub mod envelope;
pub mod mldsa;
pub mod quorum;

pub use mldsa::{fingerprint, keygen_hex, sha3_512_hex, sign_mldsa, verify_mldsa};
