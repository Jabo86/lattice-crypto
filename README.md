# lattice-crypto

Le **primitive crittografiche del nodo Lattice**, estratte in una libreria Rust che si
compila e si prova da sola. Il resto del nodo resta chiuso; questa parte è aperta perché è
quella che risponde alla domanda che conta: *la crittografia fa davvero quello che dite?*

Sito: **https://lattice-network.it** · Client Android (anch'esso pubblico):
**https://github.com/Jabo86/lattice-android**

```bash
git clone https://github.com/Jabo86/lattice-crypto && cd lattice-crypto
cargo test
```

## Cosa c'è dentro

| modulo | cosa fa |
|---|---|
| `mldsa` | firme post-quantistiche **ML-DSA-65** (FIPS 204, categoria 3), impronte delle chiavi, SHA3-512 |
| `atrest` | cifratura delle chiavi private **a riposo** (AES-256-GCM, formato `enc:v1:`), con azzeramento delle copie in memoria |
| `envelope` | buste cifrate legate al loro contesto tramite **AAD** (AES-256-GCM, formato `v1:`) |
| `quorum` | soglie del consenso **QBFT**, messaggio canonico del blocco, conteggio dei voti con deduplica dei firmatari |

## Una differenza dichiarata rispetto al nodo

Nel nodo le chiavi arrivano da variabili d'ambiente (`KEYSTORE_ENC_KEY`,
`LATTICE_ENVELOPE_KEY`) e le soglie da `LATTICE_QBFT_QUORUM`. **Qui arrivano come
parametro**: una libreria che legge l'ambiente non è provabile, e un test che dipende
dall'ambiente non dimostra niente. Le funzioni, i formati e gli algoritmi sono gli stessi.

## Cosa NON c'è, e perché

- **Il ratchet delle conversazioni**: vive sul dispositivo, ed è pubblicato con il
  [client Android](https://github.com/Jabo86/lattice-android). Va letto là, perché è là che gira.
- **Chiavi, logica di rete, accesso al database, backend, validatori**: chiusi per scelta.
  Il nodo si distribuisce come immagine firmata, verificata per digest.
- Nessuna chiave di produzione è mai passata da questo repository.

## Cosa provano i test (`cargo test`)

Non sono test decorativi: ogni proprietà dichiarata ha una prova che la contraddirebbe se
fosse falsa.

- **Firme**: andata e ritorno; un bit diverso nel messaggio invalida la firma; firma
  manomessa rifiutata; la chiave di un altro non verifica; ingressi malformati non vanno in
  panico; lunghezze FIPS 204 (chiave pubblica 1952 B, privata 4032 B, firma 3309 B); vettore
  noto di SHA3-512.
- **A riposo**: il chiaro non compare nel sigillo; due sigilli dello stesso segreto sono
  **diversi** (nonce casuale: altrimenti si capirebbe che due segreti sono uguali); chiave
  sbagliata e dato manomesso danno errore, **mai** un risultato a caso; i valori scritti
  prima della cifratura passano invariati (migrazione trasparente).
- **Buste**: una busta spostata in **un altro contesto non si apre** (è l'AAD a impedirlo);
  manomissione rilevata; buste rotte danno errore e non panico.
- **Consenso**: `q(n) = ⌈2n/3⌉` verificata su 3000 valori; safety
  (`2q − n ≥ f + 1`) su 3000 valori; vivacità (`n − f ≥ q`) su 3000 valori; la
  configurazione non abbassa mai la soglia (8.200 combinazioni);
  **enumerazione esaustiva per n = 10: 856.800 controlli** (tutte le coppie di quorum × tutte
  le terne malevole) senza una sola intersezione di soli nodi malevoli; il messaggio canonico
  lega catena e altezza; i voti si contano **una volta per validatore**.

### Farle girare su una macchina che non è la nostra

In `ci/prove.yml` c'è il flusso GitHub Actions già pronto (compilazione, prove, `clippy`
senza avvisi, `cargo fmt --check`). Non è attivo: per creare un file dentro
`.github/workflows/` GitHub pretende un token con permesso `workflow`, e quel permesso non
lo abbiamo usato per pubblicare. Per attivarlo basta spostarlo:

```bash
mkdir -p .github/workflows && git mv ci/prove.yml .github/workflows/prove.yml
git commit -m "prove automatiche a ogni modifica" && git push
```

La dimostrazione matematica completa, con anche ciò che **non** è dimostrato, è pubblica:
**https://lattice-network.it/prova-qbft**

## Licenza in tre righe

Codice **aperto e verificabile, non open source** — la differenza la scriviamo perché conta.

- **Puoi**: leggerlo, studiarlo, sottoporlo ad audit, usarlo, modificarlo per te o per la tua
  organizzazione, compilarlo e provarlo.
- **Non puoi**: ridistribuirlo, rivenderlo o offrire un servizio basato su di esso. Per
  quello serve una licenza commerciale: **legal@lattice-network.it**
- **Dal 6 settembre 2030** ogni versione diventa automaticamente **GPL-3.0-or-later**.

Licenza: **Business Source License 1.1** ([`LICENSE`](LICENSE)).
Il nome e il logo Lattice **non** sono concessi con il codice: [`TRADEMARK.md`](TRADEMARK.md).
Nessuna garanzia: [`DISCLAIMER.md`](DISCLAIMER.md). Vulnerabilità: [`SECURITY.md`](SECURITY.md)
· **security@lattice-network.it** (niente segnalazioni pubbliche).

## Contributi

Repository in **sola lettura**: le pull request non vengono accettate, perché la titolarità
del codice deve restare integra per poterlo licenziare. Le segnalazioni sono benvenute nelle
issue; le vulnerabilità **no**, quelle via email.

---

© 2026 Fabio Astorino · BSL 1.1 · Change License GPL-3.0-or-later · Change Date 2030-09-06
