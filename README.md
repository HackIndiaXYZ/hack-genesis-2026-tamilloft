# Proofwright

**Tamper-evident academic credentials, verifiable offline, in the browser.**

Team **TamilLoft** · HACK GENESIS 2026 · CHRIST (Deemed to be University), Ghaziabad
Tracks: *Blockchain & Web3* · *Emerging Technology & Innovation* · *Open Innovation*

---

## The problem

India's degree-verification market exists because a certificate is just paper with a
signature on it. Employers pay third-party agencies ₹300–₹2000 per candidate to phone a
registrar's office and ask whether a document is real. The answer takes days to weeks, the
registrar is the single point of truth, and a compromised or careless records office
silently poisons every check downstream. Meanwhile a convincing forgery costs a few
hundred rupees and a decent printer.

The underlying failure is that **the document carries no evidence of its own integrity**.
Everything depends on asking the issuer, forever.

## The approach

Proofwright makes the credential itself provable.

A registrar seals a batch of credentials into a block. Every credential is hashed into a
Merkle leaf, the batch is committed under one Merkle root, the root goes into a block
header chained to the previous block, and the header is signed with the registrar's
ECDSA P-256 key. The registrar publishes **64 bytes** — the root and the hash — not the
student records.

Each student receives a *passport*: their credential, its Merkle inclusion proof, and the
signed anchor. Anyone can verify it with no network, no database and no phone call:

| # | Check | What it proves |
|---|-------|----------------|
| 1 | Credential digest | The body is byte-for-byte what was sealed |
| 2 | Merkle inclusion | That exact leaf was in the committed batch |
| 3 | Issuer signature | The registrar's key signed this block header |
| 4 | Issuer identity | The signing key derives the DID the credential names |
| 5 | Ledger anchor | A published block carries the same root |

Change one character of the grade and checks 1 and 2 fail while 3, 4 and 5 still pass —
which tells a verifier not just *that* something is wrong but *where*.

### Why a Merkle root rather than one record per transaction

Privacy and cost. The root commits to every credential without revealing any of them, and
an inclusion proof for one credential out of *n* is `log₂(n)` hashes — about 10 for a
cohort of a thousand. A university graduating 5,000 students a year anchors 64 bytes,
not 5,000 records.

### Where a public chain fits

The signed header is the only thing that needs an external anchor, and it is small enough
to write to any L2 for a few cents. That is the one step this prototype does not perform:
the chain here is local and append-only, which demonstrates the full data structure and
every verification path, but a self-hosted ledger cannot stop a registrar from rewriting
its own history. Publishing the header externally is what closes that gap, and it is a
deliberate next step rather than something the demo pretends to have.

### Sentinel

Cryptography proves a credential is *intact*. It cannot prove it is *honest* — a
compromised registrar can sign a fraudulent credential perfectly. Sentinel is a
deterministic rule engine over the issuance record: duplicate awards, future-dated
credentials, missing enrolment identifiers, non-monotonic block timestamps, anomalous
batch sizes. Every flag names the rule that raised it, because an auditor needs to be
able to argue with a finding. It is not a model and does not pretend to be one.

---

## Running it

No build step, no dependencies, no API keys, no backend.

```bash
git clone https://github.com/HackIndiaXYZ/hack-genesis-2026-tamilloft
cd hack-genesis-2026-tamilloft
python -m http.server 8080
```

Open <http://localhost:8080>. A static file server is required only because the app uses
ES modules; opening `index.html` directly over `file://` will be blocked by CORS.

### Demo path (90 seconds)

1. **Vault** → *Load demo cohort*. Generates an ECDSA P-256 keypair in the browser and
   queues 8 credentials. The private key never leaves the device.
2. **Issue** → *Seal batch into block*. Real Merkle root, real signature, 8 passports.
3. Click *verify →* on any passport. Five green checks.
4. **Tamper lab** → *Change the grade*. Watch checks 1 and 2 break while 3, 4 and 5 hold.
5. **Ledger** → *Tamper with a sealed record*, then *Run chain audit*. The audit
   re-derives every block and names the record that no longer matches its leaf.
6. **Sentinel** → the duplicate award in the cohort is flagged under `DUP-01`.

---

## What is actually real

Every cryptographic operation runs through the browser's native `crypto.subtle`. Nothing
is stubbed, mocked or faked — break a byte and the mathematics genuinely stops agreeing.

- **SHA-256** digests over canonically serialised JSON (recursively key-sorted, so two
  parties hash identical bytes)
- **ECDSA P-256** signatures over block headers
- **Merkle trees** with inclusion proofs, verified in both directions
- **Hash-chained blocks** — each header carries its predecessor's hash
- **Key-derived DIDs** — `did:pw:<sha256(jwk)[0:40]>`, which cannot be claimed without the
  matching private key

A test harness exercises the pipeline outside the browser, including Merkle proofs for
every batch size from 1 to 33 (the odd-node promotion path is where naive implementations
break), forged signatures, substituted issuer keys, swapped roots and altered bodies.

```bash
node test/pipeline.mjs
```

## Project layout

```
index.html          five views: Vault, Issue, Ledger, Verify, Sentinel
src/css/app.css     archival / notary aesthetic
src/js/core.js      SHA-256, ECDSA, canonical JSON, Merkle trees
src/js/ledger.js    issuance, sealing, verification, chain audit, Sentinel
test/pipeline.mjs   17 assertions over the cryptographic pipeline
```

## Honest limitations

- The ledger is `localStorage`, not a public chain. See *Where a public chain fits* above.
- There is no issuer registry, so a verifier confirms a key signed a credential and that
  the key derives the stated DID, but not that the DID belongs to a real university. That
  requires a published registry — a solved problem, and orthogonal to what is demonstrated
  here.
- Revocation is not implemented. The standard answer is a signed revocation list anchored
  the same way as issuance.
- Key custody is a browser keypair. A real registrar would use an HSM.

## Licence

MIT — see [LICENSE](LICENSE).
