/* PROOFWRIGHT — ledger & verification pipeline.
   The ledger is an append-only chain of signed block headers. Each block
   commits to a batch of credentials through one Merkle root, so a registrar
   publishes 64 bytes instead of 64 student records. */

import {
  digestOf, sha256, buildMerkle, merkleProof, verifyMerkleProof,
  signPayload, verifySignature, blockHeader, hashBlock, deriveDid,
} from './core.js';

const KEY = 'proofwright.v1';
const GENESIS = '0'.repeat(64);

const blank = () => ({ issuer: null, chain: [], pending: [], issuedIndex: {} });

export function load() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? { ...blank(), ...JSON.parse(raw) } : blank();
  } catch {
    return blank();
  }
}

export function save(state) {
  localStorage.setItem(KEY, JSON.stringify(state));
}

export function reset() {
  localStorage.removeItem(KEY);
}

/* ---------- issuing ---------- */

let seq = 0;
export function credentialId() {
  seq = (seq + 1) % 4096;
  const stamp = Date.now().toString(36).toUpperCase();
  const salt = ((Math.random() * 0xffff) | 0).toString(36).toUpperCase().padStart(3, '0');
  return 'PW-' + stamp + '-' + salt + seq.toString(36).toUpperCase();
}

/* A credential is plain, readable data. Its integrity comes from the leaf
   digest, not from hiding anything. */
export function buildCredential(f) {
  const c = {
    v: 1,
    id: credentialId(),
    kind: f.kind,
    holder: f.holder,
    identifier: f.identifier,
    programme: f.programme,
    awarded: f.awarded,
    issuer: { name: f.issuerName, did: f.issuerDid },
    issuedAt: new Date().toISOString(),
  };
  if (f.grade) c.grade = f.grade;
  if (f.fileDigest) c.attachment = { name: f.fileName, sha256: f.fileDigest };
  return c;
}

/* Seal the pending batch into a block: Merkle-commit it, chain it to the tip,
   sign the header, and hand every credential back its inclusion proof. */
export async function sealBatch(state) {
  if (!state.pending.length) throw new Error('nothing pending to seal');
  if (!state.issuer) throw new Error('no issuer key in this vault');

  const leaves = [];
  for (const c of state.pending) leaves.push(await digestOf(c));

  const built = await buildMerkle(leaves);
  const tip = state.chain[state.chain.length - 1];

  const block = {
    height: state.chain.length,
    prevHash: tip ? tip.hash : GENESIS,
    merkleRoot: built.root,
    leafCount: leaves.length,
    issuedAt: new Date().toISOString(),
    issuerDid: state.issuer.did,
  };
  block.hash = await hashBlock(block);
  block.signature = await signPayload(state.issuer.privateJwk, blockHeader(block));
  block.leaves = leaves;
  block.records = state.pending.slice();

  const passports = [];
  for (let i = 0; i < state.pending.length; i++) {
    passports.push({
      format: 'proofwright/passport@1',
      credential: state.pending[i],
      leafHash: leaves[i],
      proof: merkleProof(built.layers, i),
      anchor: {
        height: block.height,
        merkleRoot: block.merkleRoot,
        blockHash: block.hash,
        signature: block.signature,
        prevHash: block.prevHash,
        leafCount: block.leafCount,
        issuedAt: block.issuedAt,
        issuerDid: block.issuerDid,
      },
      issuerKey: state.issuer.publicJwk,
    });
    state.issuedIndex[state.pending[i].id] = block.height;
  }

  state.chain.push(block);
  state.pending = [];
  save(state);
  return { block, passports };
}

/* ---------- verification ----------
   Five independent checks. A holder can run these with nothing but the
   passport file — no network, no issuer, no database lookup. */

export async function verifyPassport(passport, opts) {
  const chain = opts && opts.chain ? opts.chain : null;
  const file = opts && opts.file ? opts.file : null;
  const steps = [];
  const add = (label, ok, detail) => steps.push({ label, ok, detail });

  if (!passport || passport.format !== 'proofwright/passport@1') {
    add('Passport envelope', false, 'Not a PROOFWRIGHT passport document.');
    return { ok: false, steps };
  }

  const credential = passport.credential;
  const anchor = passport.anchor;
  const issuerKey = passport.issuerKey;

  /* 1 — the credential body still hashes to the leaf it was sealed as */
  const recomputed = await digestOf(credential);
  const bodyOk = recomputed === passport.leafHash;
  add('Credential digest', bodyOk,
    bodyOk
      ? 'Body hashes to ' + recomputed.slice(0, 24) + '…'
      : 'Sealed as ' + passport.leafHash.slice(0, 16) + '… but the body now hashes to ' + recomputed.slice(0, 16) + '…');

  /* 2 — the inclusion proof climbs from that leaf to the committed root */
  const mk = await verifyMerkleProof(recomputed, passport.proof, anchor.merkleRoot);
  add('Merkle inclusion', mk.ok,
    mk.ok
      ? passport.proof.length + ' sibling hashes resolve to the anchored root.'
      : 'Path resolves to ' + mk.computed.slice(0, 16) + '…, not the anchored root.');

  /* 3 — the header was signed by the key the passport carries */
  const header = {
    height: anchor.height, prevHash: anchor.prevHash, merkleRoot: anchor.merkleRoot,
    leafCount: anchor.leafCount, issuedAt: anchor.issuedAt, issuerDid: anchor.issuerDid,
  };
  const sigOk = await verifySignature(issuerKey, anchor.signature, header);
  add('Issuer signature', sigOk,
    sigOk ? 'ECDSA P-256 signature over the block header is valid.'
          : 'Signature does not verify against the supplied key.');

  /* 4 — that key actually owns the DID it claims */
  const derived = await deriveDid(issuerKey);
  const didOk = derived.did === anchor.issuerDid && derived.did === credential.issuer.did;
  add('Issuer identity', didOk,
    didOk ? 'Key fingerprint derives ' + derived.did
          : 'The signing key does not derive the DID named in this credential.');

  /* 5 — optional: the ledger we hold agrees */
  if (chain) {
    const block = chain[anchor.height];
    const match = !!block && block.hash === anchor.blockHash && block.merkleRoot === anchor.merkleRoot;
    add('Ledger anchor', match,
      match ? 'Block #' + anchor.height + ' on this ledger carries the same root.'
            : 'No block at height ' + anchor.height + ' on this ledger matches the anchor.');
  } else {
    add('Ledger anchor', true, 'Offline check — verified against the passport anchor alone.');
  }

  /* and the attached document, if the verifier supplied it */
  if (credential.attachment) {
    if (file) {
      const fd = await sha256(new Uint8Array(await file.arrayBuffer()));
      const fileOk = fd === credential.attachment.sha256;
      add('Attached document', fileOk,
        fileOk ? file.name + ' matches the bound digest.'
               : 'The supplied file is not the document that was sealed.');
    } else {
      add('Attached document', null,
        'This credential binds "' + credential.attachment.name + '". Attach it to check the bytes.');
    }
  }

  return { ok: steps.every((s) => s.ok !== false), steps };
}

/* ---------- chain audit ----------
   Walks the whole chain re-deriving every link. Catches a record edited
   directly in storage, which is exactly how insider fraud looks. */

export async function auditChain(chain) {
  const rows = [];
  let prev = GENESIS;
  for (const b of chain) {
    const issues = [];
    if (b.prevHash !== prev) issues.push('breaks the chain link');
    if ((await hashBlock(b)) !== b.hash) issues.push('header hash does not match contents');
    if (b.leaves) {
      const built = await buildMerkle(b.leaves);
      if (built.root !== b.merkleRoot) issues.push('Merkle root does not cover its leaves');
    }
    if (b.records && b.leaves) {
      for (let i = 0; i < b.records.length; i++) {
        if ((await digestOf(b.records[i])) !== b.leaves[i]) {
          issues.push('record ' + b.records[i].id + ' no longer matches its leaf');
        }
      }
    }
    rows.push({ height: b.height, hash: b.hash, issues, ok: !issues.length });
    prev = b.hash;
  }
  return rows;
}

/* ---------- Sentinel ----------
   A deterministic rule engine, not a language model: every flag it raises can
   be traced to a stated rule, which is what an auditor actually needs. */

export function sentinel(state) {
  const flags = [];
  const all = state.chain.flatMap((b) => b.records || []).concat(state.pending);

  /* Keyed case-insensitively so "aditi raghavan" and "Aditi Raghavan" collide,
     but the first spelling seen is what gets reported back. */
  const byHolder = new Map();
  for (const c of all) {
    const k = (c.holder || '').toLowerCase() + '|' + (c.programme || '').toLowerCase();
    const hit = byHolder.get(k);
    if (hit) hit.n++;
    else byHolder.set(k, { n: 1, holder: c.holder, programme: c.programme });
  }
  for (const { n, holder, programme } of byHolder.values()) {
    if (n > 1) {
      flags.push({ level: 'high', rule: 'DUP-01',
        text: n + ' separate credentials award ' + programme + ' to ' + holder + '.' });
    }
  }

  const now = Date.now();
  for (const c of all) {
    if (c.awarded && Date.parse(c.awarded) > now) {
      flags.push({ level: 'high', rule: 'TIME-01', text: c.id + ' is dated in the future (' + c.awarded + ').' });
    }
    if (c.holder && c.holder.trim().length < 3) {
      flags.push({ level: 'medium', rule: 'FIELD-01', text: c.id + ' has an implausibly short holder name.' });
    }
    if (!c.identifier) {
      flags.push({ level: 'medium', rule: 'FIELD-02', text: c.id + ' carries no enrolment identifier.' });
    }
  }

  if (state.pending.length > 40) {
    flags.push({ level: 'low', rule: 'BATCH-01',
      text: state.pending.length + ' credentials queued — unusually large for a single seal.' });
  }

  for (let i = 1; i < state.chain.length; i++) {
    const dt = Date.parse(state.chain[i].issuedAt) - Date.parse(state.chain[i - 1].issuedAt);
    if (dt < 0) {
      flags.push({ level: 'high', rule: 'TIME-02',
        text: 'Block #' + i + ' is timestamped before the block it follows.' });
    }
  }

  return flags;
}

export const RULES = [
  ['DUP-01', 'Same holder awarded the same programme more than once'],
  ['TIME-01', 'Award date falls in the future'],
  ['TIME-02', 'A block is timestamped before its predecessor'],
  ['FIELD-01', 'Holder name too short to be a real name'],
  ['FIELD-02', 'Credential carries no enrolment identifier'],
  ['BATCH-01', 'Pending batch unusually large for one seal'],
];
