/* PROOFWRIGHT — cryptographic core.
   Everything here is real Web Crypto. No mocks, no stubs, no server.
   SHA-256 digests · ECDSA P-256 signatures · Merkle inclusion proofs · hash-chained ledger. */

const enc = new TextEncoder();

/* ---------- encoding helpers ---------- */

export const toHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

export const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const unb64u = (s) => {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

/* Deterministic serialisation. Two parties must hash the exact same bytes or
   nothing downstream works, so key order is fixed recursively. */
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

/* ---------- digests ---------- */

export async function sha256(input) {
  const bytes = typeof input === 'string' ? enc.encode(input) : input;
  return toHex(await crypto.subtle.digest('SHA-256', bytes));
}

export const digestOf = (obj) => sha256(canonical(obj));

export async function digestFile(file) {
  return toHex(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()));
}

/* ---------- issuer identity (ECDSA P-256) ---------- */

export async function generateIssuerKeys() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
  return {
    publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
    privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey),
  };
}

const importPriv = (jwk) =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

const importPub = (jwk) =>
  crypto.subtle.importKey('jwk', { ...jwk, key_ops: ['verify'], d: undefined },
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);

export async function signPayload(privateJwk, payloadObj) {
  const key = await importPriv(privateJwk);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(canonical(payloadObj))
  );
  return b64u(sig);
}

export async function verifySignature(publicJwk, signatureB64, payloadObj) {
  try {
    const key = await importPub(publicJwk);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key,
      unb64u(signatureB64), enc.encode(canonical(payloadObj))
    );
  } catch {
    return false;
  }
}

/* A decentralised identifier derived from the key itself — it cannot be
   claimed by anyone who does not hold the matching private key. */
export async function deriveDid(publicJwk) {
  const fp = await sha256(canonical({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }));
  return { did: 'did:pw:' + fp.slice(0, 40), fingerprint: fp };
}

/* ---------- Merkle tree ----------
   Internal nodes hash the concatenated hex of their children. A lone node at
   the end of a layer is promoted by pairing it with itself. */

export async function buildMerkle(leafHashes) {
  if (!leafHashes.length) throw new Error('cannot build a Merkle tree with no leaves');
  const layers = [leafHashes.slice()];
  while (layers[layers.length - 1].length > 1) {
    const prev = layers[layers.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      const left = prev[i];
      const right = prev[i + 1] ?? prev[i];
      next.push(await sha256(left + right));
    }
    layers.push(next);
  }
  return { root: layers[layers.length - 1][0], layers };
}

export function merkleProof(layers, index) {
  const path = [];
  let idx = index;
  for (let d = 0; d < layers.length - 1; d++) {
    const layer = layers[d];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : (idx + 1 < layer.length ? idx + 1 : idx);
    path.push({ hash: layer[siblingIdx], side: isRight ? 'left' : 'right' });
    idx = Math.floor(idx / 2);
  }
  return path;
}

export async function verifyMerkleProof(leafHash, path, expectedRoot) {
  let acc = leafHash;
  for (const step of path) {
    acc = step.side === 'left' ? await sha256(step.hash + acc) : await sha256(acc + step.hash);
  }
  return { ok: acc === expectedRoot, computed: acc };
}

/* ---------- block header ---------- */

/* The header is the only thing that gets signed. Credential bodies never leave
   the holder's device — the ledger only ever sees a Merkle root. */
export const blockHeader = (b) => ({
  height: b.height,
  prevHash: b.prevHash,
  merkleRoot: b.merkleRoot,
  leafCount: b.leafCount,
  issuedAt: b.issuedAt,
  issuerDid: b.issuerDid,
});

export const hashBlock = (b) => digestOf(blockHeader(b));
