/* Exercises the real cryptographic pipeline outside the browser.
   Run with:  node test/pipeline.mjs  */
const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, v),
  removeItem: (k) => store.delete(k),
};
globalThis.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
globalThis.atob = (s) => Buffer.from(s, 'base64').toString('binary');

const core = await import('../src/js/core.js');
const L = await import('../src/js/ledger.js');

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  (ok ? pass++ : fail++);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
};

// known-answer test: SHA-256 of "abc"
t('sha256 known answer',
  (await core.sha256('abc')) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

// canonical JSON is key-order independent
t('canonical ordering',
  core.canonical({ b: 1, a: { d: 2, c: 3 } }) === core.canonical({ a: { c: 3, d: 2 }, b: 1 }));

// issuer identity
const keys = await core.generateIssuerKeys();
const id = await core.deriveDid(keys.publicJwk);
t('did derives from key', /^did:pw:[0-9a-f]{40}$/.test(id.did), id.did);

const sig = await core.signPayload(keys.privateJwk, { hello: 'world' });
t('signature verifies', await core.verifySignature(keys.publicJwk, sig, { hello: 'world' }));
t('signature rejects altered payload',
  !(await core.verifySignature(keys.publicJwk, sig, { hello: 'w0rld' })));

const other = await core.generateIssuerKeys();
t('signature rejects wrong key',
  !(await core.verifySignature(other.publicJwk, sig, { hello: 'world' })));

// Merkle over every batch size from 1..33 (exercises the odd-node path)
let merkleOk = true, badSize = null;
for (let n = 1; n <= 33; n++) {
  const leaves = [];
  for (let i = 0; i < n; i++) leaves.push(await core.sha256('leaf-' + n + '-' + i));
  const built = await core.buildMerkle(leaves);
  for (let i = 0; i < n; i++) {
    const proof = core.merkleProof(built.layers, i);
    const v = await core.verifyMerkleProof(leaves[i], proof, built.root);
    if (!v.ok) { merkleOk = false; badSize = `n=${n} i=${i}`; }
  }
  const forged = await core.verifyMerkleProof(
    await core.sha256('not-in-tree'), core.merkleProof(built.layers, 0), built.root);
  if (forged.ok) { merkleOk = false; badSize = `n=${n} accepted a forged leaf`; }
}
t('merkle proofs for batch sizes 1..33', merkleOk, badSize || '');

// full issue -> seal -> verify
const state = L.load();
state.issuer = { name: 'Test Registrar', publicJwk: keys.publicJwk, privateJwk: keys.privateJwk, did: id.did, fingerprint: id.fingerprint };
for (let i = 0; i < 7; i++) {
  state.pending.push(L.buildCredential({
    kind: 'Degree Certificate', holder: 'Student ' + i, identifier: 'ROLL' + i,
    programme: 'B.Tech CS', awarded: '2026-06-30', grade: '8.5',
    issuerName: state.issuer.name, issuerDid: state.issuer.did,
  }));
}
const sealed = await L.sealBatch(state);
t('batch sealed', state.chain.length === 1 && sealed.passports.length === 7);

const good = await L.verifyPassport(sealed.passports[3], { chain: state.chain });
t('genuine passport verifies', good.ok,
  good.steps.filter(s => s.ok === false).map(s => s.label).join(','));

// tamper the credential body
const t1 = JSON.parse(JSON.stringify(sealed.passports[3]));
t1.credential.grade = '10.00';
const r1 = await L.verifyPassport(t1, { chain: state.chain });
t('altered grade is rejected', !r1.ok && r1.steps[0].ok === false);

// tamper the root
const t2 = JSON.parse(JSON.stringify(sealed.passports[3]));
t2.anchor.merkleRoot = 'f'.repeat(64);
const r2 = await L.verifyPassport(t2, { chain: state.chain });
t('swapped merkle root is rejected', !r2.ok);

// forge the signature
const t3 = JSON.parse(JSON.stringify(sealed.passports[3]));
t3.anchor.signature = t3.anchor.signature.slice(0, -4) + 'AAAA';
const r3 = await L.verifyPassport(t3, { chain: state.chain });
t('forged signature is rejected', !r3.ok && r3.steps[2].ok === false);

// substitute a different issuer key
const t4 = JSON.parse(JSON.stringify(sealed.passports[3]));
t4.issuerKey = other.publicJwk;
const r4 = await L.verifyPassport(t4, { chain: state.chain });
t('substituted issuer key is rejected', !r4.ok);

// second block chains onto the first
state.pending.push(L.buildCredential({
  kind: 'Transcript', holder: 'Student X', identifier: 'ROLLX',
  programme: 'M.Sc', awarded: '2026-06-30', grade: '9',
  issuerName: state.issuer.name, issuerDid: state.issuer.did,
}));
const second = await L.sealBatch(state);
t('chain links', second.block.prevHash === sealed.block.hash);

let audit = await L.auditChain(state.chain);
t('clean chain audits clean', audit.every(r => r.ok),
  audit.flatMap(r => r.issues).join('; '));

// tamper a sealed record in place
state.chain[0].records[0].grade = '10.00';
audit = await L.auditChain(state.chain);
t('audit catches an edited sealed record', !audit[0].ok, audit[0].issues.join('; '));

// sentinel
state.chain[0].records[1].holder = state.chain[0].records[0].holder;
state.chain[0].records[1].programme = state.chain[0].records[0].programme;
const flags = L.sentinel(state);
t('sentinel flags a duplicate award', flags.some(f => f.rule === 'DUP-01'),
  flags.map(f => f.rule).join(','));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
