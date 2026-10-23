/* PROOFWRIGHT — interface wiring. */

import { generateIssuerKeys, deriveDid, digestFile } from './core.js';
import {
  load, save, reset, buildCredential, sealBatch,
  verifyPassport, auditChain, sentinel, RULES,
} from './ledger.js';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const short = (h, n = 14) => (h ? h.slice(0, n) + '…' + h.slice(-6) : '—');

let state = load();
let lastPassports = [];
let pendingFile = null;

/* ---------- chrome ---------- */

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

function go(view) {
  $$('.view').forEach((v) => v.classList.toggle('on', v.id === 'view-' + view));
  $$('#nav button').forEach((b) => b.setAttribute('aria-current', String(b.dataset.view === view)));
  if (view === 'ledger') renderChain();
  if (view === 'sentinel') renderFlags();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
$('#nav').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (b) go(b.dataset.view);
});

/* ---------- wax seal, engraved with the key fingerprint ---------- */

function renderSeal(fingerprint) {
  const text = fingerprint
    ? ('· ' + fingerprint.slice(0, 32).toUpperCase() + ' ').repeat(2)
    : '· NO SIGNING KEY IN THIS VAULT '.repeat(2);
  $('#sealwrap').innerHTML = `
    <svg class="seal" width="168" height="168" viewBox="0 0 200 200" aria-hidden="true">
      <defs>
        <path id="arc" d="M100,100 m-74,0 a74,74 0 1,1 148,0 a74,74 0 1,1 -148,0" fill="none"/>
        <radialGradient id="wax" cx="38%" cy="32%">
          <stop offset="0%" stop-color="#F27A52"/>
          <stop offset="62%" stop-color="#E4431F"/>
          <stop offset="100%" stop-color="#8E2410"/>
        </radialGradient>
      </defs>
      <circle cx="100" cy="100" r="88" fill="url(#wax)" opacity=".14"/>
      <circle cx="100" cy="100" r="72" fill="url(#wax)"/>
      <circle cx="100" cy="100" r="72" fill="none" stroke="#5E1708" stroke-width="2" opacity=".55"/>
      <circle cx="100" cy="100" r="58" fill="none" stroke="#2A0C04" stroke-width="1.6" stroke-dasharray="4 3" opacity=".6"/>
      <g class="ring">
        <text font-family="JetBrains Mono, monospace" font-size="7.4" fill="#2A0C04" letter-spacing="1.9" opacity=".82">
          <textPath href="#arc" startOffset="0">${esc(text)}</textPath>
        </text>
      </g>
      <path d="M100 74v52M78 100h44" stroke="#2A0C04" stroke-width="5" stroke-linecap="round" opacity=".85"/>
      <circle cx="100" cy="100" r="15" fill="none" stroke="#2A0C04" stroke-width="3.4" opacity=".85"/>
    </svg>`;
}

/* ---------- vault ---------- */

function renderVault() {
  const anchored = state.chain.reduce((n, b) => n + b.leafCount, 0);
  $('#sBlocks').textContent = state.chain.length;
  $('#sCreds').textContent = anchored;
  $('#sPending').textContent = state.pending.length;

  if (state.issuer) {
    $('#issuerName').textContent = state.issuer.name;
    $('#issuerDid').textContent = state.issuer.did;
    $('#initVault').disabled = true;
    $('#initVault').textContent = 'Issuing key present';
  }
  renderSeal(state.issuer ? state.issuer.fingerprint : null);

  const tip = state.chain[state.chain.length - 1];
  $('#tipKv').innerHTML = tip
    ? `<dt>height</dt><dd class="hl">#${tip.height}</dd>
       <dt>block hash</dt><dd>${esc(tip.hash)}</dd>
       <dt>merkle root</dt><dd class="hl">${esc(tip.merkleRoot)}</dd>
       <dt>prev</dt><dd>${esc(short(tip.prevHash, 20))}</dd>
       <dt>sealed</dt><dd>${esc(new Date(tip.issuedAt).toLocaleString())}</dd>
       <dt>leaves</dt><dd>${tip.leafCount}</dd>`
    : '<dt>state</dt><dd>empty ledger — nothing sealed yet</dd>';
}

async function initVault() {
  if (state.issuer) return;
  const keys = await generateIssuerKeys();
  const id = await deriveDid(keys.publicJwk);
  state.issuer = {
    name: 'CHRIST (Deemed to be University), Ghaziabad',
    publicJwk: keys.publicJwk,
    privateJwk: keys.privateJwk,
    did: id.did,
    fingerprint: id.fingerprint,
  };
  save(state);
  renderVault();
  toast('ECDSA P-256 keypair generated in this browser.');
}

$('#initVault').addEventListener('click', initVault);

$('#wipe').addEventListener('click', () => {
  reset();
  location.reload();
});

/* ---------- issuing ---------- */

$('input[name="doc"]').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) { pendingFile = null; $('#docHint').textContent = ''; return; }
  pendingFile = { name: f.name, digest: await digestFile(f) };
  $('#docHint').innerHTML = `sha256 <code>${esc(pendingFile.digest.slice(0, 18))}…</code>`;
});

$('#credForm').addEventListener('submit', (e) => {
  e.preventDefault();
  if (!state.issuer) return toast('Initialise an issuing key first (Vault).');
  const f = Object.fromEntries(new FormData(e.target));
  state.pending.push(buildCredential({
    kind: f.kind, holder: f.holder.trim(), identifier: f.identifier.trim(),
    programme: f.programme.trim(), awarded: f.awarded, grade: f.grade.trim(),
    issuerName: state.issuer.name, issuerDid: state.issuer.did,
    fileDigest: pendingFile ? pendingFile.digest : null,
    fileName: pendingFile ? pendingFile.name : null,
  }));
  save(state);
  e.target.reset();
  pendingFile = null;
  $('#docHint').textContent = '';
  renderQueue();
  renderVault();
});

function renderQueue() {
  const q = $('#queue');
  $('#pendTag').textContent = state.pending.length + ' queued';
  $('#sealBtn').disabled = !state.pending.length;
  if (!state.pending.length) {
    q.innerHTML = '<div class="empty">Nothing queued. Add a credential or load the demo cohort.</div>';
    return;
  }
  q.innerHTML = state.pending.map((c, i) => `
    <div class="qrow">
      <div>
        <div class="nm">${esc(c.holder)}</div>
        <div class="sub">${esc(c.identifier)} · ${esc(c.programme)}${c.attachment ? ' · 📎' : ''}</div>
      </div>
      <button class="btn ghost sp" data-drop="${i}">remove</button>
    </div>`).join('');
}

$('#queue').addEventListener('click', (e) => {
  const b = e.target.closest('[data-drop]');
  if (!b) return;
  state.pending.splice(+b.dataset.drop, 1);
  save(state);
  renderQueue();
  renderVault();
});

$('#clearQueue').addEventListener('click', () => {
  state.pending = [];
  save(state);
  renderQueue();
  renderVault();
});

$('#sealBtn').addEventListener('click', async () => {
  try {
    const out = await sealBatch(state);
    lastPassports = out.passports;
    renderQueue();
    renderVault();
    renderPassports(out.block, out.passports);
    toast(`Block #${out.block.height} sealed and signed.`);
  } catch (err) {
    toast(err.message);
  }
});

function renderPassports(block, passports) {
  $('#passportOut').innerHTML = `
    <div class="panel">
      <h3>Block #${block.height} sealed — ${passports.length} passport${passports.length > 1 ? 's' : ''} issued</h3>
      <dl class="kv" style="margin-bottom:16px">
        <dt>merkle root</dt><dd class="hl">${esc(block.merkleRoot)}</dd>
        <dt>block hash</dt><dd>${esc(block.hash)}</dd>
        <dt>signature</dt><dd>${esc(short(block.signature, 40))}</dd>
      </dl>
      <div class="queue">
        ${passports.map((p, i) => `
          <div class="qrow">
            <div>
              <div class="nm">${esc(p.credential.holder)}</div>
              <div class="sub">${esc(p.credential.id)} · proof depth ${p.proof.length}</div>
            </div>
            <div class="sp btns">
              <button class="btn ghost" data-copy="${i}">copy</button>
              <button class="btn ghost" data-save="${i}">download</button>
              <button class="btn" data-check="${i}">verify →</button>
            </div>
          </div>`).join('')}
      </div>
    </div>`;
}

$('#passportOut').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-copy],[data-save],[data-check]');
  if (!btn) return;
  const d = btn.dataset;
  const p = lastPassports[+(d.copy ?? d.save ?? d.check)];
  const json = JSON.stringify(p, null, 2);

  if (d.copy !== undefined) {
    navigator.clipboard.writeText(json).then(() => toast('Passport copied.'));
  } else if (d.save !== undefined) {
    const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = p.credential.id + '.passport.json';
    a.click();
    URL.revokeObjectURL(url);
  } else {
    $('#passportIn').value = json;
    go('verify');
    runVerify();
  }
});

/* ---------- demo cohort ---------- */

const COHORT = [
  ['Aditi Raghavan',  '22BCA1047', 'B.C.A. Data Science',            '8.74'],
  ['Rohan Mehta',     '22BTE0912', 'B.Tech. Computer Science',       '9.11'],
  ['Fathima Noor',    '22BBA2210', 'B.B.A. Finance & Analytics',     '8.32'],
  ['Kabir Sethi',     '22BSC0448', 'B.Sc. Artificial Intelligence',  '9.46'],
  ['Meera Pillai',    '22BCA1103', 'B.C.A. Data Science',            '7.98'],
  ['Devansh Arora',   '22BTE0877', 'B.Tech. Computer Science',       '8.05'],
  ['Sanya Qureshi',   '22MSC0031', 'M.Sc. Cyber Security',           '9.22'],
  /* A second certificate for a student who already has one, with a better
     grade on it. Signed just as validly as the rest — which is the point
     Sentinel exists to make. */
  ['Aditi Raghavan',  '22BCA1047', 'B.C.A. Data Science',            '9.80'],
];

$('#seedDemo').addEventListener('click', async () => {
  await initVault();
  /* Replace rather than append — loading the cohort twice would otherwise
     stack it and make Sentinel's duplicate flags meaningless. */
  state.pending = [];
  for (const [holder, identifier, programme, grade] of COHORT) {
    state.pending.push(buildCredential({
      kind: 'Degree Certificate', holder, identifier, programme,
      awarded: '2026-06-30', grade,
      issuerName: state.issuer.name, issuerDid: state.issuer.did,
    }));
  }
  save(state);
  renderQueue();
  renderVault();
  go('issue');
  toast(`${COHORT.length} credentials queued. Seal the batch.`);
});

/* ---------- ledger ---------- */

function renderChain() {
  const out = $('#chainOut');
  if (!state.chain.length) {
    out.innerHTML = '<div class="empty">No blocks sealed yet.</div>';
    return;
  }
  out.innerHTML = state.chain.slice().reverse().map((b) => `
    <div class="block" data-h="${b.height}">
      <div class="h">${b.height}<span>block</span></div>
      <dl class="kv">
        <dt>merkle root</dt><dd class="hl">${esc(b.merkleRoot)}</dd>
        <dt>block hash</dt><dd>${esc(b.hash)}</dd>
        <dt>prev hash</dt><dd>${esc(b.prevHash)}</dd>
        <dt>signature</dt><dd>${esc(short(b.signature, 44))}</dd>
        <dt>leaves</dt><dd>${b.leafCount} credential${b.leafCount > 1 ? 's' : ''}</dd>
        <dt>sealed</dt><dd>${esc(new Date(b.issuedAt).toLocaleString())}</dd>
      </dl>
    </div>`).join('');
}

$('#auditBtn').addEventListener('click', async () => {
  if (!state.chain.length) return toast('Nothing to audit — seal a batch first.');
  const rows = await auditChain(state.chain);
  const broken = rows.filter((r) => !r.ok);
  $('#auditOut').innerHTML = `
    <div class="verdict ${broken.length ? 'fail' : 'pass'}">
      <div class="big">${broken.length ? '✕' : '✓'}</div>
      <div>
        <div style="font-weight:600">${broken.length
          ? `${broken.length} of ${rows.length} blocks fail re-derivation`
          : `All ${rows.length} blocks re-derive cleanly`}</div>
        <div class="sub">${broken.length
          ? 'Each listed block was altered after it was sealed.'
          : 'Every header hash, chain link and Merkle root was recomputed from the stored contents.'}</div>
      </div>
    </div>
    ${broken.length ? `<div class="panel" style="margin-bottom:18px"><h3>Broken blocks</h3>${broken.map((r) => `
      <div class="flag"><span class="lv high">block ${r.height}</span>
      <div class="txt">${r.issues.map(esc).join(' · ')}</div></div>`).join('')}</div>` : ''}`;
  renderChain();
  $$('.block').forEach((el) => {
    const row = rows[+el.dataset.h];
    el.classList.toggle('bad', !!row && !row.ok);
  });
});

$('#tamperBtn').addEventListener('click', () => {
  const b = state.chain.find((x) => x.records && x.records.length);
  if (!b) return toast('Seal a batch first, then tamper with it.');
  const victim = b.records[0];
  victim.grade = '10.00';
  victim.holder = victim.holder + ' (altered)';
  save(state);
  renderChain();
  toast(`Record ${victim.id} edited directly in storage. Run the audit.`);
});

/* ---------- verify ---------- */

async function runVerify() {
  let passport;
  try {
    passport = JSON.parse($('#passportIn').value);
  } catch {
    $('#verifyOut').innerHTML = '<div class="verdict fail"><div class="big">✕</div><div><div style="font-weight:600">Not valid JSON</div><div class="sub">Paste a complete passport document.</div></div></div>';
    return;
  }
  const file = $('#verifyFile').files[0] || null;
  const res = await verifyPassport(passport, { chain: state.chain, file });
  const c = passport.credential || {};

  $('#verifyOut').innerHTML = `
    <div class="verdict ${res.ok ? 'pass' : 'fail'}">
      <div class="big">${res.ok ? '✓' : '✕'}</div>
      <div>
        <div style="font-weight:600">${res.ok ? 'Authentic and unaltered' : 'Verification failed'}</div>
        <div class="sub">${res.ok
          ? esc(c.kind || 'Credential') + ' for ' + esc(c.holder || '—')
          : 'This document cannot be trusted as issued.'}</div>
      </div>
    </div>
    ${res.steps.map((s) => `
      <div class="check">
        <div class="mark ${s.ok === true ? 'ok' : s.ok === false ? 'no' : 'skip'}">${s.ok === true ? '✓' : s.ok === false ? '✕' : '?'}</div>
        <div><div class="lab">${esc(s.label)}</div><div class="det">${esc(s.detail)}</div></div>
      </div>`).join('')}
    ${res.ok ? `<div class="hr"></div><dl class="kv">
      <dt>holder</dt><dd>${esc(c.holder)}</dd>
      <dt>enrolment</dt><dd>${esc(c.identifier)}</dd>
      <dt>programme</dt><dd>${esc(c.programme)}</dd>
      ${c.grade ? `<dt>grade</dt><dd class="hl">${esc(c.grade)}</dd>` : ''}
      <dt>awarded</dt><dd>${esc(c.awarded)}</dd>
      <dt>issuer</dt><dd>${esc(c.issuer && c.issuer.name)}</dd>
    </dl>` : ''}`;
}

$('#verifyBtn').addEventListener('click', runVerify);

$('#loadSample').addEventListener('click', () => {
  if (lastPassports.length) {
    $('#passportIn').value = JSON.stringify(lastPassports[0], null, 2);
    runVerify();
  } else {
    toast('Seal a batch first — passports are generated, not faked.');
    go('issue');
  }
});

/* The tamper lab edits the pasted passport in place so the failing check is
   unambiguous: one mutation, one broken link in the pipeline. */
$$('[data-tamper]').forEach((btn) => {
  btn.addEventListener('click', () => {
    let p;
    try { p = JSON.parse($('#passportIn').value); } catch { return toast('Load a passport first.'); }
    const kind = btn.dataset.tamper;
    if (kind === 'grade') p.credential.grade = '10.00';
    if (kind === 'holder') p.credential.holder = 'Someone Else Entirely';
    if (kind === 'root') p.anchor.merkleRoot = 'f'.repeat(64);
    if (kind === 'sig') p.anchor.signature = p.anchor.signature.slice(0, -4) + 'AAAA';
    $('#passportIn').value = JSON.stringify(p, null, 2);
    runVerify();
  });
});

/* ---------- sentinel ---------- */

function renderFlags() {
  const flags = sentinel(state);
  $('#flagTag').textContent = flags.length + (flags.length === 1 ? ' flag' : ' flags');
  $('#flagsOut').innerHTML = flags.length
    ? flags.map((f) => `
      <div class="flag">
        <span class="lv ${f.level}">${f.level}</span>
        <div><div class="txt">${esc(f.text)}</div><div class="rule">rule ${esc(f.rule)}</div></div>
      </div>`).join('')
    : '<div class="empty">No anomalies in the current issuance record.</div>';

  $('#rulesOut').innerHTML = RULES.map(([id, desc]) => `
    <div class="flag"><span class="lv low">${id}</span><div class="txt" style="font-size:13px">${esc(desc)}</div></div>`).join('');
}

$('#scanBtn').addEventListener('click', () => {
  renderFlags();
  toast('Issuance record re-scanned.');
});

/* ---------- boot ---------- */

renderVault();
renderQueue();
renderFlags();
