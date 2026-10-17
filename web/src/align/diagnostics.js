// Align diagnostics: derived link facts, the D1-D13 rule set (spec 5.3) and acceptance grades (spec 5.4).
// Pure module: no DOM, no imports. Missing inputs make a rule not fire; it never guesses.

export const NF_RE_DBM = -125;

// higher: bigger is better. abs: grade |value|. Bounds are inclusive edges of excellent/good/marginal.
export const THRESHOLDS = {
  rsrp: {label: 'Signal', unit: 'dBm', higher: true, excellent: -85, good: -95, marginal: -105},
  quality: {label: 'Quality', unit: 'dB', higher: true, excellent: 20, good: 13, marginal: 6},
  rsrq: {label: 'RSRQ', unit: 'dB', higher: true, excellent: -8, good: -11, marginal: -14},
  imbalance: {label: 'RX balance', unit: 'dB', higher: false, abs: true, excellent: 3, good: 6, marginal: 10},
  margin: {label: 'Clear of next cell', unit: 'dB', higher: true, excellent: 10, good: 6, marginal: 3},
  steadiness: {label: 'Steadiness', unit: 'dB', higher: false, excellent: 1, good: 2, marginal: 3},
  grant: {label: 'Spectrum grant', unit: ''},
};
export const GRADE_WORDS = {excellent: 'Excellent', good: 'Good', marginal: 'Fair', fail: 'Fail'};
export const CATALOGUE = ['D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9', 'D10', 'D11', 'D12', 'D13'];
export const VISIBLE = {portrait: 1, landscape: 1, desktop: 3, record: Infinity};
const SEVERITY = {block: 0, warn: 1, info: 2, good: 3};
const KNOWN_GRANTS_IGNORED = new Set(['Authorized', 'Unknown', '']);

const fin = (x) => typeof x === 'number' && Number.isFinite(x);
const f1 = (x) => (Math.round(x * 10) / 10).toFixed(1);
const finite = (list) => (Array.isArray(list) ? list.filter(fin) : []);
const mean = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
const median = (xs) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b), m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const sampleSd = (xs) => {
  if (xs.length < 3) return null;
  const m = mean(xs);
  return Math.sqrt(xs.reduce((a, x) => a + (x - m) ** 2, 0) / (xs.length - 1));
};
const wrap180 = (x) => ((((x + 540) % 360) + 360) % 360) - 180;
// Estimate.readings repeats the latest quality on every signal reading; consecutive repeats are one quality reading.
const distinctRuns = (xs) => xs.filter((x, i) => i === 0 || x !== xs[i - 1]);

// Downlink centre frequency for the CBRS/3.5 GHz bands this unit can camp on (TS 36.101 table 5.7.3-1).
export function earfcnMhz(n) {
  if (!fin(n)) return null;
  for (const [lo, hi, f0] of [[55240, 56739, 3550], [41590, 43589, 3400], [43590, 45589, 3600]])
    if (n >= lo && n <= hi) return Math.round((f0 + 0.1 * (n - lo)) * 10) / 10;
  return null;
}

export function derive(ctx, mem = null) {
  const est = ctx?.estimate, snap = ctx?.snapshot;
  const sig = est?.signal ?? {}, q = est?.quality ?? {};
  const best = fin(sig.best) ? sig.best : null;
  const signal = fin(sig.raw) ? sig.raw : null;
  const quality = fin(q.raw) ? q.raw : null;
  const deficit = best !== null && quality !== null ? Math.min(best - NF_RE_DBM, 30) - quality : null;

  const rsrp = finite(snap?.signal?.rsrp), rssi = finite(snap?.signal?.rssi);
  const loadGap = rsrp.length && rssi.length ? mean(rssi) - mean(rsrp) : null;

  let margin = null;
  const pci = snap?.cell?.pci;
  const co = (snap?.neighbours ?? []).filter((n) => n && n.coChannel === 'pcc' && fin(n.pci));
  if (fin(pci) && co.length) {
    const others = co.filter((n) => n.pci !== pci && fin(n.rsrp));
    const top = others.reduce((a, n) => (!a || n.rsrp > a.rsrp ? n : a), null);
    margin = {
      db: top && best !== null ? best - top.rsrp : null,
      pci: top ? top.pci : null,
      sameGroup: top ? Math.floor(top.pci / 3) === Math.floor(pci / 3) : null,
      mod3: best !== null && others.some((n) => n.pci % 3 === pci % 3 && best - n.rsrp < 10),
      clash: co.some((n) => n.pci === pci),
    };
  }

  const readings = Array.isArray(est?.readings) ? est.readings : [];
  const imbs = readings.slice(-3).map((r) => (fin(r?.chains?.[0]) && fin(r?.chains?.[1]) ? r.chains[0] - r.chains[1] : null)).filter(fin);
  const imbalance = median(imbs);
  // Spread only counts readings taken while still: the capture's own readings, or those since the
  // filter settled. Readings from the turn before Mark would read as instability.
  const cap = ctx?.capturing && ctx.capture ? ctx.capture : null;
  const since = fin(sig.since) ? sig.since : 5;
  const win = cap ? finite(cap.signals) : readings.slice(-Math.max(0, Math.min(5, since))).map((r) => r?.raw).filter(fin);
  const sdSignal = sampleSd(win);
  const cutoff = cap ? cap.t0 : !ctx?.capturing && sig.settled ? readings.at(-Math.min(readings.length, since))?.t : null;
  const memQ = Array.isArray(mem?.quality) ? mem.quality.map((v, i) => [v, mem.qualityT?.[i]]) : null;
  const qHist = cap ? finite(cap.quality)
    : memQ ? memQ.filter(([, t]) => !fin(cutoff) || !fin(t) || t >= cutoff).map(([v]) => v)
    : distinctRuns(readings.map((r) => r?.quality).filter(fin));
  const sdQuality = sampleSd(qHist.slice(-5));
  const steady = Boolean(ctx?.capturing || sig.settled);
  return {best, signal, quality, deficit, loadGap, margin, imbalance, sdSignal, sdQuality, steady};
}

const finding = (id, severity, title, action, detail, evidence) => ({id, severity, title, action, detail: detail ?? '', evidence: evidence ?? {}});

function rsrqOf(ctx) {
  const r = ctx?.estimate?.rsrq?.raw;
  return fin(r) ? r : mean(finite(ctx?.snapshot?.signal?.rsrq));
}

function hardwareSignature(ctx, imb) {
  const sccs = (ctx.snapshot?.carriers ?? []).filter((c) => c?.role === 'scc' && fin(c.rsrpChains?.[0]) && fin(c.rsrpChains?.[1]));
  if (!sccs.length) return false;
  if (!sccs.every((c) => { const d = c.rsrpChains[0] - c.rsrpChains[1]; return Math.sign(d) === Math.sign(imb) && Math.abs(d) > 3; })) return false;
  const pos = (ctx.positions ?? []).filter((p) => fin(p?.imbalance));
  for (let i = 0; i < pos.length; i++)
    for (let j = i + 1; j < pos.length; j++) {
      const a = pos[i], b = pos[j];
      if (Math.abs(a.imbalance - b.imbalance) >= 2) continue;
      if (fin(a.heading?.deg) && fin(b.heading?.deg) && Math.abs(wrap180(a.heading.deg - b.heading.deg)) < 15) continue;
      return true;
    }
  return false;
}

export function evaluate(ctx, mem = null) {
  const snap = ctx?.snapshot;
  if (!snap) return [];
  const est = ctx.estimate ?? {};
  const d = derive(ctx, mem);
  const {best, signal, quality, deficit, loadGap, margin, imbalance, sdSignal, sdQuality, steady} = d;
  const out = [];
  const grant = typeof snap.sas?.grant === 'string' ? snap.sas.grant : '';
  const earfcn = snap.cell?.earfcn ?? null;
  const rsrq = rsrqOf(ctx);
  const dlBps = fin(snap.throughput?.dlBps) ? snap.throughput.dlBps : null;
  const peakDl = fin(ctx.dlPeakBps) ? ctx.dlPeakBps : null;

  if (grant && !KNOWN_GRANTS_IGNORED.has(grant)) {
    const mhz = earfcnMhz(earfcn);
    out.push(finding('D1', 'block', `No spectrum grant (state: ${grant}). The radio can hear the tower but cannot send.`,
      'Wait for the SAS. This is not an aiming problem.',
      mhz !== null && mhz >= 3550 && mhz <= 3650 ? 'Near the coast this is often Navy radar protection.' : '', {grant, earfcn, mhz}));
  }

  const freshness = est.freshness ?? 'none';
  // Paused readings age by design; "no signal" there would be a false alarm. Stale is treated as none (spec 4.1).
  // While attached, missing readings are a data-path fault, not an aiming one: never send the installer to re-aim.
  if (!snap.paused && (!snap.attached || snap.stale || freshness === 'none' || (best !== null && best < -120))) {
    const age = est.signal?.ageMs, weak = snap.attached && best !== null && best < -120;
    const evidence = {attached: Boolean(snap.attached), freshness, stale: Boolean(snap.stale), best, ageMs: fin(age) ? age : null};
    if (snap.attached && !weak)
      out.push(finding('D2', 'block', fin(age) ? `No new readings from the Titan for ${Math.round(age / 1000)} s.` : 'No readings from the Titan yet.',
        'Check the cable and the login, not the antenna.', fin(age) ? `No reading for ${Math.round(age / 1000)} s` : 'No reading yet', {...evidence, kind: 'data'}));
    else
      out.push(finding('D2', 'block', 'No usable signal.', out.some((f) => f.id === 'D1') ? '' : 'Check the path to the tower and sweep slowly, 15° at a time.',
        weak ? `RSRP ${f1(best)} dBm` : fin(age) ? `No reading for ${Math.round(age / 1000)} s` : 'No reading yet', {...evidence, kind: 'signal'}));
  }

  if (margin && fin(margin.db) && margin.db < 3)
    out.push(finding('D3', 'warn',
      margin.db < 0 ? `PCI ${margin.pci} is stronger than your cell by ${f1(-margin.db)} dB.` : `Another cell (PCI ${margin.pci}) is nearly as strong.`,
      'Aim at your sector, or confirm the sector with dispatch.',
      `Margin ${f1(margin.db)} dB · same site: ${margin.sameGroup ? 'yes' : 'no'}`, {margin}));

  const d11 = fin(rsrq) && rsrq >= -12 && rsrq <= -11 && dlBps !== null && peakDl !== null && peakDl > 0 && dlBps > 0.7 * peakDl;

  if (best !== null && quality !== null && best >= -95 && quality < 10 && deficit > 10) {
    let action = 'Try a few degrees either side, then report it.', sub = 'e';
    if (margin && fin(margin.db) && margin.db < 6) { action = `Turn to favor your sector over PCI ${margin.pci}.`; sub = 'a'; }
    else if (margin?.mod3) {
      const m = (snap.neighbours ?? []).filter((n) => n?.coChannel === 'pcc' && fin(n.pci) && n.pci !== snap.cell.pci && n.pci % 3 === snap.cell.pci % 3 && fin(n.rsrp) && best - n.rsrp < 10)
        .reduce((a, n) => (!a || n.rsrp > a.rsrp ? n : a), null);
      action = `Re-aim for 10 dB of margin and report PCI ${m?.pci ?? margin.pci}.`; sub = 'b';
    } else if (fin(rsrq) && rsrq < -12 && fin(loadGap) && loadGap > 31 && dlBps !== null && dlBps < 1e6 && !d11) {
      action = `Extra energy on this channel is not from your cell. Report EARFCN ${earfcn ?? '?'}.`; sub = 'c';
    } else if (steady && fin(sdQuality) && sdQuality > 3 && fin(sdSignal) && sdSignal < 1) {
      action = 'Interference comes and goes. Record it and report it.'; sub = 'd';
    }
    out.push(finding('D4', 'warn', 'Strong signal, poor quality. Something is interfering.', action,
      `Quality ${f1(quality)} dB · ceiling ${f1(Math.min(best - NF_RE_DBM, 30))} dB`, {best, quality, deficit, sub, rsrq, loadGap, dlBps}));
  }

  if (margin?.clash)
    out.push(finding('D5', 'warn', 'Two cells use the same PCI on this channel.',
      `Do not accept this install. Report PCI ${snap.cell.pci} and EARFCN ${earfcn ?? '?'}.`, '', {pci: snap.cell.pci, earfcn}));

  if (fin(imbalance) && Math.abs(imbalance) > 6) {
    const hw = hardwareSignature(ctx, imbalance);
    const one = Math.abs(imbalance) > 10 ? ' (one stream likely)' : '';
    const ch = est.signal?.chains ?? [];
    out.push(finding('D6', 'warn',
      (hw ? 'One receive path is weak on every carrier.' : `One antenna path is weaker by ${f1(Math.abs(imbalance))} dB.`) + one,
      hw ? 'Check the connector and look for water. Re-aiming will not fix this.' : 'Move slightly or clear nearby obstructions.',
      `RX1 ${fin(ch[0]) ? f1(ch[0]) : '—'} / RX2 ${fin(ch[1]) ? f1(ch[1]) : '—'} dBm`, {imbalance, hardware: hw}));
  }

  if (best !== null && deficit !== null && best < -105 && deficit < 6)
    out.push(finding('D7', 'warn', 'Weak but clean signal. Something is in the path.', 'Raise the mount or clear trees from the path.',
      `RSRP ${f1(best)} dBm`, {best, deficit}));

  const peak = ctx.peak;
  if (peak && fin(peak.value) && signal !== null) {
    const below = peak.value - signal, bf = ctx.bearing;
    const lobe = (steady && below >= 10)
      || Boolean(bf?.valid && bf.fitOk && fin(bf.theta3) && bf.theta3 < 30)
      || (below <= 3 && fin(peak.quality) && quality !== null && peak.quality - quality >= 6);
    if (lobe)
      out.push(finding('D8', 'warn', 'This looks like a side lobe or the wrong sector.', 'Go back to the strongest spot or sweep wider.',
        `${f1(below)} dB below the peak`, {below, peak: peak.value, signal, theta3: bf?.theta3 ?? null}));
  }

  const R = est.signal?.R;
  if ((steady && fin(sdSignal) && sdSignal > 2) || (fin(R) && R > 4))
    out.push(finding('D9', 'warn', 'Signal moves while the antenna is still.', 'Tighten the mount and check for trees in the wind.',
      `Spread ${f1(fin(sdSignal) ? sdSignal : Math.sqrt(R))} dB`, {sdSignal, R: fin(R) ? R : null}));

  const tx = snap.radio?.txPowerDbm;
  if (fin(mem?.txHigh) && mem.txHigh >= 3 && fin(tx))
    out.push(finding('D10', 'info', 'Uplink is near full power. Upload will be the weak side.', 'Improve the path to the tower.', `TX ${f1(tx)} dBm`, {tx, run: mem.txHigh}));

  if (d11) out.push(finding('D11', 'info', 'Quality dip comes from your own traffic.', 'No action needed.', '', {rsrq, dlBps, dlPeakBps: peakDl}));

  if (snap.signal?.source === 'legacy')
    out.push(finding('D12', 'info', 'Reading times are approximate on this firmware.', 'No action needed.', '', {}));

  const blocked = out.some((f) => f.severity === 'block' || f.severity === 'warn');
  if (!blocked && grant === 'Authorized' && best !== null && quality !== null && best >= -95 && quality >= 13
    && (!margin || !fin(margin.db) || margin.db >= 6) && Math.abs(imbalance ?? 0) <= 6)
    out.push(finding('D13', 'good', 'Good spot. Lock it down.', 'Run the lock check, then record.',
      `RSRP ${f1(best)} · quality ${f1(quality)} · margin ${margin && fin(margin.db) ? f1(margin.db) : 'no other cell heard'}`, {best, quality, margin: margin?.db ?? null}));
  return out;
}

export const sortFindings = (list) => [...list].sort((a, b) => SEVERITY[a.severity] - SEVERITY[b.severity] || CATALOGUE.indexOf(a.id) - CATALOGUE.indexOf(b.id));

// Spec 5.3 display caps: every block plus at most N others.
export function pick(findings, layout = 'desktop') {
  const n = VISIBLE[layout] ?? VISIBLE.desktop;
  return [...findings.filter((f) => f.severity === 'block'), ...findings.filter((f) => f.severity !== 'block').slice(0, n)];
}

export class Diagnostics {
  constructor() { this.reset(); }

  reset() {
    this.rules = new Map(); // id -> {hits, misses, shown, last}
    this.mem = {quality: [], qualityT: [], txHigh: 0};
    this.qSeq = null;
  }

  // Tracked here (not from Estimate.readings) so quality SD and the TX run count true quality readings.
  #track(ctx) {
    const q = ctx?.estimate?.quality;
    if (!q || q.seq === null || q.seq === undefined || q.seq === this.qSeq) return;
    this.qSeq = q.seq;
    if (fin(q.raw)) { this.mem.quality = [...this.mem.quality, q.raw].slice(-5); this.mem.qualityT = [...this.mem.qualityT, q.t ?? null].slice(-5); }
    const tx = ctx.snapshot?.radio?.txPowerDbm;
    this.mem.txHigh = fin(tx) && tx >= 22 ? this.mem.txHigh + 1 : 0;
  }

  update(ctx, {newEvidence = false} = {}) {
    this.#track(ctx);
    const raw = new Map(evaluate(ctx, this.mem).map((f) => [f.id, f]));
    for (const id of CATALOGUE) {
      const f = raw.get(id);
      let r = this.rules.get(id);
      if (!r) this.rules.set(id, (r = {hits: 0, misses: 0, shown: false, last: null}));
      if (f) r.last = f;
      if (f?.severity === 'block' || (!f && r.last?.severity === 'block')) { r.shown = Boolean(f); r.hits = r.misses = 0; continue; }
      if (!newEvidence) continue;
      if (f) { r.hits++; r.misses = 0; if (r.hits >= 2) r.shown = true; }
      else { r.misses++; r.hits = 0; if (r.misses >= 3) r.shown = false; }
    }
    const shown = CATALOGUE.map((id) => this.rules.get(id)).filter((r) => r.shown && r.last).map((r) => r.last);
    const quiet = !shown.some((f) => f.severity === 'block' || f.severity === 'warn');
    return sortFindings(shown.filter((f) => f.id !== 'D13' || quiet));
  }
}

export function grade(metric, value) {
  const key = metric === 'signal' ? 'rsrp' : metric;
  const t = THRESHOLDS[key];
  if (!t) return null;
  if (key === 'grant') return typeof value === 'string' && value ? (value === 'Authorized' ? 'excellent' : 'fail') : null;
  if (!fin(value)) return null;
  const v = t.abs ? Math.abs(value) : value;
  if (t.higher) return v >= t.excellent ? 'excellent' : v >= t.good ? 'good' : v >= t.marginal ? 'marginal' : 'fail';
  return v <= t.excellent ? 'excellent' : v <= t.good ? 'good' : v <= t.marginal ? 'marginal' : 'fail';
}

export function acceptance(ctx) {
  const p = ctx?.final ?? null;
  const row = (metric, value, extra = {}) => ({metric, label: THRESHOLDS[metric].label, value, unit: THRESHOLDS[metric].unit, grade: grade(metric, value), ...extra});
  const grant = ctx?.snapshot?.sas?.grant ?? null;
  if (!p) return {rows: [row('grant', grant)], verdict: 'incomplete'};
  // Position readings already hold one entry per quality reading; equal values are separate readings.
  const qs = (p.readings ?? []).map((r) => r?.quality).filter(fin);
  const marginRow = fin(p.margin) ? row('margin', p.margin) : {...row('margin', null), grade: 'good', note: 'No other cell heard'};
  const rows = [
    row('rsrp', fin(p.best) ? p.best : null),
    row('quality', fin(p.quality?.mean) ? p.quality.mean : null),
    row('rsrq', fin(p.rsrq) ? p.rsrq : null),
    row('imbalance', fin(p.imbalance) ? Math.abs(p.imbalance) : null),
    marginRow,
    row('steadiness', qs.length >= 3 ? sampleSd(qs) : null),
    row('grant', grant),
  ];
  const verdict = rows.some((r) => r.grade === 'fail') ? 'fail' : rows.some((r) => r.grade === 'marginal') ? 'pass-notes' : 'pass';
  return {rows, verdict};
}
