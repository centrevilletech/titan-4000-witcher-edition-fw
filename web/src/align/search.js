// Positions, comparison, peak tracking, bearing fit and guidance copy. Pure: no DOM, no imports.
export const CAPTURE = {settleMs:750, need:3, needQuality:1, timeoutMs:25000, minSaveN:2, qualityIdleMs:20000, moveDb:3};
export const COMPARE = {
  signal:  {delta:0.5, drift:0.0005, sigma0:0.5, floor:0.1},
  quality: {delta:1.0, drift:0.003,  sigma0:1.0, floor:0.29},
  equivalence:1.0, decide:0.9, same:0.8, k:4
};
export const SIGMA_H = {abs:6, ios:6, 'ios-raw':8, sim:2, rel:2, manual:4.3};
export const BEARING = {theta3Median:60, theta3SigmaLog:0.4, tau:0.3, am:20};
// df 1-3 extend the spec table for sample-only summaries (pooled df is always >= 4).
const T975 = [[1,12.71],[2,4.30],[3,3.18],[4,2.78],[5,2.57],[6,2.45],[7,2.36],[8,2.31],[10,2.23],[12,2.18],[15,2.13],[20,2.09],[30,2.04],[Infinity,1.96]];
const CHI95 = [null, 3.84, 5.99, 7.81, 9.49, 11.07, 12.59, 14.07, 15.51, 16.92, 18.31];
const RAD = Math.PI / 180;
const fin = Number.isFinite;
const mean = a => a.reduce((s, v) => s + v, 0) / a.length;
const nowOf = (estimate, fallback) => fin(fallback) ? fallback : fin(estimate?.t) ? estimate.t : Date.now();

function erf(x) {
  const s = Math.sign(x), a = Math.abs(x), t = 1 / (1 + 0.3275911 * a);
  return s * (1 - ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-a * a));
}
export function phi(z) { return z === Infinity ? 1 : z === -Infinity ? 0 : 0.5 * (1 + erf(z / Math.SQRT2)); }
export function wrap180(deg) { return ((((deg + 540) % 360) + 360) % 360) - 180; }
const norm360 = d => ((d % 360) + 360) % 360;
function circ(degs) {
  const v = degs.filter(fin); if (!v.length) return null;
  const s = mean(v.map(d => Math.sin(d * RAD))), c = mean(v.map(d => Math.cos(d * RAD))), r = Math.hypot(s, c);
  if (r < 1e-9) return null;
  return {mean:norm360(Math.atan2(s, c) / RAD), sd:Math.sqrt(-2 * Math.log(Math.min(1, r))) / RAD};
}
export function circularMean(degs) { return circ(degs)?.mean ?? null; }
export function tMultiplier(df) { let t = T975[0][1]; for (const [d, v] of T975) if (d <= df) t = v; return t; }

export function summarize(values, {pooledSigma, R, floor = 0, df} = {}) {
  const v = values.filter(fin), n = v.length;
  if (!n) return {mean:null, se:null, lo:null, hi:null, n:0};
  const m = mean(v), sample = n > 1 ? Math.sqrt(v.reduce((s, x) => s + (x - m) ** 2, 0) / (n - 1)) : 0;
  const s = Math.max(fin(pooledSigma) ? pooledSigma : sample, Math.sqrt(fin(R) ? R : 0), floor), se = s / Math.sqrt(n);
  const t = tMultiplier(fin(df) ? df : fin(pooledSigma) ? COMPARE.k : Math.max(1, n - 1));
  return {mean:m, se, lo:m - t * se, hi:m + t * se, n};
}

export function pooledSigma(positions, metric) {
  const {sigma0, floor} = COMPARE[metric], k = COMPARE.k;
  let ss = 0, dfs = 0;
  for (const p of positions || []) {
    const y = (p.readings || []).map(r => r[metric]).filter(fin);
    if (y.length < 2) continue;
    const m = mean(y); ss += y.reduce((s, v) => s + (v - m) ** 2, 0); dfs += y.length - 1;
  }
  return {s:Math.max(Math.sqrt((k * sigma0 ** 2 + ss) / (k + dfs)), floor), df:k + dfs};
}

export function compare(a, b, metric) {
  const none = {pBetter:null, pWorse:null, pSame:null, delta:null, seDelta:null};
  if (a?.pci !== b?.pci) return {verdict:'different-cell', ...none};
  const A = a?.[metric], B = b?.[metric];
  if (!A || !B || !fin(A.mean) || !fin(B.mean)) return {verdict:'unsure', ...none};
  const c = COMPARE[metric], D = A.mean - B.mean;
  const dt = fin(a.t) && fin(b.t) ? Math.abs(a.t - b.t) / 1000 : 0;
  const seDelta = Math.max(Math.sqrt((A.se || 0) ** 2 + (B.se || 0) ** 2 + c.drift * dt), 1e-9);
  const pBetter = phi((D - c.delta) / seDelta), pWorse = phi((-D - c.delta) / seDelta);
  const pSame = phi((COMPARE.equivalence - D) / seDelta) - phi((-COMPARE.equivalence - D) / seDelta);
  const verdict = pBetter > COMPARE.decide ? 'better' : pWorse > COMPARE.decide ? 'worse' : pSame > COMPARE.same ? 'same' : 'unsure';
  return {verdict, pBetter, pWorse, pSame, delta:D, seDelta};
}

export class Capture {
  constructor({t0, pci = null, eci = null, need = CAPTURE.need} = {}) {
    Object.assign(this, {t0, pci, eci:eci ?? null, need});
    this.got = []; this.gotQ = []; this.poses = []; this.restarts = 0; this.lastReading = null; this.lastQSeq = null;
    this.flags = {lowConfidence:false, unsteady:false, qualityHeld:false};
    this.final = null; this.restartedAt = null; this.est = null; this.snap = null; this.doneAt = null;
  }
  status(status, now, reason) {
    const s = {status, n:this.got.length, nQuality:this.gotQ.length, need:this.need, at:now, restartedAt:this.restartedAt, flags:{...this.flags}};
    if (reason) s.reason = reason;
    if (status === 'done' || status === 'failed' || status === 'aborted') { this.final = s; if (status === 'done') this.doneAt = now; }
    return s;
  }
  restart(now, reason) { this.restarts++; this.restartedAt = now; return this.status('restarted', now, reason); }
  offer(estimate, snapshot, pose, nowMs) {
    if (this.final) return this.final;
    const now = nowOf(estimate, nowMs);
    if (!snapshot || !snapshot.connected || snapshot.paused) return this.status('aborted', now, snapshot?.paused ? 'paused' : 'stale');
    const cell = snapshot.cell || {};
    if ((cell.pci ?? null) !== this.pci || (this.eci !== null && (cell.eci ?? null) !== this.eci)) return this.status('aborted', now, 'cell');
    this.est = estimate; this.snap = snapshot;
    if (pose?.valid && fin(pose.heading)) {
      this.poses.push(pose);
      if (this.poses.length >= 2 && Math.abs(wrap180(pose.heading - this.poses[0].heading)) > 3) {
        this.got = []; this.gotQ = []; this.poses = [pose];
        return this.restart(now, 'moved');
      }
    }
    const S = snapshot.signal, sig = estimate?.signal || {}, settle = this.t0 + CAPTURE.settleMs;
    if (S && !S.heartbeat && S.readingT >= settle && fin(sig.raw)) {
      if (S.reading !== this.lastReading) {
        const r = {reading:S.reading, t:S.t, signal:sig.raw, rx:[...(sig.chains || [])], quality:null};
        const last = this.got.at(-1);
        if (last && Math.abs(r.signal - last.signal) > Math.max(CAPTURE.moveDb, 3 * (sig.deadband || 0))) {
          if (this.restarts === 0) { this.got = [r]; this.gotQ = []; this.lastReading = S.reading; return this.restart(now, 'moving'); }
          this.flags.unsteady = true;
        }
        this.got.push(r); this.lastReading = S.reading;
      } else if (this.got.length) {
        const last = this.got.at(-1); last.signal = sig.raw; last.rx = [...(sig.chains || [])];
      }
    }
    const Q = snapshot.quality, q = estimate?.quality || {};
    if (Q && Q.t >= settle && Q.seq !== this.lastQSeq && fin(q.raw)) { this.gotQ.push({t:Q.t, v:q.raw}); this.lastQSeq = Q.seq; }
    const qualityMs = estimate?.cadence?.qualityMs || 0;
    const qualityIdle = !fin(q.t) || now - q.t > Math.max(CAPTURE.qualityIdleMs, 2.5 * qualityMs);
    if (this.got.length >= this.need && (this.gotQ.length >= CAPTURE.needQuality || qualityIdle)) {
      if (!this.gotQ.length) this.flags.qualityHeld = true;
      return this.status('done', now, this.flags.qualityHeld ? 'qualityHeld' : undefined);
    }
    if (now - this.t0 >= CAPTURE.timeoutMs) {
      if (this.got.length >= CAPTURE.minSaveN) { this.flags.lowConfidence = true; if (!this.gotQ.length) this.flags.qualityHeld = true; return this.status('done', now, 'lowConfidence'); }
      return this.status('failed', now, 'not-updating');
    }
    return this.status('collecting', now);
  }
  label() {
    if (this.got.length >= this.need && !this.final) return 'Hold still · waiting for quality';
    return `Hold still · reading ${Math.min(this.got.length, this.need)} of ${this.need}`;
  }
  result(session) {
    if (this.final?.status !== 'done') return null;
    const est = this.est || {}, positions = session?.positions || [];
    const ps = pooledSigma(positions, 'signal'), pq = pooledSigma(positions, 'quality');
    const signal = summarize(this.got.map(r => r.signal), {pooledSigma:ps.s, df:ps.df, R:est.signal?.R, floor:COMPARE.signal.floor});
    let quality = null;
    const source = est.quality?.source || 'sinr';
    if (this.gotQ.length) quality = {...summarize(this.gotQ.map(q => q.v), {pooledSigma:pq.s, df:pq.df, R:est.quality?.R, floor:COMPARE.quality.floor}), source};
    else if (fin(est.quality?.raw)) {
      const se = Math.max(pq.s, Math.sqrt(est.quality.R || 0), COMPARE.quality.floor), m = est.quality.raw, t = tMultiplier(pq.df);
      quality = {mean:m, se, lo:m - t * se, hi:m + t * se, n:1, source};
    }
    const width = Math.max(0, ...this.got.map(r => r.rx.length));
    const rx = Array.from({length:width}, (_, c) => { const v = this.got.map(r => r.rx[c]).filter(fin); return v.length ? mean(v) : null; });
    const okRx = rx.filter(fin), hs = circ(this.poses.map(p => p.heading));
    const readings = this.got.map((r, i) => ({t:r.t, signal:r.signal, rx:r.rx, quality:this.gotQ[i]?.v ?? null}));
    for (const q of this.gotQ.slice(this.got.length)) readings.push({t:q.t, signal:null, rx:null, quality:q.v});
    const cell = this.snap?.cell || {}, index = positions.reduce((m, p) => Math.max(m, p.index || 0), 0) + 1;
    return {
      id:`p${Math.round(this.doneAt)}-${index}`, index, t:this.doneAt, pci:this.pci, eci:this.eci ?? cell.eci ?? null, earfcn:cell.earfcn ?? null,
      n:this.got.length, nQuality:this.gotQ.length, flags:{...this.flags},
      signal, best:okRx.length ? Math.max(...okRx) : null, rx,
      imbalance:fin(rx[0]) && fin(rx[1]) ? rx[0] - rx[1] : null,
      quality, sinr:est.quality?.sinr ?? null, rsrq:est.rsrq?.raw ?? null, margin:null,
      heading:hs ? {deg:hs.mean, sd:hs.sd, source:this.poses[0].source, relative:!!this.poses[0].relative} : null,
      predict:null, readings
    };
  }
}

export class PeakTracker {
  constructor() { this.reset(); }
  reset() { this._peak = null; this.last = []; this.ring = []; this.passedOnce = false; }
  get peak() { return this._peak; }
  offer(estimate, pose) {
    const s = estimate?.signal || {}, v = s.raw, db = s.deadband || 0;
    if (!fin(v)) return {newPeak:false};
    const t = fin(s.t) ? s.t : nowOf(estimate), r = {reading:s.reading, t, raw:v};
    if (this.last.length && this.last.at(-1).reading === s.reading && s.reading != null) { this.last[this.last.length - 1] = r; this.ring[this.ring.length - 1] = r; }
    else { this.last = [...this.last.slice(-1), r]; this.ring.push(r); }
    this.ring = this.ring.filter(x => t - x.t <= 30000);
    let newPeak = false;
    if (this.last.length === 2 && Math.abs(this.last[0].raw - this.last[1].raw) <= db) {
      const m = (this.last[0].raw + this.last[1].raw) / 2;
      if (m > (this._peak ? this._peak.value + db : -Infinity)) {
        this._peak = {value:m, t, heading:pose?.valid && fin(pose.heading) ? pose.heading : null, reading:s.reading, quality:estimate?.quality?.raw ?? null};
        newPeak = true;
      }
    }
    if (this.passed(estimate)) this.passedOnce = true;
    return {newPeak};
  }
  recent(nowMs) { const v = this.ring.filter(x => !fin(nowMs) || nowMs - x.t <= 30000).map(x => x.raw); return v.length ? Math.max(...v) : null; }
  passed(estimate) {
    if (!this._peak || this.last.length < 2) return false;
    const lim = this._peak.value - Math.max(3, 2 * (estimate?.signal?.deadband || 0));
    return this.last.every(r => r.raw <= lim);
  }
  atPeak(estimate) {
    const v = estimate?.signal?.raw;
    return !!this._peak && fin(v) && this._peak.value - v <= Math.max(0.5, estimate.signal.deadband || 0);
  }
}

export const BRACKET_COPY = {
  left:'Turn left until the signal drops 3 dB.',
  'left-edge':'Edge found. Mark the pole here.',
  right:'Now turn right past the peak until it drops 3 dB.',
  'right-edge':'Edge found. Mark the pole here.',
  done:'Set the antenna halfway between your two marks.'
};
export class Bracket {
  constructor() { this.cancel(); }
  get state() { return this._state; }
  cancel() { this._state = 'idle'; this.low = 0; this.sawTop = false; this.edgeAt = null; this.lastReading = null; }
  // The spec's start(estimate) has no peak argument; a peak (number or PeakTracker.peak) may be passed and is required when given.
  start(estimate, peak) {
    if (arguments.length > 1 && !fin(peak?.value ?? peak)) return false;
    this.cancel(); this._state = 'left'; this.lastReading = estimate?.signal?.reading ?? null; return true;
  }
  offer(estimate, peak) {
    const s = estimate?.signal || {}, v = s.raw, p = peak?.value ?? peak;
    if (this._state === 'idle' || this._state === 'done' || !fin(v) || !fin(p)) return this._state;
    if (s.reading != null && s.reading === this.lastReading) return this._state;
    this.lastReading = s.reading;
    const t = fin(s.t) ? s.t : nowOf(estimate), low = v <= p - 3;
    if (this._state === 'left-edge' || this._state === 'right-edge') {
      if (v > p - 3 || t - this.edgeAt >= 8000) { this._state = this._state === 'left-edge' ? 'right' : 'done'; this.low = 0; }
      else return this._state;
      if (this._state === 'done') return this._state;
    }
    if (this._state === 'left') {
      this.low = low ? this.low + 1 : 0;
      if (this.low >= 2) { this._state = 'left-edge'; this.edgeAt = t; this.low = 0; }
    } else if (this._state === 'right') {
      if (v >= p - 1) this.sawTop = true;
      this.low = low && this.sawTop ? this.low + 1 : 0;
      if (this.low >= 2) { this._state = 'right-edge'; this.edgeAt = t; this.low = 0; }
    }
    return this._state;
  }
}

const invalidFit = (reason, n, relative) => ({valid:false, reason, fitOk:false, n, relative, theta0:null, hdi68:null, hdi95:null, theta3:null,
  theta3Range:null, recommended:null, edge:null, expectedLossAt:() => null, gainAt:() => null, pWithinAt:() => null});
function hdi(values, mass, level) {
  const order = values.map((v, i) => i).sort((a, b) => mass[b] - mass[a]);
  let acc = 0, lo = Infinity, hi = -Infinity;
  for (const i of order) { lo = Math.min(lo, values[i]); hi = Math.max(hi, values[i]); acc += mass[i]; if (acc >= level) break; }
  return [lo, hi];
}

export function fitBearing(points, opts = {}) {
  const o = {...BEARING, ...opts};
  let pts = (points || []).filter(p => fin(p?.heading) && fin(p?.y));
  const nRel = pts.filter(p => p.relative).length, relative = nRel > pts.length - nRel;
  pts = pts.filter(p => !!p.relative === relative);
  const few = list => new Set(list.map(p => norm360(Math.round(p.heading)))).size < 3;
  if (few(pts)) return invalidFit('few', pts.length, relative);
  // Trim first and unwrap around the strongest point: a mean over a near-full circle can sit
  // opposite the peak and split its neighbours across the ±180° cut.
  const apex = pts.reduce((a, p) => p.y > a.y ? p : a);
  pts = pts.filter(p => p.y >= apex.y - 10);
  if (few(pts)) return invalidFit('few', pts.length, relative);
  const d0 = pts.map(p => wrap180(p.heading - apex.heading));
  const ref = norm360(apex.heading + (circularMean(d0) ?? 0));
  const d = pts.map(p => wrap180(p.heading - ref));
  const span = Math.max(...d) - Math.min(...d);
  if (span < 20) return invalidFit('span', pts.length, relative);
  const n = pts.length, se2 = pts.map(p => (fin(p.se) ? p.se : 0.3) ** 2), sH = pts.map(p => fin(p.sigmaH) ? p.sigmaH : 6);
  const t3 = o.theta3Grid || Array.from({length:16}, (_, k) => 20 * 6 ** (k / 15));
  const dMin = Math.min(...d), dMax = Math.max(...d), step = span < 40 ? 0.5 : 1;
  const t0 = []; for (let x = dMin - 20; x <= dMax + 20 + 1e-9; x += step) t0.push(x);
  const logL = new Float64Array(t0.length * t3.length), chi = new Float64Array(logL.length), w = new Float64Array(n), z = new Float64Array(n);
  for (let j = 0; j < t3.length; j++) {
    const th = t3[j], prior = -(Math.log(th / o.theta3Median) ** 2) / (2 * o.theta3SigmaLog ** 2);
    for (let i = 0; i < t0.length; i++) {
      let sw = 0, swz = 0, slv = 0;
      for (let m = 0; m < n; m++) {
        const e = d[m] - t0[i], A = Math.min(12 * (e / th) ** 2, o.am), g = A < o.am ? 24 * Math.abs(e) / th ** 2 : 0;
        const v = se2[m] + o.tau ** 2 + (g * sH[m]) ** 2;
        w[m] = 1 / v; z[m] = pts[m].y + A; sw += w[m]; swz += w[m] * z[m]; slv += Math.log(v);
      }
      const P0 = swz / sw; let c2 = 0;
      for (let m = 0; m < n; m++) c2 += w[m] * (z[m] - P0) ** 2;
      const k = j * t0.length + i; chi[k] = c2;
      logL[k] = -0.5 * c2 - 0.5 * slv - 0.5 * Math.log(sw) + prior;
    }
  }
  let top = -Infinity, mapK = 0;
  for (let k = 0; k < logL.length; k++) if (logL[k] > top) { top = logL[k]; mapK = k; }
  const p = new Float64Array(logL.length); let tot = 0;
  for (let k = 0; k < p.length; k++) { p[k] = Math.exp(logL[k] - top); tot += p[k]; }
  const m0 = new Array(t0.length).fill(0), m3 = new Array(t3.length).fill(0);
  for (let j = 0; j < t3.length; j++) for (let i = 0; i < t0.length; i++) { const k = j * t0.length + i; p[k] /= tot; m0[i] += p[k]; m3[j] += p[k]; }
  const i0 = m0.indexOf(Math.max(...m0)), j3 = m3.indexOf(Math.max(...m3));
  // Negligible cells are dropped so the loss scan stays cheap on a phone with long sweeps.
  const cells = []; for (let k = 0; k < p.length; k++) if (p[k] > 1e-9) cells.push([p[k], t0[k % t0.length], t3[Math.floor(k / t0.length)]]);
  const loss = h => { let s = 0; for (const [pk, a, th] of cells) s += pk * Math.min(12 * ((h - a) / th) ** 2, o.am); return s; };
  const L = t0.map(loss), recI = L.indexOf(Math.min(...L)), rec = t0[recI], Lrec = L[recI];
  const lowMass = m0.reduce((s, v, i) => s + (t0[i] <= t0[0] + 10 ? v : 0), 0);
  const highMass = m0.reduce((s, v, i) => s + (t0[i] >= t0.at(-1) - 10 ? v : 0), 0);
  const df = Math.max(1, n - 2), crit = df <= 10 ? CHI95[df] : df + 2 * Math.sqrt(2 * df);
  const mapJ = Math.floor(mapK / t0.length), interior = t3.length < 3 || (mapJ > 0 && mapJ < t3.length - 1);
  const abs = x => norm360(ref + x), rel = h => wrap180(h - ref);
  return {
    valid:true, fitOk:n >= 4 && chi[mapK] <= crit && interior, n, relative,
    theta0:abs(t0[i0]), hdi68:hdi(t0, m0, 0.68).map(abs), hdi95:hdi(t0, m0, 0.95).map(abs),
    theta3:t3[j3], theta3Range:hdi(t3, m3, 0.68), recommended:abs(rec),
    edge:lowMass > 0.2 ? 'left' : highMass > 0.2 ? 'right' : null, chi2:chi[mapK],
    expectedLossAt:h => loss(rel(h)), gainAt:h => loss(rel(h)) - Lrec,
    pWithinAt:h => { const x = rel(h); let s = 0; for (const [pk, a, th] of cells) if (Math.abs(x - a) <= 0.2 * th) s += pk; return s; }
  };
}

// Builds fitBearing points for one PCI: headed positions plus headed sweep readings (signal) or headed positions with quality.
export function bearingPoints(session, {pci, metric = 'signal', R = null, sweep = metric === 'signal'} = {}) {
  const out = [];
  for (const p of session?.positions || []) {
    const s = p[metric];
    if (p.pci !== pci || !p.heading || !s || !fin(s.mean)) continue;
    out.push({heading:p.heading.deg, y:s.mean, se:s.se, sigmaH:SIGMA_H[p.heading.source] ?? 6, relative:!!p.heading.relative});
  }
  if (sweep) for (const r of session?.sweep || []) {
    if (r.pci !== pci || !fin(r.heading) || !fin(r.raw)) continue;
    out.push({heading:r.heading, y:r.raw, se:Math.max(Math.sqrt(fin(R) ? R : 0), 0.3), sigmaH:SIGMA_H[r.source] ?? 6, relative:!!r.relative});
  }
  return out;
}

export class AlignSession {
  constructor() { this.positions = []; this.archived = []; this.sweep = []; this.lock = null; }
  add(record) { if (record) this.positions.push(record); return record; }
  undo() { return this.positions.pop() ?? null; }
  clear() { this.positions = []; this.archived = []; this.lock = null; }
  onCellChange(oldPci, newPci) {
    if (oldPci === newPci) return;
    if (this.positions.length) this.archived.push({pci:oldPci, positions:this.positions});
    this.positions = []; this.lock = null;
  }
  logSweep(estimate, pose, pci) {
    const s = estimate?.signal;
    if (!s || !fin(s.raw)) return null;
    const ok = pose?.valid && fin(pose.heading);
    const row = {t:s.t, reading:s.reading, raw:s.raw, heading:ok ? pose.heading : null, sd:ok ? pose.sd ?? null : null,
      relative:ok ? !!pose.relative : false, source:ok ? pose.source ?? null : null, pci};
    const last = this.sweep.at(-1);
    // A revision updates the value but keeps the heading taken when the reading was measured.
    if (last && s.reading != null && last.reading === s.reading && last.pci === pci)
      this.sweep[this.sweep.length - 1] = ok ? row : {...row, heading:last.heading, sd:last.sd, relative:last.relative, source:last.source};
    else { this.sweep.push(row); if (this.sweep.length > 200) this.sweep.splice(0, this.sweep.length - 200); }
    return row;
  }
  best() {
    let pool = this.positions.filter(p => !p.flags?.lowConfidence && fin(p.signal?.mean));
    if (!pool.length) pool = this.positions.filter(p => fin(p.signal?.mean));
    if (!pool.length) return null;
    const S = pool.reduce((a, b) => b.signal.mean > a.signal.mean ? b : a);
    const eligible = pool.filter(p => p.signal.mean >= S.signal.mean - 3 && compare(p, S, 'signal').verdict !== 'worse' && p.quality && fin(p.quality.mean));
    const Q = eligible.length ? eligible.reduce((a, b) => b.quality.mean > a.quality.mean ? b : a) : null;
    if (Q && Q !== S && compare(Q, S, 'quality').verdict === 'better') return {position:Q, basis:'quality'};
    return {position:S, basis:'signal'};
  }
  verdicts() {
    const out = new Map(), b = this.best();
    if (!b) return out;
    for (const p of this.positions) out.set(p.id, compare(p, b.position, b.basis));
    return out;
  }
  startLock(estimate) {
    const rs = (estimate?.readings || []).map(r => r.raw).filter(fin).slice(-2), b = this.best();
    const baseline = rs.length >= 2 ? mean(rs) : b ? b.position.signal.mean : estimate?.signal?.raw ?? null;
    this.lock = {baseline, band:Math.max(1.5, 2 * (estimate?.signal?.deadband || 0)), inBand:0, state:'watching', drop:null, reading:estimate?.signal?.reading ?? null};
    return this.lock;
  }
  offerLock(estimate) {
    const L = this.lock, s = estimate?.signal;
    if (!L) return null;
    if (!s || !fin(s.raw) || !fin(L.baseline) || (s.reading != null && s.reading === L.reading)) return L.state;
    L.reading = s.reading;
    if (s.raw < L.baseline - L.band) { L.inBand = 0; L.drop = L.baseline - s.raw; L.state = 'dropped'; }
    else { L.inBand++; L.state = L.inBand >= 3 ? 'locked' : 'watching'; }
    return L.state;
  }
  toJSON() { return {positions:this.positions, archived:this.archived, sweep:this.sweep, lock:this.lock}; }
}

export function roundTurn(deg) {
  const a = Math.abs(deg);
  if (!fin(a)) return {value:null, text:'a little', clamped:false};
  if (a < 4) return {value:Math.round(a), text:'a little', clamped:false};
  if (a < 45) { const v = Math.max(5, Math.round(a / 5) * 5); return {value:v, text:`about ${v}°`, clamped:false}; }
  return {value:45, text:'about 45°', clamped:true};
}

const G = (key, text, tone = 'quiet', arrow = 'none', detail = '') => ({key, text, detail, tone, arrow});
const secs = ms => fin(ms) ? Math.max(0, Math.round(ms / 1000)) : null;
function fitDetail(bearing, h, extra) {
  if (!bearing?.valid) return extra || '';
  const parts = [];
  if (fin(h)) {
    const g = bearing.gainAt(h), p = bearing.pWithinAt(h);
    if (fin(g)) parts.push(`Expected gain ${Math.max(0, g).toFixed(1)} dB`);
    if (fin(p)) parts.push(`${Math.round(p * 100)}% within 0.5 dB of the peak`);
  }
  if (fin(bearing.theta3)) parts.push(`beam about ${Math.round(bearing.theta3)}°`);
  return [parts.join(' · '), extra].filter(Boolean).join('. ');
}

export function guidance(ctx = {}) {
  const {step, estimate:est, snapshot:snap, capture, peak, bracket, lock, session, bearing, pose, best, lastSaved, cellChange} = ctx;
  const now = fin(ctx.now) ? ctx.now : Date.now();
  if (!snap) return G('connecting', 'Connecting to Titan…');
  if (snap.paused) return G('paused', 'Readings paused.');
  if (cellChange && (!fin(cellChange.t) || now - cellChange.t <= 10000))
    return G('cell-change', `Now on PCI ${cellChange.to} (was ${cellChange.from}). That is a different sector.`, 'attention');
  if (!snap.attached) return G('detached', 'Not connected to the network. Waiting to reconnect.', 'attention');
  const sig = est?.signal || {}, hasReading = sig.reading != null || fin(sig.raw);
  const freshness = snap.stale ? 'none' : est?.freshness;
  if (freshness === 'none' && (hasReading || !snap.connected)) {
    const age = secs(sig.ageMs ?? (fin(sig.t) ? now - sig.t : null));
    return G('stale', age === null ? 'No fresh reading. Check the link.' : `No fresh reading for ${age} s. Check the link.`, 'attention');
  }
  if (!hasReading) return G('first', "Waiting for the modem's first reading.", 'quiet', 'hold');
  if (capture) {
    const st = capture.status;
    if (st === 'failed' && (!fin(capture.at) || now - capture.at <= 8000)) return G('capture-fail', 'Signal not updating. Check the link.', 'attention');
    const live = st === 'collecting' || st === 'restarted';
    if (live && (st === 'restarted' || (fin(capture.restartedAt) && now - capture.restartedAt <= 4000))) return G('moved', 'Still moving? Holding again.', 'attention', 'hold');
    if (live && capture.n >= capture.need) return G('capture-quality', 'Hold still: waiting for a quality reading.', 'quiet', 'hold');
    if (live) return G('capture', `Hold still: ${capture.n} of ${capture.need} readings.`, 'quiet', 'hold');
  }
  if (lastSaved && now - (lastSaved.savedAt ?? lastSaved.t) <= 6000) return G('saved', `Position ${lastSaved.index} saved. Adjust and compare.`, 'go');
  const lk = lock ?? session?.lock;
  if (lk?.state === 'dropped') return G('lock-drop', `Dropped ${fin(lk.drop) ? lk.drop.toFixed(1) : '?'} dB while tightening. Loosen and nudge back.`, 'attention');
  if (lk?.state === 'locked') return G('locked', 'Locked. Record the install.', 'done');
  if (lk?.state === 'watching') return G('lock', 'Tighten the bolts. Watching for slips.', 'quiet', 'hold');
  const bs = bracket?.state;
  if (bs && bs !== 'idle') return G(`bracket-${bs}`, BRACKET_COPY[bs], 'go', bs === 'left' ? 'left' : bs === 'right' ? 'right' : bs === 'done' ? 'none' : 'hold');
  if (step === 'record' && !lk) return G('record', 'Review the results, then export.');
  if (freshness === 'old') return G('old', `Last reading ${secs(sig.ageMs ?? now - sig.t)} s old. Hold still.`, 'attention', 'hold');
  const hp = fin(pose?.heading) ? pose.heading : null, h = hp !== null && !!pose.relative === !!bearing?.relative ? hp : null;
  if (bearing?.valid && fin(h)) {
    if (bearing.fitOk) {
      const gain = bearing.gainAt(h);
      if (bearing.pWithinAt(h) >= 0.9 && gain < 0.3) return G('good-enough', 'Good spot. Lock it down.', 'done', 'hold', fitDetail(bearing, h));
      const diff = wrap180(bearing.recommended - h), [lo, hi] = bearing.hdi68 || [0, 0];
      if (Math.abs(diff) > Math.max(2 * (pose.sd || 0), norm360(hi - lo) / 2) && gain >= 0.3) {
        const rt = roundTurn(diff), dir = diff > 0 ? 'right' : 'left';
        const to = bearing.relative ? '' : ` (to ${norm360(Math.round(bearing.recommended))}°)`;
        return G('turn', `Turn ${rt.text} ${dir}${to}.`, 'go', dir, fitDetail(bearing, h, rt.clamped ? 'Check again after you turn.' : ''));
      }
    } else return G('irregular', 'Signal is irregular. Use the best marked position.', 'attention', 'none', fitDetail(bearing, h));
  } else if (bearing?.valid && !bearing.fitOk) return G('irregular', 'Signal is irregular. Use the best marked position.', 'attention', 'none', fitDetail(bearing, null));
  if (bearing?.edge) return G('try-side', `Try a position further ${bearing.edge}.`, 'go', bearing.edge, fitDetail(bearing, h));
  if (peak?.passed?.(est)) {
    const ph = peak.peak?.heading;
    if (fin(ph) && fin(hp)) {
      const diff = wrap180(ph - hp), rt = roundTurn(diff);
      return G('passed', `You passed the peak. Turn back ${rt.text}.`, 'go', diff > 0 ? 'right' : 'left', fitDetail(bearing, h, rt.clamped ? 'Check again after you turn.' : ''));
    }
    return G('passed', 'You passed the peak. Turn back to where it was strongest.', 'go', 'none', fitDetail(bearing, h));
  }
  const latest = session?.positions?.at(-1), bp = best?.position;
  if (step === 'confirm' && bp && latest && latest !== bp) {
    const v = compare(latest, bp, best.basis).verdict;
    if (v === 'worse') return G('go-back', `Position ${bp.index} is better. Go back to it.`, 'go');
    if (v === 'same') return G('same', `About the same as Position ${bp.index}. Either spot works.`, 'done');
  }
  if (peak?.atPeak?.(est)) return G('at-peak', 'This is the strongest spot so far. Mark it.', 'done', 'hold');
  if (sig.trend === 'up') return G('better', 'Better. Keep turning the same way.', 'go');
  if (sig.trend === 'down') return G('worse', 'Weaker. Turn back the other way.', 'attention');
  if (freshness === 'waiting') {
    const eta = est?.cadence?.signalEta, p50 = eta?.p50;
    const soon = !fin(p50) || eta.overdue || p50 <= 500;
    return G('wait', soon ? 'Hold still. Next reading any moment.' : `Hold still. Next reading in about ${Math.round(p50 / 1000)} s.`, 'quiet', 'hold');
  }
  if (step === 'peak') return G('nudge', 'Turn 2-5° at a time and mark the best spots.');
  if (step === 'confirm') return G('confirm', 'Mark the best spot again to confirm it.');
  if (step === 'record') return G('record', 'Review the results, then export.');
  return G('sweep', 'Turn about 15°, then hold until the ping.');
}
