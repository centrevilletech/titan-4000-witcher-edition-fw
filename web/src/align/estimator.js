// Event-driven level estimation for the Align screen (spec section 4.1).
// Everything here advances only on a NEW modem sample (seq change), never on the poll clock,
// so a faster source drops in without retuning. Pure module: no browser globals.

export const PROFILES = {
  rsrp: {q:0.1, r0:0.25, rMin:0.01, rMax:9,  qS:0.005, qM:2.0, huber:Infinity, band:1.0},
  cinr: {q:0.1, r0:0.5,  rMin:0.05, rMax:16, qS:0.01,  qM:3.0, huber:2.0,      band:1.0},
  sinr: {q:1.0, r0:1.0,  rMin:0.10, rMax:16, qS:0.01,  qM:3.0, huber:2.0,      band:1.0},
  rsrq: {q:0.1, r0:0.25, rMin:0.02, rMax:9,  qS:0.005, qM:1.0, huber:Infinity, band:0.5},
};
export const LIMITS = {zMove:3, zSettle:1.5, settleCount:2, minSettledN:3, cusumK:0.5, cusumH:4,
  lambdaR:0.9, diffWin:10, dtFloorS:0.2, gapResetMs:30000, oldMs:10000, noneMs:30000};

const finite = (v) => typeof v === 'number' && Number.isFinite(v);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const finites = (list) => (Array.isArray(list) ? list.filter(finite) : []);

function quantile(values, p) {
  const s = [...values].sort((a, b) => a - b);
  if (!s.length) return null;
  const i = (s.length - 1) * p, lo = Math.floor(i), hi = Math.ceil(i);
  return s[lo] + (s[hi] - s[lo]) * (i - lo);
}
const median = (values) => quantile(values, 0.5);

export function powerMean(dbs) {
  const v = finites(dbs);
  if (!v.length) return null;
  return 10 * Math.log10(v.reduce((a, x) => a + 10 ** (x / 10), 0) / v.length);
}

// Linear-power mean of filtered chains; weights follow each chain's share of the power.
// Optional R on the inputs is combined the same way; quantum sets the resolution floor on sd.
export function combine(states, {quantum = 0} = {}) {
  const s = (states || []).filter((c) => c && finite(c.value) && finite(c.sd));
  if (!s.length) return null;
  const p = s.map((c) => 10 ** (c.value / 10)), sum = p.reduce((a, x) => a + x, 0);
  const w = p.map((x) => x / sum);
  const variance = s.reduce((a, c, i) => a + w[i] ** 2 * c.sd ** 2, 0);
  const out = {value: 10 * Math.log10(sum / s.length), sd: Math.max(Math.sqrt(variance), quantum / Math.sqrt(12))};
  if (s.every((c) => finite(c.R))) out.R = s.reduce((a, c, i) => a + w[i] ** 2 * c.R, 0);
  return out;
}

// Switched-noise scalar Kalman level filter: tiny process noise while settled, large while
// moving, with z-test + CUSUM switching, Huber down-weighting and a learned reading variance.
export class LevelFilter {
  constructor(profile) {
    this.p = profile;
    this.reset();
  }

  reset() {
    this.x = null; this.P = null; this.t = null; this.R = this.p.r0; this.rHat = this.p.r0; this.mode = 'moving'; this.key = undefined;
    this.calm = 0; this.nSince = 0; this.gp = 0; this.gn = 0; this.win = []; this.diffs = []; this.n = 0;
    this.prev = null;
  }

  #save() {
    const {x, P, t, R, rHat, mode, calm, nSince, gp, gn, n} = this;
    return {x, P, t, R, rHat, mode, calm, nSince, gp, gn, n, win: [...this.win], diffs: [...this.diffs]};
  }

  // key names the reading: a revision only undoes the previous update when it belonged to the same
  // reading, otherwise a chain missing on the first sample would erase the reading before it.
  update(y, tMs, {weight = 1, revise = false, key} = {}) {
    if (!finite(y)) return this.state();
    if (revise && this.prev && key === this.key) Object.assign(this, this.prev, {win: [...this.prev.win], diffs: [...this.prev.diffs]});
    this.prev = this.#save();
    this.key = key;
    const tOk = finite(tMs);
    const L = LIMITS, p = this.p;
    const count = () => { if (weight >= 1) this.n++; };
    if (this.x === null) {
      this.x = y; this.P = this.R; this.t = tOk ? tMs : null; this.nSince = 1; this.win = [y]; this.mode = 'moving';
      count();
      return this.state();
    }
    const dt = tOk && this.t !== null ? Math.max(L.dtFloorS, (tMs - this.t) / 1000) : L.dtFloorS;
    if (tOk) this.t = tMs;
    const Reff = this.R / weight;
    const nu = y - this.x;
    const z = nu / Math.sqrt(this.P + p.qS * dt + Reff);
    const az = Math.abs(z);
    this.gp = Math.max(0, this.gp + z - L.cusumK);
    this.gn = Math.max(0, this.gn - z - L.cusumK);
    if (az > L.zMove || this.gp > L.cusumH || this.gn > L.cusumH) {
      this.mode = 'moving'; this.calm = 0; this.nSince = 0; this.gp = 0; this.gn = 0; this.win = [];
    } else if (this.mode === 'moving' && az < L.zSettle) {
      if (++this.calm >= L.settleCount) this.mode = 'settled';
    } else if (az >= L.zSettle) this.calm = 0;
    const Pm = this.P + (this.mode === 'moving' ? p.qM : p.qS) * dt;
    const w = this.mode === 'settled' && az > p.huber ? p.huber / az : 1;
    const K = Pm / (Pm + Reff / w);
    this.x += K * nu;
    this.P = (1 - K) * Pm;
    if (this.mode === 'settled') {
      const eps = y - this.x;
      const r = eps ** 2 + this.P, floor = p.q ** 2 / 12 + p.rMin;
      const rRes = L.lambdaR * this.R + (1 - L.lambdaR) * r;
      if (this.win.length) {
        this.diffs.push(Math.abs(y - this.win.at(-1)));
        if (this.diffs.length > L.diffWin) this.diffs.shift();
      }
      const rDiff = this.diffs.length >= 4 ? ((1.4826 * median(this.diffs)) / Math.SQRT2) ** 2 : 0;
      // The max of two noisy estimates runs 1.6-1.75x high: kept only for move switching, where a
      // low R would cause false moves. Everything downstream gets the residual estimate rHat.
      this.R = Math.min(p.rMax, Math.max(floor, rRes, rDiff));
      this.rHat = clamp(L.lambdaR * this.rHat + (1 - L.lambdaR) * r, floor, p.rMax);
    }
    this.nSince++;
    this.win.push(y);
    if (this.win.length > 3) this.win.shift();
    count();
    return this.state();
  }

  settled(nowMs) {
    if (this.mode !== 'settled' || this.nSince < LIMITS.minSettledN || !(nowMs - this.t <= LIMITS.oldMs)) return false;
    const m = this.win.reduce((a, v) => a + v, 0) / this.win.length;
    const tol = Math.max(2 * Math.sqrt(this.R), this.p.band);
    return this.win.every((v) => Math.abs(v - m) <= tol);
  }

  state() {
    if (this.x === null) return {value: null, sd: null, lo: null, hi: null, mode: 'moving', R: this.rHat, n: this.n};
    const sd = Math.sqrt(Math.max(this.P, this.p.q ** 2 / 12));
    return {value: this.x, sd, lo: this.x - 1.96 * sd, hi: this.x + 1.96 * sd, mode: this.mode, R: this.rHat, n: this.n};
  }
}

// Gap statistics of independent readings: EWMA expectation and an empirical
// conditional "next reading in" distribution (waiting-time paradox aware).
export class Cadence {
  constructor({initialMs, priorMs}) {
    this.initialMs = initialMs;
    this.priorMs = priorMs;
    this.reset();
  }

  reset() {
    this.gaps = []; this.lastT = null; this.exp = clamp(this.initialMs, 500, 20000);
  }

  observe(tMs) {
    if (!finite(tMs)) return;
    if (this.lastT !== null) {
      if (tMs <= this.lastT) return;
      const gap = tMs - this.lastT;
      if (gap >= 300 && gap <= 30000) {
        this.gaps.push(gap);
        if (this.gaps.length > 30) this.gaps.shift();
        this.exp = clamp(0.3 * gap + 0.7 * this.exp, 500, 20000);
      }
    }
    this.lastT = tMs;
  }

  get expected() { return this.exp; }

  eta(nowMs) {
    if (this.lastT === null) return {p50: null, p90: null, overdue: false};
    const e = nowMs - this.lastT;
    const G = this.gaps.length >= 5 ? this.gaps : this.priorMs;
    const S = G.filter((g) => g > e).map((g) => g - e);
    if (S.length >= 3) return {p50: median(S), p90: quantile(S, 0.9), overdue: false};
    return {p50: null, p90: null, overdue: e > Math.max(...G)};
  }
}

// PCI is fresh on every poll but ECI follows the modem's ~8 s refresh. An ECI change only counts when
// both sides are known and the PCI has held for one refresh, so a late or blank ECI is never a new cell.
export class CellTracker {
  constructor(holdMs = 10000) { this.holdMs = holdMs; this.reset(); }
  reset() { this.pci = null; this.eci = null; this.since = null; }
  offer(pci, eci, nowMs) {
    if (pci == null) return false;
    eci ??= null;
    if (this.pci === null || pci !== this.pci) {
      const changed = this.pci !== null;
      this.pci = pci; this.eci = eci; this.since = nowMs;
      return changed;
    }
    if (eci === null) return false;
    if (this.eci === null || !(nowMs - this.since >= this.holdMs)) { this.eci = eci; return false; }
    if (eci === this.eci) return false;
    this.eci = eci; this.since = nowMs;
    return true;
  }
}

const EMPTY_EVENT = () => ({signal: null, quality: null, reset: null});
const trendOf = (delta, deadband) => (delta === null ? null : delta >= deadband ? 'up' : delta <= -deadband ? 'down' : 'steady');

export class SignalEstimator {
  constructor({profiles = PROFILES} = {}) {
    this.profiles = profiles;
    this.cadenceS = new Cadence({initialMs: 2500, priorMs: [1000, 2500, 4000, 6000]});
    this.cadenceQ = new Cadence({initialMs: 8300, priorMs: [7400, 8200, 8300, 9200]});
    // Source trackers survive resets so a pre-reset sample is never consumed twice.
    this.lastSignalSeq = null; this.lastQualitySeq = null; this.cells = new CellTracker();
    this.detached = false; this.connected = false; this.now = 0; this.resets = 0; this.chainsN = 2;
    this.#clear();
  }

  #clear() {
    this.rsrp = []; this.rsrq = new LevelFilter(this.profiles.rsrq);
    this.cinr = []; this.sinr = new LevelFilter(this.profiles.sinr); this.qualitySource = null;
    this.sig = null; this.qual = null; this.n = 0; this.nQ = 0; this.readings = [];
    this.lastReading = null; this.lastReadingT = null; this.lastReadingRaw = null; this.prevReadingRaw = null;
    this.lastQualityRaw = null; this.latestQualityRaw = null;
  }

  reset(reason = 'manual') {
    this.#clear();
    this.resets++;
    if (reason === 'detach') { this.cadenceS.reset(); this.cadenceQ.reset(); this.cells.reset(); }
  }

  #chainFilter(list, c, profile) {
    return (list[c] ??= new LevelFilter(profile));
  }

  #combined(list, profile, nowMs) {
    const fs = list.slice(0, this.chainsN).filter((f) => f && f.x !== null);
    if (!fs.length) return null;
    const c = combine(fs.map((f) => f.state()), {quantum: profile.q});
    return {...c, lo: c.value - 1.96 * c.sd, hi: c.value + 1.96 * c.sd,
      mode: fs.some((f) => f.mode === 'moving') ? 'moving' : 'settled', settled: fs.every((f) => f.settled(nowMs)),
      since: Math.min(...fs.map((f) => f.nSince))};
  }

  #qualityLevel(nowMs) {
    if (this.qualitySource === 'cinr') return this.#combined(this.cinr, this.profiles.cinr, nowMs);
    if (this.qualitySource !== 'sinr' || this.sinr.x === null) return null;
    const s = this.sinr.state();
    return {value: s.value, sd: s.sd, lo: s.lo, hi: s.hi, R: s.R, mode: s.mode, settled: this.sinr.settled(nowMs)};
  }

  #signalDeadband(level) {
    return clamp(2 * Math.sqrt(2 * (level?.R ?? this.profiles.rsrp.r0)), 0.5, 3.0);
  }

  #qualityDeadband(level) {
    const r0 = this.profiles[this.qualitySource === 'sinr' ? 'sinr' : 'cinr'].r0;
    return clamp(2 * Math.sqrt(2 * (level?.R ?? r0)), 1.0, 4.0);
  }

  ingest(snapshot, nowMs = Date.now()) {
    this.now = nowMs;
    const event = EMPTY_EVENT();
    if (!snapshot) { this.connected = false; return event; }
    this.connected = !!snapshot.connected;
    if (snapshot.paused) return event;
    if (!snapshot.attached) {
      if (!this.detached) { this.detached = true; this.reset('detach'); event.reset = 'detach'; }
      return event;
    }
    this.detached = false;
    const cell = snapshot.cell || {};
    if (this.cells.offer(cell.pci, cell.eci, nowMs)) { this.reset('cell'); event.reset = 'cell'; }
    if (finite(snapshot.activeChains) && snapshot.activeChains >= 1) this.chainsN = snapshot.activeChains;

    const S = snapshot.signal;
    // A legacy heartbeat repeats an unchanged value: it only proves the source is alive, so it ages
    // the reading but never feeds filters, cadence or the reading log.
    if (S && S.seq !== this.lastSignalSeq && S.heartbeat && this.sig) {
      this.sig = {...this.sig, seq: S.seq, t: S.t, heartbeat: true};
      this.lastSignalSeq = S.seq; this.lastReading = S.reading; this.lastReadingT = S.readingT;
      event.signal = 'heartbeat';
    } else if (S && S.seq !== this.lastSignalSeq) {
      const isNew = S.reading !== this.lastReading;
      if (isNew && this.lastReadingT !== null && S.readingT - this.lastReadingT > LIMITS.gapResetMs) {
        this.reset('gap');
        event.reset ??= 'gap';
      }
      const weight = S.heartbeat ? 0.5 : 1, revise = !isNew;
      const rsrp = Array.isArray(S.rsrp) ? S.rsrp : [];
      for (let c = 0; c < this.chainsN; c++) {
        if (finite(rsrp[c])) this.#chainFilter(this.rsrp, c, this.profiles.rsrp).update(rsrp[c], S.t, {weight, revise, key: S.reading});
      }
      const rq = finites(S.rsrq);
      const rsrqMean = rq.length ? rq.reduce((a, v) => a + v, 0) / rq.length : null;
      if (rsrqMean !== null) this.rsrq.update(rsrqMean, S.t, {revise, key: S.reading});
      const raw = powerMean(rsrp);
      const fin = finites(rsrp);
      if (isNew) {
        this.prevReadingRaw = this.lastReadingRaw;
        this.cadenceS.observe(S.readingT);
        if (!S.heartbeat) this.n++;
      }
      const level = this.#combined(this.rsrp, this.profiles.rsrp, nowMs);
      const delta = this.prevReadingRaw === null || raw === null ? null : raw - this.prevReadingRaw;
      const deadband = this.#signalDeadband(level);
      this.sig = {seq: S.seq, reading: S.reading, t: S.t, readingT: S.readingT, raw, chains: [...rsrp],
        best: fin.length ? Math.max(...fin) : null,
        imbalance: finite(rsrp[0]) && finite(rsrp[1]) ? rsrp[0] - rsrp[1] : null,
        rsrqRaw: rsrqMean, delta, trend: trendOf(delta, deadband), heartbeat: !!S.heartbeat};
      const row = {reading: S.reading, t: S.t, raw, chains: [...rsrp], est: level?.value ?? null, sd: level?.sd ?? null,
        quality: this.latestQualityRaw};
      if (isNew || !this.readings.length) {
        this.readings.push(row);
        if (this.readings.length > 120) this.readings.shift();
      } else this.readings[this.readings.length - 1] = row;
      this.lastReadingRaw = raw; this.lastReading = S.reading; this.lastReadingT = S.readingT; this.lastSignalSeq = S.seq;
      event.signal = isNew ? 'new' : 'revised';
    }

    const Q = snapshot.quality;
    if (Q && Q.seq !== this.lastQualitySeq) {
      const cinr = Array.isArray(Q.cinr) ? Q.cinr : [];
      const src = finites(cinr).length ? 'cinr' : finite(Q.sinr) ? 'sinr' : null;
      if (src && src !== this.qualitySource) {
        this.cinr = []; this.sinr = new LevelFilter(this.profiles.sinr); this.lastQualityRaw = null; this.qualitySource = src;
      }
      let raw = null;
      if (src === 'cinr') {
        for (let c = 0; c < this.chainsN; c++) {
          if (finite(cinr[c])) this.#chainFilter(this.cinr, c, this.profiles.cinr).update(cinr[c], Q.t);
        }
        raw = powerMean(cinr.slice(0, this.chainsN));
      } else if (src === 'sinr') {
        this.sinr.update(Q.sinr, Q.t);
        raw = Q.sinr;
      }
      if (src) {
        const level = this.#qualityLevel(nowMs);
        const delta = this.lastQualityRaw === null || raw === null ? null : raw - this.lastQualityRaw;
        this.qual = {seq: Q.seq, t: Q.t, raw, chains: [...cinr], sinr: finite(Q.sinr) ? Q.sinr : null,
          step: src === 'sinr' ? (finite(Q.sinrStep) ? Q.sinrStep : 1) : 0.1,
          delta, trend: trendOf(delta, this.#qualityDeadband(level))};
        this.lastQualityRaw = raw; this.latestQualityRaw = raw;
        this.cadenceQ.observe(Q.t);
        this.nQ++;
      }
      this.lastQualitySeq = Q.seq;
      if (src) event.quality = 'new';
    }
    return event;
  }

  get state() { return this.stateAt(this.now); }

  // Same as `state` but aged to nowMs (for the freshness ring between polls). Never feeds filters.
  stateAt(nowMs = this.now) {
    this.now = nowMs;
    const sig = this.sig, qual = this.qual;
    const level = this.#combined(this.rsrp, this.profiles.rsrp, nowMs);
    const qLevel = this.#qualityLevel(nowMs);
    const E = this.cadenceS.expected;
    const age = sig ? nowMs - sig.t : null;
    const freshness = !sig || !this.connected || age > LIMITS.noneMs ? 'none'
      : age > LIMITS.oldMs ? 'old' : age > 2 * E ? 'waiting' : 'live';
    const f0 = this.rsrp[0], f1 = this.rsrp[1];
    const imbalanceEst = this.chainsN >= 2 && f0?.x != null && f1?.x != null ? f0.x - f1.x : null;
    const rsrqState = this.rsrq.state();
    return {
      t: nowMs,
      freshness,
      signal: {
        seq: sig?.seq ?? null, reading: sig?.reading ?? null, t: sig?.t ?? null, readingT: sig?.readingT ?? null, ageMs: age,
        raw: sig?.raw ?? null, chains: sig ? [...sig.chains] : [], best: sig?.best ?? null,
        imbalance: sig?.imbalance ?? null, imbalanceEst,
        est: level?.value ?? null, sd: level?.sd ?? null, lo: level?.lo ?? null, hi: level?.hi ?? null, R: level?.R ?? null,
        mode: level?.mode ?? null, settled: !!level?.settled, since: level?.since ?? 0,
        trend: sig?.trend ?? null, delta: sig?.delta ?? null, deadband: this.#signalDeadband(level),
        n: this.n, heartbeat: !!sig?.heartbeat,
      },
      quality: {
        seq: qual?.seq ?? null, t: qual?.t ?? null, ageMs: qual ? nowMs - qual.t : null, source: this.qualitySource,
        step: qual?.step ?? (this.qualitySource === 'sinr' ? 1 : 0.1),
        raw: qual?.raw ?? null, chains: qual ? [...qual.chains] : [], sinr: qual?.sinr ?? null,
        est: qLevel?.value ?? null, sd: qLevel?.sd ?? null, lo: qLevel?.lo ?? null, hi: qLevel?.hi ?? null, R: qLevel?.R ?? null,
        mode: qLevel?.mode ?? null, settled: !!qLevel?.settled,
        trend: qual?.trend ?? null, delta: qual?.delta ?? null, deadband: this.#qualityDeadband(qLevel), n: this.nQ,
      },
      rsrq: {raw: sig?.rsrqRaw ?? null, est: rsrqState.value, sd: rsrqState.sd},
      cadence: {signalMs: E, qualityMs: this.cadenceQ.expected,
        signalEta: this.cadenceS.eta(nowMs), qualityEta: this.cadenceQ.eta(nowMs)},
      readings: this.readings.map((r) => ({...r, chains: [...r.chains]})),
      resets: this.resets,
    };
  }
}
