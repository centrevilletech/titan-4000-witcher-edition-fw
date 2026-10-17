// Align feedback: sound, haptics, compass and wake lock. Pure helpers first; every
// browser API is touched only inside functions so node --test can import this file.
export const PATTERNS = {better:[35], worse:[15,60,15], steady:[10], peak:[40,40,40,40,120], mark:[80], fault:[200,100,200], click:[8]};
export const STALE_TICK_MS = 5000;
const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
const RAD = Math.PI/180;
const norm360 = d => { const x = ((d % 360) + 360) % 360; return x >= 360 - 1e-9 ? 0 : x; };
export const wrap180 = x => ((x + 540) % 360) - 180;

export function pitchAbsolute(signalDbm) {
  const q = clamp((signalDbm + 120)/45, 0, 1);
  return 440*2**(Math.round(24*(Number.isFinite(q) ? q : 0))/12);
}
export function pitchZoom(belowDb, deadband) {
  const b = clamp(Number.isFinite(belowDb) ? belowDb : 0, 0, 18);
  return 1320*2**(-Math.round(b/Math.max(Number.isFinite(deadband) ? deadband : 1, 1))/12);
}

// Note plan for one reading event (section 5.2); AlignAudio plays it, tests inspect it.
export function readingNotes({hz, trend = null, newPeak = false, atPeak = false}) {
  if (!(hz > 0)) return [];
  const third = 2**(4/12);
  const notes = newPeak ? [0, 4, 7].map((s, i) => ({hz:hz*2**(s/12), at:i*90, dur:200, gain:1}))
    : trend === 'up' ? [{hz:hz/third, at:0, dur:140, gain:1}, {hz, at:110, dur:140, gain:1}]
    : trend === 'down' ? [{hz:hz*third, at:0, dur:140, gain:1}, {hz, at:110, dur:140, gain:1}]
    : [{hz, at:0, dur:140, gain:1}];
  if (atPeak && !newPeak) { const last = notes[notes.length - 1]; notes.push({...last, hz:2*last.hz, gain:0.3}); }
  return notes;
}
export const staleTickDue = (lastTickMs, nowMs) => lastTickMs == null || nowMs - lastTickMs >= STALE_TICK_MS;

// Phone back pressed on the panel back, top edge up (Appendix B). Degrees in, degrees out.
export function poseFromEuler(alpha, beta, gamma) {
  const a = (alpha || 0)*RAD, b = (beta || 0)*RAD, g = (gamma || 0)*RAD;
  const vx = -Math.cos(a)*Math.sin(g) - Math.sin(a)*Math.sin(b)*Math.cos(g);
  const vy = -Math.sin(a)*Math.sin(g) + Math.cos(a)*Math.sin(b)*Math.cos(g);
  const up = -Math.cos(b)*Math.cos(g), upright = Math.abs(up) < 0.8;
  const heading = norm360(upright ? Math.atan2(vx, vy)/RAD : 360 - (alpha || 0));
  return {heading, tilt:Math.asin(clamp(-up, -1, 1))/RAD, upright};
}

export function circularStats(degs) {
  let s = 0, c = 0, n = 0;
  for (const d of degs) if (Number.isFinite(d)) { s += Math.sin(d*RAD); c += Math.cos(d*RAD); n++; }
  if (!n) return {mean:null, sd:null};
  const r = Math.min(1, Math.hypot(s, c)/n);
  return {mean:norm360(Math.atan2(s, c)/RAD), sd:r >= 1 ? 0 : r > 0 ? Math.sqrt(-2*Math.log(r))/RAD : 180};
}

// Unit-vector EMA so 359 -> 1 averages to 0, not 180; sd over a sliding window of raw headings.
export class HeadingFilter {
  constructor({alpha = 0.15, windowMs = 2000} = {}) { this.alpha = alpha; this.windowMs = windowMs; this.reset(); }
  reset() { this.sx = null; this.sy = null; this.buf = []; }
  push(deg, t) {
    const s = Math.sin(deg*RAD), c = Math.cos(deg*RAD), k = this.alpha;
    if (this.sx == null) { this.sx = s; this.sy = c; } else { this.sx = (1 - k)*this.sx + k*s; this.sy = (1 - k)*this.sy + k*c; }
    this.buf.push([t, deg]);
    while (this.buf.length && this.buf[0][0] < t - this.windowMs) this.buf.shift();
    return {heading:this.heading, sd:this.sd()};
  }
  span(now) { return this.buf.length ? now - this.buf[0][0] : 0; }
  get heading() { return this.sx == null ? null : norm360(Math.atan2(this.sx, this.sy)/RAD); }
  sd(sinceMs = -Infinity) { return circularStats(this.buf.filter(([t]) => t >= sinceMs).map(([, d]) => d)).sd; }
}

export function decimalYear(date) {
  const d = date instanceof Date ? date : new Date(date), y = d.getUTCFullYear();
  const start = Date.UTC(y, 0, 1), end = Date.UTC(y + 1, 0, 1);
  return y + (d.getTime() - start)/(end - start);
}

const WMM_EPOCH = 2025.0, WMM_A = 6371.2, WMM_N = 12;
// rows in COF order: [g, h, gdot, hdot] for n = 1..12, m = 0..n
const WMM = [[-29351.8,0.0,12.0,0.0],[-1410.8,4545.4,9.7,-21.5],[-2556.6,0.0,-11.6,0.0],[2951.1,-3133.6,-5.2,-27.7],[1649.3,-815.1,-8.0,-12.1],[1361.0,0.0,-1.3,0.0],[-2404.1,-56.6,-4.2,4.0],[1243.8,237.5,0.4,-0.3],[453.6,-549.5,-15.6,-4.1],[895.0,0.0,-1.6,0.0],[799.5,278.6,-2.4,-1.1],[55.7,-133.9,-6.0,4.1],[-281.1,212.0,5.6,1.6],[12.1,-375.6,-7.0,-4.4],[-233.2,0.0,0.6,0.0],[368.9,45.4,1.4,-0.5],[187.2,220.2,0.0,2.2],[-138.7,-122.9,0.6,0.4],[-142.0,43.0,2.2,1.7],[20.9,106.1,0.9,1.9],[64.4,0.0,-0.2,0.0],[63.8,-18.4,-0.4,0.3],[76.9,16.8,0.9,-1.6],[-115.7,48.8,1.2,-0.4],[-40.9,-59.8,-0.9,0.9],[14.9,10.9,0.3,0.7],[-60.7,72.7,0.9,0.9],[79.5,0.0,-0.0,0.0],[-77.0,-48.9,-0.1,0.6],[-8.8,-14.4,-0.1,0.5],[59.3,-1.0,0.5,-0.8],[15.8,23.4,-0.1,0.0],[2.5,-7.4,-0.8,-1.0],[-11.1,-25.1,-0.8,0.6],[14.2,-2.3,0.8,-0.2],[23.2,0.0,-0.1,0.0],[10.8,7.1,0.2,-0.2],[-17.5,-12.6,0.0,0.5],[2.0,11.4,0.5,-0.4],[-21.7,-9.7,-0.1,0.4],[16.9,12.7,0.3,-0.5],[15.0,0.7,0.2,-0.6],[-16.8,-5.2,-0.0,0.3],[0.9,3.9,0.2,0.2],[4.6,0.0,-0.0,0.0],[7.8,-24.8,-0.1,-0.3],[3.0,12.2,0.1,0.3],[-0.2,8.3,0.3,-0.3],[-2.5,-3.3,-0.3,0.3],[-13.1,-5.2,0.0,0.2],[2.4,7.2,0.3,-0.1],[8.6,-0.6,-0.1,-0.2],[-8.7,0.8,0.1,0.4],[-12.9,10.0,-0.1,0.1],[-1.3,0.0,0.1,0.0],[-6.4,3.3,0.0,0.0],[0.2,0.0,0.1,-0.0],[2.0,2.4,0.1,-0.2],[-1.0,5.3,-0.0,0.1],[-0.6,-9.1,-0.3,-0.1],[-0.9,0.4,0.0,0.1],[1.5,-4.2,-0.1,0.0],[0.9,-3.8,-0.1,-0.1],[-2.7,0.9,-0.0,0.2],[-3.9,-9.1,-0.0,-0.0],[2.9,0.0,0.0,0.0],[-1.5,0.0,-0.0,-0.0],[-2.5,2.9,0.0,0.1],[2.4,-0.6,0.0,-0.0],[-0.6,0.2,0.0,0.1],[-0.1,0.5,-0.1,-0.0],[-0.6,-0.3,0.0,-0.0],[-0.1,-1.2,-0.0,0.1],[1.1,-1.7,-0.1,-0.0],[-1.0,-2.9,-0.1,0.0],[-0.2,-1.8,-0.1,0.0],[2.6,-2.3,-0.1,0.0],[-2.0,0.0,0.0,0.0],[-0.2,-1.3,0.0,-0.0],[0.3,0.7,-0.0,0.0],[1.2,1.0,-0.0,-0.1],[-1.3,-1.4,-0.0,0.1],[0.6,-0.0,-0.0,-0.0],[0.6,0.6,0.1,-0.0],[0.5,-0.1,-0.0,-0.0],[-0.1,0.8,0.0,0.0],[-0.4,0.1,0.0,-0.0],[-0.2,-1.0,-0.1,-0.0],[-1.3,0.1,-0.0,0.0],[-0.7,0.2,-0.1,-0.1]];
export function declination(latDeg, lonDeg, altKm = 0, year = decimalYear(new Date())) {
  const dt = year - WMM_EPOCH, rad = Math.PI/180, a = 6378.137, f = 1/298.257223563, e2 = f*(2-f);
  const lat = latDeg*rad, lon = lonDeg*rad, sl = Math.sin(lat), cl = Math.cos(lat), Rc = a/Math.sqrt(1 - e2*sl*sl);
  const p = (Rc + altKm)*cl, z = (Rc*(1 - e2) + altKm)*sl, r = Math.hypot(p, z), phc = Math.asin(z/r);
  const st = Math.cos(phc), ct = Math.sin(phc), P = [], dP = [];
  for (let n = 0; n <= WMM_N; n++) { P.push(new Float64Array(WMM_N + 1)); dP.push(new Float64Array(WMM_N + 1)); }
  P[0][0] = 1;
  for (let n = 1; n <= WMM_N; n++) for (let m = 0; m <= n; m++) {
    if (n === m) { const k = n === 1 ? 1 : Math.sqrt((2*n - 1)/(2*n)); P[n][n] = k*st*P[n-1][n-1]; dP[n][n] = k*(st*dP[n-1][n-1] + ct*P[n-1][n-1]); }
    else { const k1 = (2*n - 1)/Math.sqrt(n*n - m*m), k2 = n - 1 >= m ? Math.sqrt(((n-1)*(n-1) - m*m)/(n*n - m*m)) : 0;
      P[n][m] = k1*ct*P[n-1][m] - (n - 2 >= m ? k2*P[n-2][m] : 0);
      dP[n][m] = k1*(ct*dP[n-1][m] - st*P[n-1][m]) - (n - 2 >= m ? k2*dP[n-2][m] : 0); }
  }
  let X = 0, Y = 0, Z = 0, i = 0;
  for (let n = 1; n <= WMM_N; n++) { const ar = Math.pow(WMM_A/r, n + 2);
    for (let m = 0; m <= n; m++, i++) { const [g0, h0, gd, hd] = WMM[i], g = g0 + gd*dt, h = h0 + hd*dt, cm = Math.cos(m*lon), sm = Math.sin(m*lon);
      X += ar*(g*cm + h*sm)*dP[n][m]; Z -= (n + 1)*ar*(g*cm + h*sm)*P[n][m]; Y += ar*m*(g*sm - h*cm)*P[n][m]/(st || 1e-12); } }
  const psi = phc - lat, Xg = X*Math.cos(psi) - Z*Math.sin(psi);
  return Math.atan2(Y, Xg)/rad;
}
// Alabama plane fit (max error 0.032 deg inside 30-35 N, 84.8-88.5 W, for 2026.75; drifts -0.065 deg/yr)
export const alabamaDeclination = (lat, lon, year) => lat < 30 || lat > 35 || lon < -88.5 || lon > -84.8 ? null
  : -3.9823 - 0.0845*(lat - 32.5) - 0.6618*(lon + 86.7) - 0.065*(year - 2026.75);

const hasWindow = () => typeof window !== 'undefined';
const nav = () => typeof navigator !== 'undefined' ? navigator : null;
const audioCtor = () => hasWindow() ? window.AudioContext || window.webkitAudioContext || null : null;

export class AlignAudio {
  #ctx = null; #out = null; #enabled = false; #lastHz = 880;
  get supported() { return !!audioCtor(); }
  get enabled() { return this.#enabled; }
  async enable() {
    const Ctor = audioCtor();
    if (!Ctor) return false;
    try {
      const n = nav();
      if (n?.audioSession) try { n.audioSession.type = 'playback'; } catch {}
      if (!this.#ctx) {
        const ctx = new Ctor(), master = ctx.createGain(), comp = ctx.createDynamicsCompressor();
        master.gain.value = 0.5; comp.threshold.value = -18; comp.ratio.value = 4;
        master.connect(comp).connect(ctx.destination);
        this.#ctx = ctx; this.#out = master;
      }
      await this.#ctx.resume();
      this.#enabled = this.#ctx.state === 'running';
    } catch { this.#enabled = false; }
    return this.#enabled;
  }
  disable() { this.#enabled = false; this.#ctx?.suspend?.().catch(() => {}); }
  #tone({hz, at = 0, dur = 140, gain = 1, type = 'triangle', attack = 0.005, flat = false}) {
    const ctx = this.#ctx;
    if (!this.#enabled || !ctx || ctx.state !== 'running' || !(hz > 0)) return;
    const t0 = ctx.currentTime + at/1000, end = t0 + dur/1000, osc = ctx.createOscillator(), env = ctx.createGain();
    osc.type = type; osc.frequency.setValueAtTime(hz, t0);
    env.gain.setValueAtTime(0, t0);
    env.gain.linearRampToValueAtTime(gain, t0 + Math.min(attack, dur/2000));
    if (flat) { env.gain.setValueAtTime(gain, end - 0.004); env.gain.linearRampToValueAtTime(0, end); }
    else env.gain.exponentialRampToValueAtTime(0.001*Math.max(gain, 0.01), end);
    osc.connect(env).connect(this.#out);
    osc.start(t0); osc.stop(end + 0.02);
    osc.onended = () => { osc.disconnect(); env.disconnect(); };
  }
  reading(event) {
    if (event?.hz > 0) this.#lastHz = event.hz;
    for (const n of readingNotes(event || {})) this.#tone(n);
  }
  click() { this.#tone({hz:2000, dur:8, gain:0.15, type:'square', attack:0.001}); }
  chime(hz = this.#lastHz) { this.#tone({hz}); this.#tone({hz:2*hz, at:120}); }
  fault() { for (const at of [0, 200]) this.#tone({hz:220, at, dur:120, gain:0.5, type:'square', flat:true}); }
  staleTick() { this.#tone({hz:300, dur:40, gain:0.4}); }
  suspend() { this.#ctx?.suspend?.().catch(() => {}); }
  resume() { if (this.#enabled) this.#ctx?.resume?.().catch(() => {}); }
}

export class Haptics {
  get supported() { return typeof nav()?.vibrate === 'function'; }
  pulse(name) {
    const p = PATTERNS[name];
    if (!p || !this.supported) return false;
    try { return nav().vibrate(p); } catch { return false; }
  }
}

const ROTATION_STILL = 3, STILL_MS = 1000, FIRST_EVENT_MS = 1500, NOTIFY_MS = 100;

export class Compass {
  #source = null; #handlers = []; #filter = new HeadingFilter(); #listeners = new Set();
  #raw = null; #offset = []; #lastFastT = null; #motionSeen = false; #notifiedT = 0;
  #loc = null; #wmm = null; #override = null; #firstEvent = null;
  static capabilities() {
    if (!hasWindow()) return {secure:false, absEvent:false, iosPerm:false, rel:false, motion:false};
    const secure = !!window.isSecureContext, DOE = window.DeviceOrientationEvent;
    return {secure, absEvent:secure && 'ondeviceorientationabsolute' in window,
      iosPerm:typeof DOE?.requestPermission === 'function', rel:'DeviceOrientationEvent' in window, motion:'DeviceMotionEvent' in window};
  }
  get active() { return !!this.#source; }
  get source() { return this.#source; }
  async start() {
    if (this.#source) return this.#source;
    const cap = Compass.capabilities();
    if (!hasWindow()) return 'none';
    if (!cap.secure) return 'insecure';
    if (!cap.rel) return 'none';
    let mode, event, perm = null;
    // Chromium also exposes requestPermission (it may answer 'prompt'), so the event is chosen by
    // capability: absolute events win, and the iOS compass path is only for browsers without them.
    if (cap.iosPerm) {
      try {
        // requestPermission must be the first await so it stays inside the user gesture.
        const motion = window.DeviceMotionEvent?.requestPermission ? window.DeviceMotionEvent.requestPermission() : null;
        perm = await window.DeviceOrientationEvent.requestPermission();
        await motion?.catch(() => 'denied');
      } catch { perm = 'denied'; }
      if (perm === 'denied' && !cap.absEvent) return 'denied';
    }
    if (cap.absEvent) { mode = 'abs'; event = 'deviceorientationabsolute'; }
    else if (cap.iosPerm) { mode = 'ios'; event = 'deviceorientation'; }
    else { mode = 'rel'; event = 'deviceorientation'; }
    this.#reset();
    const got = new Promise(resolve => { this.#firstEvent = resolve; });
    this.#listen(event, e => this.#orientation(e, mode));
    if (cap.motion) this.#listen('devicemotion', e => this.#motion(e));
    this.#source = mode;
    const ok = await Promise.race([got.then(() => true), new Promise(r => setTimeout(() => r(false), FIRST_EVENT_MS))]);
    if (!ok) { this.stop(); return perm === 'denied' ? 'denied' : 'none'; }
    return mode;
  }
  stop() {
    for (const [type, fn] of this.#handlers) window.removeEventListener(type, fn);
    this.#handlers = []; this.#source = null; this.#firstEvent = null;
  }
  #listen(type, fn) { window.addEventListener(type, fn); this.#handlers.push([type, fn]); }
  #reset() { this.#filter.reset(); this.#raw = null; this.#offset = []; this.#lastFastT = null; this.#motionSeen = false; }
  #motion(e) {
    const r = e.rotationRate;
    if (!r || r.alpha == null && r.beta == null && r.gamma == null) return;
    this.#motionSeen = true;
    if (Math.hypot(r.alpha || 0, r.beta || 0, r.gamma || 0) >= ROTATION_STILL || this.#lastFastT == null) this.#lastFastT = Date.now();
  }
  #orientation(e, mode) {
    if (e.alpha == null) return;
    const t = Date.now();
    let source = mode, relative = false, accuracy = null, base;
    if (mode === 'ios' && Number.isFinite(e.webkitCompassHeading)) {
      accuracy = Number.isFinite(e.webkitCompassAccuracy) ? e.webkitCompassAccuracy : null;
      // The iOS compass heading is only trustworthy near flat; learn the alpha offset there.
      if (Math.abs(e.beta) < 45 && Math.abs(e.gamma) < 45 && accuracy != null && accuracy >= 0 && accuracy <= 20) {
        this.#offset.push(e.webkitCompassHeading - (360 - e.alpha));
        if (this.#offset.length > 60) this.#offset.shift();
      }
      const offset = circularStats(this.#offset).mean;
      if (offset == null) { base = {...poseFromEuler(e.alpha, e.beta, e.gamma), heading:norm360(e.webkitCompassHeading)}; source = 'ios-raw'; }
      else base = poseFromEuler(e.alpha - offset, e.beta, e.gamma);
    } else {
      base = poseFromEuler(e.alpha, e.beta, e.gamma);
      if (mode === 'ios') { source = 'rel'; relative = true; }
      else if (mode === 'rel') relative = !e.absolute;
    }
    this.#filter.push(base.heading, t);
    this.#raw = {...base, source, relative, accuracy, t};
    this.#firstEvent?.(); this.#firstEvent = null;
    if (t - this.#notifiedT >= NOTIFY_MS && this.#listeners.size) {
      this.#notifiedT = t;
      const pose = this.pose();
      for (const fn of this.#listeners) try { fn(pose); } catch {}
    }
  }
  get declination() { return this.#override ?? this.#wmm; }
  setLocation(lat, lon, altM) {
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) { this.#loc = null; this.#wmm = null; return; }
    const altKm = Number.isFinite(altM) ? altM/1000 : 0, l = this.#loc;
    if (l && Math.abs(l.lat - lat) < 0.01 && Math.abs(l.lon - lon) < 0.01) return;
    this.#loc = {lat, lon, altKm};
    this.#wmm = declination(lat, lon, altKm, decimalYear(new Date()));
  }
  setDeclinationOverride(deg) { this.#override = Number.isFinite(deg) ? deg : null; }
  pose() {
    const raw = this.#raw;
    if (!raw || !this.#source) return null;
    const now = Date.now(), smooth = this.#filter.heading, sd = this.#filter.sd() ?? 180;
    const still = this.#motionSeen ? this.#lastFastT != null && now - this.#lastFastT >= STILL_MS
      : this.#filter.span(now) >= STILL_MS && (this.#filter.sd(now - STILL_MS) ?? 180) < 1.5;
    const decl = raw.relative ? null : this.declination;
    const heading = raw.relative || decl == null ? smooth : norm360(smooth + decl);
    const accOk = raw.source === 'ios' || raw.source === 'ios-raw' ? raw.accuracy != null && raw.accuracy >= 0 && raw.accuracy <= 15 : true;
    return {heading, magnetic:raw.relative ? null : smooth, declination:decl, relative:raw.relative, sd, tilt:raw.tilt,
      upright:raw.upright, still, valid:still && sd < 3 && raw.upright && accOk, source:raw.source, accuracy:raw.accuracy, t:raw.t};
  }
  onChange(fn) { this.#listeners.add(fn); return () => this.#listeners.delete(fn); }
}

export class WakeLockManager {
  #sentinel = null; #wanted = false; #bound = false;
  get supported() { return typeof nav()?.wakeLock?.request === 'function'; }
  get active() { return !!this.#sentinel && !this.#sentinel.released; }
  async request() {
    this.#wanted = true;
    if (!this.#bound && typeof document !== 'undefined') {
      this.#bound = true;
      // The browser drops the lock whenever the tab hides; take it back on return.
      document.addEventListener('visibilitychange', () => { if (this.#wanted && !document.hidden && !this.active) this.#acquire(); });
    }
    return this.#acquire();
  }
  async #acquire() {
    if (!this.supported) return false;
    if (this.active) return true;
    try {
      const s = await nav().wakeLock.request('screen');
      s.addEventListener?.('release', () => { if (this.#sentinel === s) this.#sentinel = null; });
      if (!this.#wanted) { s.release().catch(() => {}); return false; }
      this.#sentinel = s;
      return true;
    } catch { return false; }
  }
  async release() {
    this.#wanted = false;
    const s = this.#sentinel; this.#sentinel = null;
    try { await s?.release(); } catch {}
  }
}
