// Link prediction: SINR -> CQI -> MCS -> TBS for Band 48 TDD carriers (spec 3b, 4.6).

export const CQI64 = { // TS 36.213 Table 7.2.3-1, CQI 1..15
  mod: ['QPSK','QPSK','QPSK','QPSK','QPSK','QPSK','16QAM','16QAM','16QAM','64QAM','64QAM','64QAM','64QAM','64QAM','64QAM'],
  rate:[78,120,193,308,449,602,378,490,616,466,567,666,772,873,948],
  eff: [0.1523,0.2344,0.3770,0.6016,0.8770,1.1758,1.4766,1.9141,2.4063,2.7305,3.3223,3.9023,4.5234,5.1152,5.5547],
  thr: [-6.7,-4.7,-2.3,0.2,2.4,4.3,5.9,8.1,10.3,11.7,14.1,16.3,18.7,21.0,22.7],   // 10% BLER SISO AWGN (simulator values, calibrate)
  mcs: [0,0,1,3,6,7,11,13,15,17,20,21,23,25,28]
};
export const CQI256 = { // TS 36.213 Table 7.2.3-2
  mod: ['QPSK','QPSK','QPSK','16QAM','16QAM','16QAM','64QAM','64QAM','64QAM','64QAM','64QAM','256QAM','256QAM','256QAM','256QAM'],
  rate:[78,193,449,378,490,616,466,567,666,772,873,711,797,885,948],
  eff: [0.1523,0.3770,0.8770,1.4766,1.9141,2.4063,2.7305,3.3223,3.9023,4.5234,5.1152,5.5547,6.2266,6.9141,7.4063],
  thr: [-6.7,-2.3,2.4,5.9,8.1,10.3,11.7,14.1,16.3,18.7,21.0,22.7,24.6,26.6,28.2],  // 13-15 extrapolated
  mcs: [0,0,3,5,7,9,10,13,14,16,18,21,23,25,27]
};
// TS 36.213 Table 7.1.7.1-1 (PDSCH, 64QAM), 7.1.7.1-1A (256QAM), 8.6.1-1 (PUSCH): MCS index -> I_TBS
export const MCS_ITBS_64  = [0,1,2,3,4,5,6,7,8,9,9,10,11,12,13,14,15,15,16,17,18,19,20,21,22,23,24,25,26];
export const MCS_ITBS_256 = [0,2,4,6,8,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,27,28,29,30,31,32,33];
export const MCS_ITBS_UL  = [0,1,2,3,4,5,6,7,8,9,10,10,11,12,13,14,15,16,17,18,19,19,20,21,22,23,24,25,26];
// TS 36.213 Table 7.1.7.2.1-1, one layer, rows I_TBS 0..33 (27..33 are the Rel-12 256QAM rows; row 27 < row 26 by design).
export const TBS = {
  100:[2792,3624,4584,5736,7224,8760,10296,12216,14112,15840,17568,19848,22920,25456,28336,30576,32856,36696,39232,43816,46888,51024,55056,57336,61664,63776,75376,66592,71112,73712,78704,81176,84760,97896],
  75: [2088,2728,3368,4392,5352,6712,7736,9144,10680,11832,12960,15264,16992,19080,21384,22920,24496,27376,29296,32856,35160,37888,40576,43816,45352,46888,55056,48936,52752,55056,59256,61664,63776,75376],
  56: [1544,2024,2536,3240,4008,4968,5992,6712,7736,8760,9912,11448,12576,14688,15840,16992,18336,20616,22152,24496,26416,28336,30576,31704,34008,35160,40576,36696,39232,42368,43816,46888,46888,55056],
  50: [1384,1800,2216,2856,3624,4392,5160,6200,6968,7992,8760,9912,11448,12960,14112,15264,16416,18336,19848,21384,22920,25456,27376,28336,30576,31704,36696,32856,35160,36696,39232,40576,42368,48936],
  37: [1032,1352,1672,2152,2664,3240,3880,4584,5160,5736,6456,7480,8504,9528,10680,11448,12216,13536,14688,15840,16992,18336,19848,21384,22920,23688,27376,24496,26416,27376,29296,30576,31704,36696],
  25: [680,904,1096,1416,1800,2216,2600,3112,3496,4008,4392,4968,5736,6456,7224,7736,7992,9144,9912,10680,11448,12576,13536,14112,15264,15840,18336,16416,17568,18336,19848,20616,21384,24496],
  18: [488,632,776,1032,1288,1544,1864,2216,2536,2856,3112,3624,4136,4584,5160,5544,5992,6456,7224,7736,8248,9144,9528,10296,11064,11448,13536,11832,12576,13536,14112,14688,15264,17568]
};
export const PRB_DL = {5:25, 10:50, 15:75, 20:100};
export const PRB_UL = {5:24, 10:48, 15:72, 20:96};
export const DWPTS_PRB = {25:18, 50:37, 75:56, 100:75};      // floor(0.75*N_PRB)
// TS 36.211 Table 4.2-2: [D, S, U] subframes per 10 ms for UL/DL configuration 0..6
export const TDD = {0:[2,2,6], 1:[4,2,4], 2:[6,2,2], 3:[6,1,3], 4:[7,1,2], 5:[8,1,1], 6:[3,2,5]};
export const DEFAULTS = {rankOffset:{cinr:{1:-1.5, 2:-4.4}, sinr:{1:-1.5, 2:-5.0}}, eta:0.85, catBitsPerTti:452256, ulGapDb:8, tdd:{sa:2, ssp:7}};

const Z = 1.645;
// DwPTS PDSCH: SSF 0 and 5 carry none, SSF 9 uses 0.375*N_PRB, the rest 0.75*N_PRB.
const dwpts = ssp => (ssp === 0 || ssp === 5) ? 0 : ssp === 9 ? 0.375 : 0.75;
const frame = tdd => TDD[tdd?.sa] ? tdd : DEFAULTS.tdd;

export function cqiFromSinr(sinrEff, table) {
  let c = 0;
  for (let i = 0; i < 15; i++) if (sinrEff >= table.thr[i]) c = i + 1;
  return c;
}

export function dlMbps(mcs, layers, bwMhz, tdd, use256) {
  const n = PRB_DL[bwMhz], t = frame(tdd);
  const itbs = (use256 ? MCS_ITBS_256 : MCS_ITBS_64)[mcs];
  if (!n || itbs === undefined) return 0;
  const [D, S] = TDD[t.sa], f = dwpts(t.ssp);
  const special = f === 0.75 ? TBS[DWPTS_PRB[n]][itbs] : f === 0.375 ? Math.round(0.375 * TBS[n][itbs]) : 0;
  return (D * TBS[n][itbs] + S * special) * layers * 100 / 1e6;
}

// PUSCH columns were not retrieved: scale the DL column by the PRB ratio (within 2% at 20 MHz). Label UL "about".
export function ulMbps(mcs, bwMhz, tdd) {
  const n = PRB_DL[bwMhz], itbs = MCS_ITBS_UL[mcs];
  if (!n || itbs === undefined) return 0;
  return TDD[frame(tdd).sa][2] * Math.round(TBS[n][itbs] * PRB_UL[bwMhz] / n) * 100 / 1e6;
}

export function modulationOf(mcs, table) {
  if (mcs == null || !Number.isFinite(mcs)) return null;
  if (table === '256') return mcs <= 4 ? 'QPSK' : mcs <= 10 ? '16QAM' : mcs <= 19 ? '64QAM' : '256QAM';
  if (table === 'ul') return mcs <= 10 ? 'QPSK' : mcs <= 20 ? '16QAM' : '64QAM';
  return mcs <= 9 ? 'QPSK' : mcs <= 16 ? '16QAM' : '64QAM';
}

// input.cal (optional, partial DEFAULTS) is the hook for lead calibration of offsets and eta; no online learning in v1.
function setup(input) {
  const cal = input.cal || {};
  const caps = input.caps || {};
  const kind = input.input === 'sinr' ? 'sinr' : 'cinr';
  const use256 = !!caps.dl256;
  return {
    kind, use256,
    table: use256 ? CQI256 : CQI64,
    off: {...DEFAULTS.rankOffset[kind], ...cal.rankOffset?.[kind]},
    eta: cal.eta ?? DEFAULTS.eta,
    ulGapDb: cal.ulGapDb ?? DEFAULTS.ulGapDb,
    maxLayers: caps.maxLayers ?? 2,
    catBits: caps.catBitsPerTti ?? DEFAULTS.catBitsPerTti,
    tdd: frame(input.tdd),
    tddGiven: !!TDD[input.tdd?.sa] && input.tdd?.ssp != null,
  };
}

function carrierModel(c, o, shift = 0, forceRank = 0) {
  const bw = c.bwMhz ?? 20, sinr = Number.isFinite(c.sinr) ? c.sinr + shift : -Infinity;
  const reported = c.role === 'pcc' && c.cqiFresh && !forceRank;
  const option = r => {
    const rep = reported && c.cqi && c.ri === r;
    const cqi = rep ? Math.max(0, Math.min(15, Math.round(c.cqi))) : cqiFromSinr(sinr + o.off[r], o.table);
    const mcs = cqi ? Math.min(o.table.mcs[cqi - 1], o.use256 ? 27 : 28) : null;
    return {rank: r, cqi, mcs, rep, phy: mcs === null ? 0 : dlMbps(mcs, r, bw, o.tdd, o.use256)};
  };
  const ranks = forceRank ? [forceRank] : o.maxLayers >= 2 ? [1, 2] : [1];
  const opts = ranks.map(option);
  let best = opts.reduce((a, b) => b.phy > a.phy ? b : a);
  if (reported && ranks.includes(c.ri)) best = opts.find(x => x.rank === c.ri);
  return {
    role: c.role, cqi: best.cqi, mcs: best.mcs, rank: best.rank,
    modulation: modulationOf(best.mcs, o.use256 ? '256' : '64'),
    dlMbps: best.phy * o.eta, reported: best.rep,
  };
}

function capMbps(o) {
  const [D, S] = TDD[o.tdd.sa];
  return o.catBits * (D + S * dwpts(o.tdd.ssp)) * 100 / 1e6 * o.eta;
}

const total = (carriers, o, shift) =>
  Math.min(carriers.reduce((s, c) => s + carrierModel(c, o, shift * (Number.isFinite(c.sinrSd) ? c.sinrSd : 0)).dlMbps, 0), capMbps(o));

const idealSinr = o => o.table.thr[14] - o.off[2] + 1;

export function predict(input) {
  const o = setup(input), carriers = input.carriers || [];
  const per = carriers.map(c => carrierModel(c, o));
  const cap = capMbps(o);
  const dl = Math.min(per.reduce((s, c) => s + c.dlMbps, 0), cap);
  const lo = total(carriers, o, -Z), hi = total(carriers, o, Z);
  const ideal = carriers.reduce((s, c) => s + carrierModel({...c, sinr: idealSinr(o)}, o, 0, Math.min(2, o.maxLayers)).dlMbps, 0);
  const denom = Math.min(ideal, cap);
  const potential = denom > 0 ? Math.round(100 * Math.min(1, dl / denom)) : 0;

  const pcc = carriers.find(c => c.role === 'pcc') || null;
  let ulMcs = null, ul = null;
  if (pcc) {
    if (Number.isFinite(input.ulMcsObserved)) ulMcs = input.ulMcsObserved;
    else {
      const cqi = cqiFromSinr((Number.isFinite(pcc.sinr) ? pcc.sinr : -Infinity) - o.ulGapDb, CQI64);
      ulMcs = cqi ? CQI64.mcs[cqi - 1] : null;
    }
    // Power-limited uplink: the modem is near max TX, so the scheduler backs off.
    if (ulMcs !== null && input.txPowerDbm >= 21) ulMcs = Math.max(0, ulMcs - 4);
    ul = ulMcs === null ? 0 : ulMbps(ulMcs, pcc.bwMhz ?? 20, o.tdd) * o.eta;
  }
  const pccOut = per.find(c => c.role === 'pcc');
  const assumptions = [];
  if (!o.tddGiven) assumptions.push(`TDD ${o.tdd.sa}/${o.tdd.ssp} assumed`);
  if (!o.use256) assumptions.push('64QAM table assumed');
  return {
    carriers: per.map(({reported, ...c}) => c),
    dlMbps: dl, dlLo: Math.min(lo, dl), dlHi: Math.max(hi, dl),
    ulMbps: ul,
    dlModulation: (pccOut || per.find(c => c.modulation))?.modulation ?? null,
    ulModulation: modulationOf(ulMcs, 'ul'),
    potential,
    basis: pccOut?.reported ? 'reported-cqi' : 'model',
    assumptions,
  };
}

export function potentialSmooth(input) {
  const o = setup(input), carriers = input.carriers || [];
  const cap = o.use256 ? 5.9 : 4.4;
  const se = s => !Number.isFinite(s) || s < -10 ? 0 : Math.min(cap, 0.6 * Math.log2(1 + 10 ** (s / 10)));
  const two = Math.min(2, o.maxLayers) >= 2;
  const cell = (s, bw) => Math.max(se(s + o.off[1]), two ? 2 * se(s + o.off[2]) : 0) * bw;
  let got = 0, ideal = 0;
  for (const c of carriers) {
    const bw = c.bwMhz ?? 20;
    got += cell(c.sinr, bw);
    ideal += cell(idealSinr(o), bw);
  }
  return ideal > 0 ? Math.min(1, got / ideal) : 0;
}
